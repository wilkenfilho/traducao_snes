"""
core.tbl
--------
Gerenciamento de tabelas de caracteres (TBL) — o mapeamento entre bytes da
ROM e caracteres reais. Este é o ponto mais "artesanal" de qualquer projeto
de tradução de ROM: cada jogo pode usar uma tabela custom diferente, e não
existe forma 100% automática de descobrir isso do zero sem nenhuma pista.

Este módulo oferece três caminhos, do mais confiável ao mais arriscado,
todos com confiança explícita:

1. Importar um arquivo .tbl padrão (formato "XX=c", um por linha) — já
   existe uma comunidade enorme de TBLs prontas para jogos conhecidos.
2. Busca relativa ("relative search"): técnica clássica de ROM hacking.
   O usuário informa uma palavra que sabe que existe no jogo (ex.: um nome
   próprio, "LEVEL", "HP" etc). O algoritmo procura, na ROM, sequências de
   bytes cujos deltas relativos batem com os deltas ASCII da palavra
   informada, e extrapola o alfabeto a partir daí.
3. Hipótese ASCII direta: assume que o jogo usa ASCII padrão (comum em
   traduções fanmade/homebrew, raro em jogos originais japoneses/US com
   tabela custom). Pontuada por teste de frequência de letras.

Nenhuma dessas hipóteses é aplicada automaticamente sem o usuário revisar
a confiança reportada.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import re

CONTROL_TOKEN_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")


@dataclass
class TableResult:
    byte_to_char: dict
    char_to_byte: dict
    confidence: float
    method: str
    notes: str = ""


def parse_tbl_text(text: str) -> dict:
    """
    Faz o parse de um arquivo .tbl no formato padrão da comunidade:
        41=A
        42=B
        FE=[END]
        FF=[LINE]
    Suporta multi-byte (ex.: 8140=A) e comentários iniciados por '//' ou '#'.
    """
    mapping = {}
    for raw_line in text.splitlines():
        # remove só a quebra de linha (\r\n) — NÃO usar strip() aqui, pois
        # entradas legítimas como "FF= " (espaço) têm o valor significativo
        # à direita do "=", e strip() apagaria justamente esse espaço.
        line = raw_line.rstrip("\r\n")
        stripped_for_check = line.strip()
        if not stripped_for_check or stripped_for_check.startswith(("//", "#")):
            continue
        if "=" not in line:
            continue
        code, char = line.split("=", 1)
        code = code.strip()
        try:
            key = int(code, 16)
        except ValueError:
            continue
        mapping[key] = char
    return mapping


def table_to_tbl_text(byte_to_char: dict) -> str:
    lines = []
    for k in sorted(byte_to_char.keys()):
        v = byte_to_char[k]
        width = 4 if k > 0xFF else 2
        lines.append(f"{k:0{width}X}={v}")
    return "\n".join(lines)


def identity_ascii_table() -> dict:
    return {b: chr(b) for b in range(0x20, 0x7F)}


def invert_table(byte_to_char: dict) -> dict:
    inv = {}
    for b, c in byte_to_char.items():
        inv.setdefault(c, b)  # primeira ocorrência vence em caso de colisão
    return inv


def score_ascii_hypothesis(rom: bytes, sample_limit: int = 400_000) -> float:
    """
    Testa a hipótese 'a ROM contém texto ASCII puro' via teste de frequência
    de letras contra o inglês padrão (chi-quadrado simplificado). Retorna
    confiança 0..1. É apenas um indício, nunca prova.
    """
    from collections import Counter

    sample = rom[:sample_limit]
    letters = [chr(b).lower() for b in sample if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A]
    if len(letters) < 200:
        return 0.0
    counts = Counter(letters)
    total = sum(counts.values())
    expected_freq = {
        'e': .127, 't': .091, 'a': .082, 'o': .075, 'i': .070, 'n': .067,
        's': .063, 'h': .061, 'r': .060, 'd': .043, 'l': .040, 'c': .028,
        'u': .028, 'm': .024, 'w': .024, 'f': .022, 'g': .020, 'y': .020,
        'p': .019, 'b': .015, 'v': .010, 'k': .008, 'j': .002, 'x': .002,
        'q': .001, 'z': .001,
    }
    chi2 = 0.0
    for ch, exp_f in expected_freq.items():
        observed = counts.get(ch, 0)
        expected = exp_f * total
        if expected > 0:
            chi2 += ((observed - expected) ** 2) / expected
    # normaliza heuristicamente: chi2 baixo => confiança alta
    confidence = max(0.0, 1.0 - min(chi2 / 500.0, 1.0))
    # exige também presença razoável de espaços (0x20) entre os bytes de texto
    space_ratio = sample.count(0x20) / max(len(sample), 1)
    if space_ratio < 0.01:
        confidence *= 0.5
    return round(confidence, 3)


def relative_search(rom: bytes, known_word: str, max_results: int = 25) -> list[dict]:
    """
    Busca relativa clássica: dado uma palavra conhecida (ex. 'LEVEL'), procura
    na ROM sequências de bytes cujas diferenças consecutivas batem com as
    diferenças ASCII consecutivas da palavra. Isso funciona bem quando a
    tabela custom preserva a ordem alfabética relativa (muito comum).
    Retorna candidatos com o offset e a tabela parcial inferida.
    """
    known_word = known_word.strip()
    if len(known_word) < 3:
        return []
    ascii_vals = [ord(c) for c in known_word]
    deltas = [b - a for a, b in zip(ascii_vals, ascii_vals[1:])]
    n = len(known_word)
    results = []
    limit = len(rom) - n
    for i in range(limit):
        window = rom[i:i + n]
        ok = True
        for j in range(n - 1):
            if (window[j + 1] - window[j]) != deltas[j]:
                ok = False
                break
        if ok:
            base_byte = window[0]
            base_char = ascii_vals[0]
            offset_delta = base_byte - base_char
            inferred = {ord(c) + offset_delta: c for c in set("ABCDEFGHIJKLMNOPQRSTUVWXYZ "
                                                                "abcdefghijklmnopqrstuvwxyz0123456789")}
            results.append({
                "offset": i,
                "matched_bytes": list(window),
                "byte_shift": offset_delta,
                "inferred_table": inferred,
            })
            if len(results) >= max_results:
                break
    return results


def build_table_result(method: str, byte_to_char: dict, confidence: float, notes: str = "") -> TableResult:
    return TableResult(
        byte_to_char=byte_to_char,
        char_to_byte=invert_table(byte_to_char),
        confidence=confidence,
        method=method,
        notes=notes,
    )


def decode_bytes(data: bytes, table: dict, terminators: set[int]) -> tuple[str, bool]:
    """
    Decodifica bytes usando a tabela. Bytes não mapeados viram tokens de
    controle {XX} para não perder informação (rastreabilidade total).
    Retorna (texto, terminou_com_terminador?).
    """
    out = []
    terminated = False
    for b in data:
        if b in terminators:
            terminated = True
            break
        if b in table:
            out.append(table[b])
        else:
            out.append(f"{{{b:02X}}}")
    return "".join(out), terminated


def encode_text(text: str, table_inv: dict, terminator_byte: Optional[int]) -> Optional[bytes]:
    """
    Codifica texto de volta para bytes usando a tabela invertida. Tokens de
    controle no formato {XX} (hex) ou {NOME} (mapeado via table_inv) são
    respeitados. Retorna None se algum caractere não puder ser codificado
    (sinal de que a tradução usa um símbolo fora da tabela do jogo).
    """
    out = bytearray()
    i = 0
    while i < len(text):
        m = CONTROL_TOKEN_RE.match(text, i)
        if m:
            token = m.group(1)
            try:
                out.append(int(token, 16))
                i = m.end()
                continue
            except ValueError:
                if token in table_inv:
                    out.append(table_inv[token])
                    i = m.end()
                    continue
                return None
        ch = text[i]
        if ch in table_inv:
            out.append(table_inv[ch])
        else:
            return None
        i += 1
    if terminator_byte is not None:
        out.append(terminator_byte)
    return bytes(out)
