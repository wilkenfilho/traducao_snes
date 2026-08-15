"""
core.text_scan
---------------
Varre a ROM usando uma tabela de caracteres (TBL) já definida (importada,
ou inferida por busca relativa/hipótese ASCII) e localiza blocos candidatos
a texto traduzível, com pontuação de confiança individual por bloco.

ATENÇÃO — jogos com DTE/MTE (Dual/Multi Tile Encoding): quando a tabela
mapeia a maior parte do espaço de bytes para palavras/fragmentos inteiros
(ex.: 0x44="you", 0x41="the"), a varredura cega por terminador fica pouco
confiável por dois motivos:
1. Quase QUALQUER sequência de bytes decodifica como "algo parecido com
   texto", já que a cobertura da tabela é quase total — isso infla a
   confiança de regiões que não são diálogo de verdade (ex.: tabelas de
   ponteiro, gráficos). Por isso a pontuação aqui usa sinais linguísticos
   (densidade de espaço, formato de "palavra") além de "% de bytes
   resolvidos".
2. Muitos desses jogos não usam 0x00 como terminador de string — usar o
   terminador errado faz os blocos "colarem" uns nos outros. Quando
   possível, prefira `segment_blocks_by_pointers()`, que usa os endereços
   de uma tabela de ponteiros já detectada para demarcar o início real de
   cada string, em vez de adivinhar onde ela termina.

A confiança de cada bloco considera:
- proporção de bytes resolvidos pela tabela vs. desconhecidos ({XX})
- plausibilidade linguística: densidade do byte-espaço, tamanho médio de
  "palavra", proporção de vogais — não apenas "foi resolvido pela tabela"
- presença de espaços e pontuação plausível
- comprimento mínimo (blocos muito curtos são mais frequentemente falsos
  positivos: nomes de variável, IDs, tiles etc.)
- repetição suspeita (sequências de bytes idênticos costumam ser padding,
  não texto)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from .tbl import decode_bytes

DEFAULT_TERMINATORS = {0x00}
VOWELS = set("aeiouAEIOU")


@dataclass
class TextBlock:
    start: int
    end: int
    raw: bytes
    text: str
    confidence: float
    terminated_cleanly: bool
    category_hint: str = "desconhecido"
    ai_verdict: str | None = None       # None | "texto_real" | "ruido"
    ai_confidence: float | None = None
    ai_reason: str = ""


def _looks_like_padding(raw: bytes) -> bool:
    if len(raw) < 4:
        return False
    uniq = len(set(raw))
    return uniq <= 2


def _find_space_byte(byte_to_char: dict) -> int | None:
    """Descobre qual byte a tabela usa para espaço — nem sempre é 0x20 (ex.: DTE=0xFF)."""
    for b, c in byte_to_char.items():
        if c == " ":
            return b
    return None


def _word_plausibility(text: str) -> float:
    """
    Mede se o texto decodificado tem "formato de palavra real" — independente
    de quantos bytes a tabela resolveu. Isso é o que realmente distingue
    diálogo de verdade de dado binário que, por coincidência, também decodifica
    para caracteres válidos (comum em tabelas DTE com cobertura quase total).
    """
    # separa em "palavras" por qualquer caractere que não seja letra/apóstrofo
    import re
    words = re.findall(r"[A-Za-z']+", text)
    if not words:
        return 0.0
    avg_len = sum(len(w) for w in words) / len(words)
    len_score = 1.0 - min(abs(avg_len - 4.2) / 4.2, 1.0)  # pico ~4 letras, típico do inglês

    vowel_ratios = []
    for w in words:
        letters = [c for c in w if c.isalpha()]
        if letters:
            vowel_ratios.append(sum(1 for c in letters if c in VOWELS) / len(letters))
    avg_vowel_ratio = sum(vowel_ratios) / len(vowel_ratios) if vowel_ratios else 0.0
    # palavras reais em inglês tendem a ter 30-55% de vogais
    vowel_score = 1.0 - min(abs(avg_vowel_ratio - 0.40) / 0.40, 1.0)

    coverage = sum(len(w) for w in words) / max(len(text), 1)  # quanto do texto é "palavra"

    return round(max(0.0, 0.4 * len_score + 0.35 * vowel_score + 0.25 * coverage), 3)


def _score_block(raw: bytes, text: str, terminated: bool) -> float:
    if len(raw) == 0:
        return 0.0
    unresolved = text.count("{")
    resolved_ratio = 1.0 - min(unresolved / max(len(raw), 1), 1.0)
    # peso de resolved_ratio reduzido: em tabelas DTE de cobertura quase total,
    # "foi resolvido" deixa de discriminar texto real de dado binário coincidente.
    score = 0.25 * resolved_ratio

    if terminated:
        score += 0.10

    printable_chars = sum(1 for c in text if c.isprintable() and c != "{")
    printable_ratio = printable_chars / max(len(text), 1)
    score += 0.10 * printable_ratio

    score += 0.35 * _word_plausibility(text)

    space_or_punct = sum(1 for c in text if c in " .,!?'\"-")
    if len(text) >= 6:
        score += 0.10 * min(space_or_punct / (len(text) / 8), 1.0)

    length_bonus = min(len(raw) / 40.0, 1.0)
    score += 0.10 * length_bonus

    if _looks_like_padding(raw):
        score *= 0.1

    return round(min(score, 1.0), 3)


def _guess_category(text: str) -> str:
    low = text.lower()
    if any(k in low for k in ["hp", "mp", "attack", "defense", "level", "lv.", "atk", "def"]):
        return "estatísticas/menu"
    if len(text) <= 12 and text.isupper():
        return "item/nome curto"
    if text.endswith(("?", "!", ".", "...")) or len(text.split()) >= 4:
        return "diálogo"
    return "texto genérico"


def find_text_blocks(
    rom: bytes,
    byte_to_char: dict,
    terminators: set[int] = None,
    min_len: int = 4,
    max_len: int = 400,
    min_confidence: float = 0.35,
    scan_start: int = 0,
    scan_end: int | None = None,
) -> list[TextBlock]:
    terminators = terminators or DEFAULT_TERMINATORS
    scan_end = scan_end if scan_end is not None else len(rom)

    blocks: list[TextBlock] = []
    i = scan_start
    n = scan_end
    while i < n:
        b = rom[i]
        if b not in byte_to_char and b not in terminators:
            i += 1
            continue
        j = i
        while j < n and rom[j] not in terminators and (j - i) < max_len:
            j += 1
        terminated = j < n and rom[j] in terminators
        raw_end = min(j + 1, n) if terminated else j
        raw = rom[i:raw_end]
        text, term_ok = decode_bytes(raw, byte_to_char, terminators)
        if len(raw) >= min_len:
            conf = _score_block(raw, text, term_ok)
            if conf >= min_confidence:
                blocks.append(TextBlock(
                    start=i, end=raw_end, raw=raw, text=text,
                    confidence=conf, terminated_cleanly=term_ok,
                    category_hint=_guess_category(text),
                ))
        i = raw_end if raw_end > i else i + 1
    return blocks


def merge_overlapping(blocks: list[TextBlock]) -> list[TextBlock]:
    """Remove blocos totalmente contidos em outros de maior confiança."""
    blocks_sorted = sorted(blocks, key=lambda b: (-b.confidence, b.start))
    kept: list[TextBlock] = []
    covered = []  # lista de (start,end)
    for blk in blocks_sorted:
        overlap = any(not (blk.end <= s or blk.start >= e) for s, e in covered)
        if not overlap:
            kept.append(blk)
            covered.append((blk.start, blk.end))
    return sorted(kept, key=lambda b: b.start)


def segment_blocks_by_pointers(
    rom: bytes,
    byte_to_char: dict,
    pointer_targets: list[int],
    terminators: set[int] | None = None,
    max_len: int = 400,
    region_end: int | None = None,
) -> list[TextBlock]:
    """
    Segmentação orientada por ponteiros — a forma robusta de demarcar strings
    em jogos onde o terminador de string é desconhecido ou onde uma tabela
    DTE de cobertura quase total torna a varredura cega pouco confiável
    (ver aviso no topo do módulo).

    `pointer_targets` deve ser a lista de offsets físicos (já convertidos de
    endereço SNES para offset de arquivo) apontados por uma tabela de
    ponteiros já detectada (ver core/pointers.py), idealmente da MESMA
    tabela — não misture ponteiros de tabelas diferentes.

    Cada bloco vai do seu ponteiro até o PRÓXIMO ponteiro da lista (assumindo
    que as strings ficam contíguas na mesma ordem da tabela — o caso mais
    comum) ou até um terminador conhecido, o que vier primeiro. Isso elimina
    a necessidade de adivinhar terminador ou de confiar apenas na cobertura
    da tabela de caracteres.
    """
    if not pointer_targets:
        return []
    targets = sorted(set(t for t in pointer_targets if 0 <= t < len(rom)))
    region_end = region_end if region_end is not None else len(rom)
    terminators = terminators or set()

    blocks: list[TextBlock] = []
    for idx, start in enumerate(targets):
        next_start = targets[idx + 1] if idx + 1 < len(targets) else region_end
        hard_limit = min(start + max_len, next_start, region_end)

        end = hard_limit
        terminated = False
        if terminators:
            for j in range(start, hard_limit):
                if rom[j] in terminators:
                    end = j + 1
                    terminated = True
                    break

        raw = rom[start:end]
        if not raw:
            continue
        text, _ = decode_bytes(raw, byte_to_char, terminators)
        # confiança-base alta por vir de um ponteiro real e verificado, ajustada
        # pela plausibilidade linguística do resultado (mesmo ponteiro correto
        # pode apontar pra dado não-textual em tabelas raras).
        plaus = _word_plausibility(text)
        conf = round(min(0.55 + 0.4 * plaus + (0.05 if terminated else 0.0), 0.97), 3)
        blocks.append(TextBlock(
            start=start, end=end, raw=raw, text=text, confidence=conf,
            terminated_cleanly=terminated, category_hint=_guess_category(text),
        ))
    return blocks
