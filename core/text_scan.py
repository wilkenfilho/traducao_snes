"""
core.text_scan
---------------
Varre a ROM usando uma tabela de caracteres (TBL) já definida (importada,
ou inferida por busca relativa/hipótese ASCII) e localiza blocos candidatos
a texto traduzível, com pontuação de confiança individual por bloco.

A confiança de cada bloco considera:
- proporção de bytes resolvidos pela tabela vs. desconhecidos ({XX})
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


@dataclass
class TextBlock:
    start: int
    end: int
    raw: bytes
    text: str
    confidence: float
    terminated_cleanly: bool
    category_hint: str = "desconhecido"


def _looks_like_padding(raw: bytes) -> bool:
    if len(raw) < 4:
        return False
    uniq = len(set(raw))
    return uniq <= 2


def _score_block(raw: bytes, text: str, terminated: bool) -> float:
    if len(raw) == 0:
        return 0.0
    unresolved = text.count("{")
    resolved_ratio = 1.0 - min(unresolved / max(len(raw), 1), 1.0)
    score = 0.45 * resolved_ratio

    if terminated:
        score += 0.15

    printable_chars = sum(1 for c in text if c.isprintable() and c != "{")
    printable_ratio = printable_chars / max(len(text), 1)
    score += 0.15 * printable_ratio

    space_or_punct = sum(1 for c in text if c in " .,!?'\"-")
    if len(text) >= 6:
        score += 0.10 * min(space_or_punct / (len(text) / 8), 1.0)

    length_bonus = min(len(raw) / 40.0, 1.0)
    score += 0.15 * length_bonus

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
