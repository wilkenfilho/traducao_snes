"""
core.pointers
-------------
Detecção heurística de tabelas de ponteiros associadas a blocos de texto.

Estratégia (a mesma usada manualmente por romhackers, aqui automatizada de
forma conservadora): para cada bloco de texto candidato, calculamos o
endereço SNES do seu offset físico (via mapeamento LoROM/HiROM já
detectado) e procuramos, na ROM inteira, ocorrências desse valor de 16 bits
em little-endian (formato de ponteiro mais comum em jogos SNES). Quando
vários blocos de um mesmo grupo (ex.: mesma "tabela" de diálogos) têm seus
ponteiros encontrados em posições próximas e em sequência, isso é forte
evidência de uma tabela de ponteiros real — pontuamos a confiança de acordo.

Isso NÃO cobre: ponteiros de 24 bits com banco explícito, ponteiros
comprimidos/calculados, tabelas indexadas por outra tabela intermediária,
ou texto comprimido (LZ, RLE proprietário etc.) — esses casos exigem um
"perfil de jogo" dedicado (ver core/profiles.py) e são reportados como
"não identificado com segurança" em vez de arriscar um palpite.
"""

from __future__ import annotations
from dataclasses import dataclass
from .rom_io import pc_to_snes


@dataclass
class PointerTableCandidate:
    table_offset: int          # onde a tabela de ponteiros parece começar na ROM
    entry_count: int
    entry_size: int            # 2 ou 3 bytes
    matched_block_indices: list
    confidence: float


def _find_le16_occurrences(rom: bytes, value: int) -> list[int]:
    lo = value & 0xFF
    hi = (value >> 8) & 0xFF
    pat = bytes([lo, hi])
    positions = []
    start = 0
    while True:
        idx = rom.find(pat, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions


def find_pointer_candidates(rom: bytes, blocks: list, mapping: str, max_blocks: int = 300) -> list[PointerTableCandidate]:
    if mapping not in ("LoROM", "HiROM", "ExHiROM"):
        return []

    hits_per_block = {}
    for idx, blk in enumerate(blocks[:max_blocks]):
        snes_addr = pc_to_snes(blk.start, mapping)
        if snes_addr is None:
            continue
        addr16 = snes_addr & 0xFFFF
        positions = _find_le16_occurrences(rom, addr16)
        # descarta ruído: endereços de 16 bits comuns demais geram falsos positivos
        if 0 < len(positions) <= 8:
            hits_per_block[idx] = positions

    if not hits_per_block:
        return []

    # agrupa posições próximas (mesma vizinhança = possível mesma tabela)
    all_positions = sorted({p for positions in hits_per_block.values() for p in positions})
    clusters: list[list[int]] = []
    current: list[int] = []
    for p in all_positions:
        if current and p - current[-1] > 512:
            clusters.append(current)
            current = []
        current.append(p)
    if current:
        clusters.append(current)

    candidates = []
    for cluster in clusters:
        matched_blocks = [idx for idx, positions in hits_per_block.items()
                           if any(p in cluster for p in positions)]
        if len(matched_blocks) < 2:
            continue
        span = cluster[-1] - cluster[0]
        density = len(cluster) / max(span / 2, 1)
        confidence = min(0.3 + 0.5 * min(len(matched_blocks) / 10, 1.0) + 0.2 * min(density, 1.0), 0.95)
        candidates.append(PointerTableCandidate(
            table_offset=cluster[0],
            entry_count=len(cluster),
            entry_size=2,
            matched_block_indices=matched_blocks,
            confidence=round(confidence, 3),
        ))
    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates
