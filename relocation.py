"""
core.relocation
-----------------
Quando o texto traduzido não cabe no espaço original, duas estratégias são
possíveis:

1. Encolher/adaptar a tradução até caber (preferencial — feito na etapa de
   tradução/revisão, fora deste módulo).
2. Realocar o bloco inteiro para uma área livre da ROM e corrigir o(s)
   ponteiro(s) que apontam para ele.

Este módulo só executa a estratégia 2 quando:
  - existe uma tabela de ponteiros já detectada e associada ao bloco
    (ver core/pointers.py) com confiança suficiente, e
  - o formato do ponteiro é simples (16 bits, mapeamento LoROM/HiROM
    padrão) — o único caso que sabemos recalcular com segurança sem um
    perfil de jogo dedicado.

Se essas condições não forem atendidas, a realocação é RECUSADA e o bloco
é marcado como risco para revisão manual — nunca escrevemos um ponteiro
"no chute".
"""

from __future__ import annotations
from dataclasses import dataclass
from .rom_io import pc_to_snes


@dataclass
class FreeSpaceRegion:
    start: int
    end: int
    fill_byte: int


def find_free_space(rom: bytes, min_run: int = 64, fill_bytes=(0xFF, 0x00)) -> list[FreeSpaceRegion]:
    """
    Localiza regiões de padding (sequências longas do mesmo byte, tipicamente
    0xFF ou 0x00) que costumam indicar espaço não utilizado no cartucho.
    Isso é uma heurística — o usuário deve confirmar antes de usar como
    destino de realocação, pois padding também pode ser dado legítimo.
    """
    regions = []
    i = 0
    n = len(rom)
    while i < n:
        b = rom[i]
        if b in fill_bytes:
            j = i
            while j < n and rom[j] == b:
                j += 1
            if j - i >= min_run:
                regions.append(FreeSpaceRegion(start=i, end=j, fill_byte=b))
            i = j
        else:
            i += 1
    return regions


@dataclass
class RelocationResult:
    success: bool
    new_offset: int | None
    message: str


def try_relocate_block(
    rom_buffer: bytearray,
    new_data: bytes,
    free_regions: list[FreeSpaceRegion],
    used_free_ranges: list,
    pointer_table_offset: int | None,
    pointer_entry_index: int | None,
    mapping: str,
) -> RelocationResult:
    """
    Tenta realocar `new_data` para dentro de uma região livre disponível e,
    se um ponteiro de 16 bits associado for informado, reescreve-o.
    `used_free_ranges` é atualizado in-place para evitar colisão entre
    múltiplas realocações na mesma execução.
    """
    if pointer_table_offset is None or pointer_entry_index is None:
        return RelocationResult(False, None, "Sem tabela de ponteiros confiável associada — realocação recusada.")

    needed = len(new_data)
    for region in free_regions:
        # descarta sobreposição com áreas já usadas nesta sessão
        overlap = any(not (region.end <= s or region.start >= e) for s, e in used_free_ranges)
        if overlap:
            continue
        available = region.end - region.start
        if available >= needed:
            dest = region.start
            rom_buffer[dest:dest + needed] = new_data
            used_free_ranges.append((dest, dest + needed))

            snes_addr = pc_to_snes(dest, mapping)
            if snes_addr is None:
                return RelocationResult(False, None, "Falha ao converter offset físico em endereço SNES para o novo ponteiro.")
            addr16 = snes_addr & 0xFFFF
            ptr_pos = pointer_table_offset + pointer_entry_index * 2
            if ptr_pos + 2 > len(rom_buffer):
                return RelocationResult(False, None, "Posição do ponteiro fora dos limites da ROM.")
            rom_buffer[ptr_pos] = addr16 & 0xFF
            rom_buffer[ptr_pos + 1] = (addr16 >> 8) & 0xFF
            return RelocationResult(True, dest, f"Bloco realocado para 0x{dest:06X} e ponteiro atualizado.")

    return RelocationResult(False, None, "Nenhuma região livre grande o suficiente foi encontrada.")
