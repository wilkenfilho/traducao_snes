"""
core.rom_io
------------
Leitura não-destrutiva de ROMs SNES/Super Famicom (.sfc / .smc), detecção de
cabeçalho de 512 bytes (formato "Super Magicom"/copier header), cálculo de
checksum interno e detecção heurística de mapeamento (LoROM / HiROM / ExHiROM).

Tudo aqui é determinístico e baseado em especificação pública do header
interno do SNES (offsets 0x7FC0 para LoROM e 0xFFC0 para HiROM). Não há
"achismo" nesta camada — cada resultado vem com uma pontuação de confiança
calculada a partir de testes objetivos (checksum + complemento == 0xFFFF).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

HEADER_SIZE = 512

REGION_TABLE = {
    0x00: "Japão (NTSC)", 0x01: "EUA/Canadá (NTSC)", 0x02: "Europa (PAL)",
    0x03: "Suécia (PAL)", 0x04: "Finlândia (PAL)", 0x05: "Dinamarca (PAL)",
    0x06: "França (PAL)", 0x07: "Holanda (PAL)", 0x08: "Espanha (PAL)",
    0x09: "Alemanha (PAL)", 0x0A: "Itália (PAL)", 0x0B: "China (PAL)",
    0x0C: "Indonésia (PAL)", 0x0D: "Coreia (NTSC)", 0x0E: "Comum",
    0x0F: "Canadá (NTSC)", 0x10: "Brasil (PAL-M)", 0x11: "Austrália (PAL)",
}


@dataclass
class HeaderCandidate:
    mapping: str            # "LoROM" | "HiROM" | "ExHiROM"
    header_offset: int
    title: str
    rom_makeup: int
    rom_type: int
    rom_size_byte: int
    sram_size_byte: int
    region_byte: int
    region_name: str
    dev_id: int
    version: int
    checksum: int
    checksum_complement: int
    checksum_valid: bool
    confidence: float       # 0.0 - 1.0


@dataclass
class RomInfo:
    filename: str
    raw_size: int
    has_copier_header: bool
    copier_header_bytes: bytes
    rom: bytes                       # dados sem o header de 512 bytes
    best_mapping: Optional[HeaderCandidate]
    candidates: list = field(default_factory=list)
    risks: list = field(default_factory=list)


def detect_copier_header(data: bytes) -> bool:
    """
    Detecta o header de 512 bytes usado por copiadoras antigas (.smc).
    Regra padrão da comunidade: (tamanho_do_arquivo mod 0x8000) == 512
    e o arquivo sem esses 512 bytes bate com múltiplo de 1KB coerente
    com tamanhos reais de ROM SNES (256KB a 8MB, potências/somas de 2).
    """
    if len(data) < HEADER_SIZE:
        return False
    remainder = len(data) % 0x8000
    if remainder == HEADER_SIZE:
        return True
    return False


def strip_header(data: bytes) -> tuple[bool, bytes, bytes]:
    """Retorna (tinha_header, header_bytes, rom_sem_header)."""
    if detect_copier_header(data):
        return True, data[:HEADER_SIZE], data[HEADER_SIZE:]
    return False, b"", data


def calc_checksum(rom: bytes) -> int:
    """Checksum interno do SNES: soma de todos os bytes mod 0x10000."""
    return sum(rom) & 0xFFFF


def _read_header_at(rom: bytes, offset: int, mapping_name: str) -> Optional[HeaderCandidate]:
    if offset + 0x40 > len(rom):
        return None
    block = rom[offset:offset + 0x40]
    try:
        title_bytes = block[0x00:0x15]
        title = title_bytes.decode("ascii", errors="replace").strip("\x00").strip()
        rom_makeup = block[0x15]
        rom_type = block[0x16]
        rom_size_byte = block[0x17]
        sram_size_byte = block[0x18]
        region_byte = block[0x19]
        dev_id = block[0x1A]
        version = block[0x1B]
        checksum_complement = block[0x1C] | (block[0x1D] << 8)
        checksum = block[0x1E] | (block[0x1F] << 8)
    except IndexError:
        return None

    checksum_valid = (checksum ^ checksum_complement) == 0xFFFF

    # pontuação de confiança: soma de evidências objetivas
    score = 0.0
    if checksum_valid:
        score += 0.55
    # complemento e checksum não podem ser ambos 0x0000 ou 0xFFFF (placeholder inválido)
    if checksum not in (0x0000, 0xFFFF):
        score += 0.10
    printable_ratio = sum(1 for b in title_bytes if 0x20 <= b <= 0x7E or b == 0x00) / len(title_bytes)
    score += 0.20 * printable_ratio
    if region_byte in REGION_TABLE:
        score += 0.10
    if 0x07 <= rom_size_byte <= 0x0D:  # tamanhos plausíveis (256KB a 8MB)
        score += 0.05
    score = min(score, 1.0)

    calc_sum = calc_checksum(rom)
    # o checksum interno é calculado sobre a ROM completa (ou espelhada); aqui
    # comparamos com a soma bruta como evidência adicional, sem tratar como
    # prova definitiva (ROMs com padding/espelhamento variam).
    if calc_sum == checksum:
        score = min(score + 0.05, 1.0)

    return HeaderCandidate(
        mapping=mapping_name,
        header_offset=offset,
        title=title,
        rom_makeup=rom_makeup,
        rom_type=rom_type,
        rom_size_byte=rom_size_byte,
        sram_size_byte=sram_size_byte,
        region_byte=region_byte,
        region_name=REGION_TABLE.get(region_byte, f"Desconhecida (0x{region_byte:02X})"),
        dev_id=dev_id,
        version=version,
        checksum=checksum,
        checksum_complement=checksum_complement,
        checksum_valid=checksum_valid,
        confidence=score,
    )


def analyze_rom(filename: str, raw_data: bytes) -> RomInfo:
    has_header, header_bytes, rom = strip_header(raw_data)
    risks = []

    candidates = []
    lorom = _read_header_at(rom, 0x7FC0, "LoROM")
    hirom = _read_header_at(rom, 0xFFC0, "HiROM")
    exhirom = _read_header_at(rom, 0x40FFC0, "ExHiROM") if len(rom) > 0x40FFC0 + 0x40 else None
    for c in (lorom, hirom, exhirom):
        if c is not None:
            candidates.append(c)

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    best = candidates[0] if candidates else None

    if best is None:
        risks.append("Não foi possível localizar um header interno válido (LoROM/HiROM/ExHiROM). "
                      "A ROM pode estar corrompida, ser um formato não suportado (ex.: SA-1, Super FX "
                      "com mapeamento especial) ou não ser uma ROM SNES.")
    elif best.confidence < 0.6:
        risks.append(f"Mapeamento detectado ({best.mapping}) com confiança baixa "
                      f"({best.confidence:.0%}). Resultados de offset/ponteiro podem estar incorretos.")
    elif not best.checksum_valid:
        risks.append("Checksum interno inconsistente (checksum XOR complemento != 0xFFFF). "
                      "A ROM pode ser um hack prévio, estar corrompida ou usar mapeamento especial.")

    if len(candidates) >= 2 and candidates[0].confidence - candidates[1].confidence < 0.15:
        risks.append(f"Ambiguidade entre mapeamentos {candidates[0].mapping} "
                      f"({candidates[0].confidence:.0%}) e {candidates[1].mapping} "
                      f"({candidates[1].confidence:.0%}). Verifique manualmente antes de prosseguir.")

    return RomInfo(
        filename=filename,
        raw_size=len(raw_data),
        has_copier_header=has_header,
        copier_header_bytes=header_bytes,
        rom=rom,
        best_mapping=best,
        candidates=candidates,
        risks=risks,
    )


def snes_to_pc(address: int, mapping: str) -> Optional[int]:
    """Converte endereço SNES (bank<<16 | addr) para offset físico no arquivo (sem header)."""
    bank = (address >> 16) & 0xFF
    addr = address & 0xFFFF
    if mapping == "LoROM":
        if addr < 0x8000:
            return None
        return ((bank & 0x7F) * 0x8000) + (addr - 0x8000)
    if mapping == "HiROM":
        return ((bank & 0x3F) * 0x10000) + addr
    if mapping == "ExHiROM":
        if bank >= 0xC0:
            return ((bank - 0xC0) * 0x10000) + addr
        return 0x400000 + (bank * 0x10000) + addr
    return None


def pc_to_snes(offset: int, mapping: str) -> Optional[int]:
    """Converte offset físico (sem header) para endereço SNES (aproximação padrão, banco de dados fast)."""
    if mapping == "LoROM":
        bank = (offset // 0x8000) & 0x7F
        addr = (offset % 0x8000) + 0x8000
        return (0x80 + bank) << 16 | addr
    if mapping == "HiROM":
        bank = (offset // 0x10000) & 0x3F
        addr = offset % 0x10000
        return (0xC0 + bank) << 16 | addr
    if mapping == "ExHiROM":
        if offset < 0x400000:
            bank = 0xC0 + (offset // 0x10000)
            addr = offset % 0x10000
            return bank << 16 | addr
        rel = offset - 0x400000
        bank = rel // 0x10000
        addr = rel % 0x10000
        return bank << 16 | addr
    return None
