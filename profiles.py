"""
core.profiles
--------------
Sistema de "perfis de jogo" — o ponto de extensão da arquitetura.

A detecção 100% genérica (TBL por busca relativa, ponteiros de 16 bits
simples, sem compressão) cobre uma fatia real, mas limitada, dos jogos de
SNES. Para suportar um jogo específico com precisão total (compressão
proprietária, ponteiros de 24 bits, tabelas indiretas, tiles de fonte
variável etc.), o caminho correto — usado por toda a comunidade de ROM
hacking — é registrar aqui um `GameProfile` dedicado, feito a partir de
engenharia reversa daquele jogo específico.

Um perfil pode sobrescrever qualquer etapa do pipeline genérico:
- identificação (via título do header e/ou checksum)
- tabela de caracteres fixa
- rotina de descompressão/compressão de texto
- estratégia de localização de blocos de texto
- estratégia de ponteiros (16/24 bits, indireta, etc.)
- estratégia de realocação

Isso permite adicionar suporte a novos jogos sem tocar no pipeline
genérico nem no restante da aplicação.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class GameProfile:
    id: str
    display_name: str
    match_titles: list = field(default_factory=list)     # substrings do título do header
    match_checksums: list = field(default_factory=list)   # checksums internos conhecidos
    fixed_tbl: Optional[dict] = None
    decompress_fn: Optional[Callable[[bytes], bytes]] = None
    compress_fn: Optional[Callable[[bytes], bytes]] = None
    text_scan_override: Optional[Callable] = None
    pointer_scan_override: Optional[Callable] = None
    notes: str = ""


REGISTRY: list[GameProfile] = [
    # Exemplo de estrutura para futura expansão — nenhum perfil "real" é
    # assumido por padrão, para não fingir suporte que não existe:
    #
    # GameProfile(
    #     id="exemplo_jogo_xyz",
    #     display_name="Exemplo Jogo XYZ (JP)",
    #     match_titles=["EXEMPLO JOGO"],
    #     match_checksums=[0x1234],
    #     fixed_tbl={0x80: "A", 0x81: "B"},
    #     notes="Tabela extraída manualmente via engenharia reversa do jogo X.",
    # ),
]


def detect_profile(rom_info) -> Optional[GameProfile]:
    if rom_info.best_mapping is None:
        return None
    title = (rom_info.best_mapping.title or "").upper()
    checksum = rom_info.best_mapping.checksum
    for profile in REGISTRY:
        if any(t.upper() in title for t in profile.match_titles):
            return profile
        if checksum in profile.match_checksums:
            return profile
    return None
