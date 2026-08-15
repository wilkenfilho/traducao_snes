"""
core.font_vision
------------------
Extração de tiles gráficos de fonte SNES (2bpp/4bpp) e leitura via visão
computacional (Gemini multimodal) para inferir a tabela de caracteres a
partir do que a fonte REALMENTE PARECE, em vez de heurística estatística
sobre os bytes de texto. Esta é a técnica que mais se aproxima de "resolver"
o problema da tabela custom sem pista textual prévia — só que agora
automatizada.

Duas etapas independentes:
1. Localizar candidatos a região de fonte na ROM (heurística de entropia
   de tile — só indica candidatos, não confirma).
2. Renderizar os tiles como imagem e pedir para o modelo multimodal
   transcrever cada glifo, tile a tile, retornando um mapeamento
   índice_do_tile -> caractere.

O usuário SEMPRE confirma visualmente a região antes do OCR rodar, e revisa
o resultado do OCR antes de aceitar como tabela — nunca é aplicado sem
essa confirmação.
"""

from __future__ import annotations
from dataclasses import dataclass
import json


def decode_tile(data: bytes, offset: int, bpp: int = 2) -> list:
    """
    Decodifica um tile 8x8 no formato planar SNES.
    2bpp: 16 bytes/tile (2 planos intercalados por linha).
    4bpp: 32 bytes/tile (planos 0-1 nos primeiros 16 bytes, 2-3 nos 16 seguintes,
    mesmo layout intercalado por linha).
    Retorna uma matriz 8x8 de valores de cor (0..2^bpp-1).
    """
    if bpp not in (2, 4):
        raise ValueError("bpp deve ser 2 ou 4")
    tile_bytes = 16 if bpp == 2 else 32
    if offset + tile_bytes > len(data):
        return [[0] * 8 for _ in range(8)]
    chunk = data[offset:offset + tile_bytes]
    pixels = [[0] * 8 for _ in range(8)]
    planes_group = 1 if bpp == 2 else 2
    for group in range(planes_group):
        base = group * 16
        for row in range(8):
            plane0 = chunk[base + row * 2]
            plane1 = chunk[base + row * 2 + 1]
            for col in range(8):
                bit = 7 - col
                p0 = (plane0 >> bit) & 1
                p1 = (plane1 >> bit) & 1
                pixels[row][col] |= (p0 | (p1 << 1)) << (group * 2)
    return pixels


def _tile_ink_ratio(pixels: list) -> float:
    total = sum(1 for row in pixels for v in row if v != 0)
    return total / 64.0


@dataclass
class FontCandidateRegion:
    offset: int
    bpp: int
    tile_count: int
    avg_ink_ratio: float
    confidence: float


def scan_font_candidates(rom: bytes, bpp_options=(2, 4), tiles_to_check: int = 64,
                          stride: int = 16, max_candidates: int = 15) -> list[FontCandidateRegion]:
    """
    Heurística de localização de fonte: tiles de glifo têm uma proporção de
    pixels "acesos" moderada (nem em branco, nem cheios — letras têm forma),
    e blocos consecutivos de tiles tendem a ter padrões DIFERENTES entre si
    (glifos distintos), ao contrário de gráficos repetitivos (tilemaps de
    parede, por ex.) ou dados puramente aleatórios.
    """
    results = []
    tile_size = {2: 16, 4: 32}
    for bpp in bpp_options:
        tsz = tile_size[bpp]
        block_span = tsz * tiles_to_check
        for offset in range(0, max(len(rom) - block_span, 0), stride * tsz):
            ratios = []
            distinct_signatures = set()
            for t in range(tiles_to_check):
                tile_off = offset + t * tsz
                pixels = decode_tile(rom, tile_off, bpp)
                ratios.append(_tile_ink_ratio(pixels))
                distinct_signatures.add(tuple(tuple(row) for row in pixels))
            if not ratios:
                continue
            avg_ratio = sum(ratios) / len(ratios)
            diversity = len(distinct_signatures) / tiles_to_check
            # fonte real: ink ratio moderado (~0.10-0.45) e alta diversidade entre tiles
            if 0.08 <= avg_ratio <= 0.45 and diversity >= 0.5:
                confidence = min(diversity, 1.0) * (1.0 - abs(avg_ratio - 0.25) / 0.25)
                results.append(FontCandidateRegion(
                    offset=offset, bpp=bpp, tile_count=tiles_to_check,
                    avg_ink_ratio=round(avg_ratio, 3), confidence=round(max(confidence, 0), 3),
                ))
    results.sort(key=lambda r: r.confidence, reverse=True)
    return results[:max_candidates]


def render_tileset_image(rom: bytes, offset: int, bpp: int, tile_count: int = 128,
                          cols: int = 16, scale: int = 4):
    """
    Renderiza os tiles como uma imagem PIL em grade, para inspeção visual
    (pelo usuário) e para envio ao modelo de visão. Requer Pillow.
    """
    from PIL import Image
    tile_size = 16 if bpp == 2 else 32
    rows = (tile_count + cols - 1) // cols
    img = Image.new("L", (cols * 8 * scale, rows * 8 * scale), color=32)
    max_val = (2 ** bpp) - 1
    for t in range(tile_count):
        tile_off = offset + t * tile_size
        pixels = decode_tile(rom, tile_off, bpp)
        tx, ty = (t % cols) * 8 * scale, (t // cols) * 8 * scale
        for row in range(8):
            for col in range(8):
                val = int(pixels[row][col] / max_val * 255) if max_val else 0
                for sy in range(scale):
                    for sx in range(scale):
                        img.putpixel((tx + col * scale + sx, ty + row * scale + sy), val)
    return img, cols, rows


FONT_OCR_PROMPT = """Esta imagem mostra uma grade de tiles gráficos extraídos de uma ROM de \
Super Nintendo, organizados em {cols} colunas por {rows} linhas, numerados a partir de 0 \
(esquerda para direita, cima para baixo). Alguns tiles podem estar em branco, ser ruído \
gráfico (não fonte de texto), ou repetir símbolos.

Para cada tile que claramente representa uma LETRA, NÚMERO, PONTUAÇÃO ou SÍMBOLO DE TEXTO \
legível, identifique qual caractere ele representa. Ignore tiles que pareçam ruído, sprites \
ou gráficos não relacionados a texto.

Responda SOMENTE em JSON, no formato:
{{"mappings": [{{"tile_index": 0, "character": "A", "confidence": "alta|media|baixa"}}, ...]}}
"""


def run_font_ocr(image, cols: int, rows: int, api_key: str, model_name: str = "gemini-2.0-flash") -> list[dict]:
    """
    Envia a imagem do tileset para o Gemini multimodal e retorna a lista de
    mapeamentos tile_index -> caractere propostos pelo modelo. O chamador
    é responsável por converter tile_index em byte real da ROM (depende de
    onde os tiles foram extraídos) e por apresentar tudo para revisão do
    usuário antes de aceitar como tabela.
    """
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)
    prompt = FONT_OCR_PROMPT.format(cols=cols, rows=rows)
    response = model.generate_content(
        [prompt, image],
        generation_config={"temperature": 0.1, "response_mime_type": "application/json"},
    )
    data = json.loads(response.text)
    return data.get("mappings", [])
