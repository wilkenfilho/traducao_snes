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

    LIMITAÇÃO IMPORTANTE: isto assume que os bytes da ROM já são bitmap de
    tile CRU. A maioria dos jogos de SNES comprime gráficos (mesmo esquema
    de LZ/RLE usado pra texto, às vezes um esquema diferente e dedicado).
    Se essa varredura não encontra nada plausível, ou se a imagem renderizada
    parece ruído puro (alto contraste aleatório, sem forma de letra), isso é
    o sinal mais provável de que os gráficos estão comprimidos nesta região —
    não que a heurística "errou". Use `try_decompress_region_for_tiles()`
    antes de desistir.
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


def try_decompress_region_for_tiles(rom: bytes, offset: int, search_window: int = 4096) -> dict | None:
    """
    Tenta descomprimir a região antes de tratá-la como bitmap de tile cru —
    reaproveita a mesma biblioteca de descompressores validados por
    round-trip usada para texto (core.compression). Gráficos em SNES às
    vezes usam o mesmo esquema do texto, às vezes um esquema dedicado (não
    coberto aqui). Retorna {"decompressed": bytes, "scheme": str, "confidence": float}
    ou None se nada auto-consistente foi encontrado.
    """
    from . import compression
    matches = compression.try_all_schemes(rom, offset, search_window=search_window,
                                           min_plausible_len=64)
    consistent = [m for m in matches if m.self_consistent]
    if not consistent:
        return None
    best = consistent[0]
    return {"decompressed": best.decompressed, "scheme": best.scheme, "confidence": best.confidence}


def label_tiles_from_known_table(byte_to_char: dict, base_byte: int = 0x00,
                                  tile_count: int = 128) -> dict[int, str]:
    """
    Reaproveita a TBL já confirmada pelo usuário: se a convenção do jogo é
    "índice do tile na VRAM = valor do byte do caractere" (comum, mas NÃO
    universal — tabelas descritas como "Complex" costumam remapear a ordem),
    isto rotula de graça, sem gastar nenhuma chamada de IA, todo tile cujo
    byte correspondente já tem um caractere ÚNICO conhecido na tabela
    (ignora entradas DTE multi-caractere e comandos [CMD_xx], que não são
    um glifo visual single-tile).
    """
    labels = {}
    for tile_index in range(tile_count):
        byte_val = base_byte + tile_index
        char = byte_to_char.get(byte_val)
        if char and len(char) == 1 and char.isprintable():
            labels[tile_index] = char
    return labels


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

VALIDATE_HYPOTHESIS_PROMPT = """Esta imagem mostra uma grade de tiles gráficos de uma ROM de \
Super Nintendo, {cols} colunas por {rows} linhas, numerados a partir de 0 (esquerda->direita, \
cima->baixo).

Olhe APENAS estes tiles específicos e diga qual caractere cada um parece representar \
visualmente (letra, número, pontuação — ou "ilegível"/"não é texto" se não parecer um glifo \
de texto): {tile_indices}

Responda SOMENTE em JSON: {{"readings": [{{"tile_index": N, "character_read": "X"}}, ...]}}
Mesma quantidade e ordem dos índices pedidos.
"""

UNKNOWN_ONLY_PROMPT = """Esta imagem mostra uma grade de tiles gráficos de uma ROM de Super \
Nintendo, {cols} colunas por {rows} linhas, numerados a partir de 0 (esquerda->direita, \
cima->baixo). A maioria dos tiles já foi identificada por outra fonte e NÃO precisa da sua \
análise.

Analise APENAS estes tiles, cujo caractere ainda é desconhecido: {tile_indices}
Para cada um, diga qual caractere/símbolo ele representa (ou "ilegível"/"não é texto").

Responda SOMENTE em JSON: {{"mappings": [{{"tile_index": N, "character": "X", \
"confidence": "alta|media|baixa"}}, ...]}}
"""


def run_font_ocr(image, cols: int, rows: int, api_key: str, model_name: str = "gemini-2.0-flash") -> list[dict]:
    """
    Modo "gastador": pede ao modelo pra ler TODOS os tiles da grade de uma vez.
    Use `run_font_ocr_economical()` sempre que já existir uma TBL confirmada —
    ele gasta uma fração disso.
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


def validate_tile_hypothesis(image, cols: int, rows: int, api_key: str, model_name: str,
                              hypothesis_labels: dict[int, str], sample_size: int = 10) -> dict:
    """
    Passo econômico #1: em vez de pedir pro modelo ler TODOS os tiles, pede
    pra ler só uma AMOSTRA pequena (padrão 10) dos tiles que a TBL já
    rotulou por hipótese (índice do tile = valor do byte). Se o modelo
    confirma a maioria, a hipótese é válida e o resto da tabela já rotulada
    pela TBL pode ser aceito de graça, sem gastar mais chamadas. Se não
    confirma, avisa que a suposição de ordem não vale pra esse jogo (comum
    em tabelas descritas como "Complex"/remapeadas).
    """
    if not hypothesis_labels:
        return {"agreement_rate": 0.0, "checked": [], "verdict": "sem_hipotese",
                "note": "Nenhum tile pôde ser rotulado por hipótese a partir da TBL atual."}

    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)

    sample_indices = sorted(hypothesis_labels.keys())[:sample_size] if len(hypothesis_labels) <= sample_size \
        else sorted(list(hypothesis_labels.keys()))[::max(1, len(hypothesis_labels) // sample_size)][:sample_size]

    prompt = VALIDATE_HYPOTHESIS_PROMPT.format(cols=cols, rows=rows, tile_indices=sample_indices)
    response = model.generate_content(
        [prompt, image],
        generation_config={"temperature": 0.0, "response_mime_type": "application/json"},
    )
    data = json.loads(response.text)
    readings = {r["tile_index"]: r.get("character_read", "") for r in data.get("readings", [])}

    checked = []
    matches = 0
    for idx in sample_indices:
        expected = hypothesis_labels[idx]
        got = readings.get(idx, "")
        is_match = got.strip().lower() == expected.strip().lower()
        if is_match:
            matches += 1
        checked.append({"tile_index": idx, "hypothesis": expected, "model_read": got, "match": is_match})

    agreement = matches / len(sample_indices) if sample_indices else 0.0
    if agreement >= 0.7:
        verdict = "confirmado"
        note = (f"{matches}/{len(sample_indices)} tiles bateram — hipótese "
                f"'índice do tile = byte' parece válida. O restante da tabela rotulado "
                f"pela TBL pode ser usado sem gastar mais chamadas de IA.")
    elif agreement >= 0.3:
        verdict = "parcial"
        note = (f"Só {matches}/{len(sample_indices)} bateram — correspondência parcial. "
                f"Pode haver deslocamento (offset errado) ou remapeamento parcial. Revise "
                f"manualmente antes de confiar.")
    else:
        verdict = "nao_confirmado"
        note = (f"Apenas {matches}/{len(sample_indices)} bateram — a ordem dos tiles NÃO "
                f"corresponde ao valor do byte para este jogo (bem possível numa tabela "
                f"'Complex' como a sua). Não reaproveite a TBL para rotular o resto; "
                f"use OCR completo ou busque a região certa manualmente.")

    return {"agreement_rate": round(agreement, 3), "checked": checked, "verdict": verdict, "note": note}


def run_font_ocr_unknown_only(image, cols: int, rows: int, api_key: str, model_name: str,
                               unknown_indices: list[int]) -> list[dict]:
    """
    Passo econômico #2: depois de validar a hipótese, só manda pro modelo
    ler os tiles que a TBL NÃO explica (bytes de controle [CMD_xx], bytes
    sem entrada na tabela) — ou seja, exatamente os casos em que o OCR
    agrega informação nova. Isso evita pagar por tiles cuja resposta você
    já sabia de graça pela TBL.
    """
    if not unknown_indices:
        return []
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)
    prompt = UNKNOWN_ONLY_PROMPT.format(cols=cols, rows=rows, tile_indices=unknown_indices)
    response = model.generate_content(
        [prompt, image],
        generation_config={"temperature": 0.1, "response_mime_type": "application/json"},
    )
    data = json.loads(response.text)
    return data.get("mappings", [])
