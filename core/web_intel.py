"""
core.web_intel
----------------
Busca por trabalho de engenharia reversa JÁ PUBLICADO sobre o jogo em
questão — não é "a IA descobrindo do zero", é "achar o que a comunidade de
ROM hacking já documentou" (tabelas .tbl, patches de tradução existentes,
notas técnicas sobre compressão/ponteiros). Isso é, na prática, o passo de
maior retorno para jogos populares.

Usa a busca HTML pública do DuckDuckGo (sem necessidade de chave de API).
Como é scraping de HTML de terceiros, está sujeito a quebrar se o site
mudar o layout — por isso todas as funções falham de forma graciosa e
nunca derrubam o restante do pipeline.
"""

from __future__ import annotations
from dataclasses import dataclass
import re


@dataclass
class WebResult:
    title: str
    url: str
    snippet: str


def _duckduckgo_html_search(query: str, max_results: int = 8, timeout: int = 10) -> list[WebResult]:
    import requests
    results: list[WebResult] = []
    try:
        resp = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            headers={"User-Agent": "Mozilla/5.0 (compatible; SNESTranslatorTool/1.0)"},
            timeout=timeout,
        )
        resp.raise_for_status()
    except Exception:  # noqa: BLE001
        return results

    html = resp.text
    # parsing tolerante por regex (evita dependência pesada de parser HTML completo;
    # se o layout do DuckDuckGo mudar, isso simplesmente retorna lista vazia).
    block_re = re.compile(
        r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?'
        r'class="result__snippet"[^>]*>(.*?)</a>',
        re.DOTALL,
    )
    for m in block_re.finditer(html):
        url_raw, title_html, snippet_html = m.groups()
        title = re.sub("<[^>]+>", "", title_html).strip()
        snippet = re.sub("<[^>]+>", "", snippet_html).strip()
        url = url_raw
        # DuckDuckGo às vezes embrulha a URL real em um redirect próprio
        redirect_match = re.search(r"uddg=([^&]+)", url)
        if redirect_match:
            from urllib.parse import unquote
            url = unquote(redirect_match.group(1))
        if title and url:
            results.append(WebResult(title=title, url=url, snippet=snippet))
        if len(results) >= max_results:
            break
    return results


def search_known_game_resources(title: str, region_hint: str = "") -> dict:
    """
    Executa algumas buscas direcionadas e agrupa por categoria de resultado.
    Retorna um dicionário {"tbl": [...], "patches": [...], "tecnico": [...]}.
    Nunca lança exceção — em caso de falha de rede, retorna listas vazias
    com uma nota explicando o motivo.
    """
    title_clean = title.strip()
    out = {"tbl": [], "patches": [], "tecnico": [], "erro": None}
    if not title_clean:
        out["erro"] = "Título do jogo vazio (header não identificado) — não é possível buscar."
        return out

    try:
        out["tbl"] = _duckduckgo_html_search(f'"{title_clean}" snes tbl table hacking', max_results=5)
        out["patches"] = _duckduckgo_html_search(
            f'"{title_clean}" site:romhacking.net translation patch', max_results=5)
        out["tecnico"] = _duckduckgo_html_search(
            f'"{title_clean}" snes rom hacking pointer compression', max_results=5)
    except Exception as e:  # noqa: BLE001
        out["erro"] = f"Falha ao buscar na web: {e}"
    return out
