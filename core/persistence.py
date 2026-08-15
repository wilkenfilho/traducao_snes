"""
core.persistence
------------------
Salvar/carregar o progresso da sessão (tabela ativa, blocos detectados,
traduções feitas, candidatos de ponteiro) para poder continuar depois — o
Streamlit perde todo o estado quando a aba fecha ou o servidor reinicia.

Dois destinos:
1. Local (.json baixado/enviado pelo navegador) — sempre disponível, não
   depende de nada externo, mas o usuário precisa guardar o arquivo.
2. GitHub (API de Conteúdo de um repositório do usuário) — persiste de
   verdade entre sessões/redeploys, útil para "app privado só meu" hospedado
   no Streamlit Community Cloud, cujo disco é efêmero. Requer um Personal
   Access Token do GitHub com escopo de escrita no repositório escolhido.

SEGURANÇA: a chave do Gemini e o token do GitHub, quando salvos no GitHub,
ficam no arquivo JSON do progresso — recomende SEMPRE um repositório
PRIVADO para isso. Este módulo nunca loga ou expõe esses valores fora do
que o próprio usuário pediu para salvar.
"""

from __future__ import annotations
import base64
import json
from typing import Any


def _bytes_to_b64(obj: Any) -> Any:
    """Converte recursivamente bytes para string base64, pra caber em JSON."""
    if isinstance(obj, bytes):
        return {"__bytes_b64__": base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, dict):
        return {k: _bytes_to_b64(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_bytes_to_b64(v) for v in obj]
    return obj


def _b64_to_bytes(obj: Any) -> Any:
    if isinstance(obj, dict):
        if set(obj.keys()) == {"__bytes_b64__"}:
            return base64.b64decode(obj["__bytes_b64__"])
        return {k: _b64_to_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_b64_to_bytes(v) for v in obj]
    return obj


def serialize_session(
    filename: str,
    table_result: Any,
    text_blocks: list,
    translations: dict,
    glossary_terms: dict,
    pointer_candidates: list,
    gemini_model: str,
    rom_sha1: str = "",
) -> dict:
    """
    Monta um dicionário JSON-serializável com o essencial da sessão. NÃO
    inclui a ROM em si (o usuário reenvia o arquivo original — evita
    arquivos de progresso gigantes e problemas de direitos autorais de
    redistribuir a ROM).
    """
    data = {
        "version": 1,
        "filename": filename,
        "rom_sha1": rom_sha1,
        "gemini_model": gemini_model,
        "table_result": {
            "byte_to_char": table_result.byte_to_char,
            "confidence": table_result.confidence,
            "method": table_result.method,
            "notes": table_result.notes,
        } if table_result else None,
        "text_blocks": [
            {
                "start": b.start, "end": b.end, "raw": b.raw, "text": b.text,
                "confidence": b.confidence, "terminated_cleanly": b.terminated_cleanly,
                "category_hint": b.category_hint, "ai_verdict": b.ai_verdict,
                "ai_confidence": b.ai_confidence, "ai_reason": b.ai_reason,
            } for b in text_blocks
        ],
        "translations": {str(k): v for k, v in translations.items()},
        "glossary_terms": glossary_terms,
        "pointer_candidates": [
            {
                "table_offset": c.table_offset, "entry_count": c.entry_count,
                "entry_size": c.entry_size, "matched_block_indices": c.matched_block_indices,
                "confidence": c.confidence, "kind": getattr(c, "kind", "direto_16bit"),
            } for c in pointer_candidates
        ],
    }
    return _bytes_to_b64(data)


def deserialize_session(data: dict) -> dict:
    """
    Desserializa de volta em estruturas que o app.py sabe reconstruir
    (dicts simples — o app.py é responsável por reconstruir TextBlock,
    TableResult, etc. a partir daqui, mantendo este módulo independente
    das classes de core.text_scan/tbl/pointers).
    """
    return _b64_to_bytes(data)


def save_local_json(data: dict) -> bytes:
    """Retorna os bytes prontos pra um st.download_button."""
    return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")


def load_local_json(raw_bytes: bytes) -> dict:
    return json.loads(raw_bytes.decode("utf-8"))


# ---------------------------------------------------------------------------
# GitHub Contents API — salvar/carregar como arquivo num repositório privado
# ---------------------------------------------------------------------------

def _github_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_save_json(token: str, owner: str, repo: str, path: str, data: dict,
                      branch: str = "main", commit_message: str = "Atualiza progresso da tradução") -> dict:
    """
    Cria ou atualiza `path` no repositório via API de Conteúdo do GitHub.
    Retorna {"ok": bool, "message": str}.
    """
    import requests
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    content_b64 = base64.b64encode(
        json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    ).decode("ascii")

    # precisa do sha do arquivo atual se ele já existir, senão a API recusa o update
    sha = None
    try:
        get_resp = requests.get(url, headers=_github_headers(token), params={"ref": branch}, timeout=15)
        if get_resp.status_code == 200:
            sha = get_resp.json().get("sha")
    except Exception:  # noqa: BLE001
        pass

    payload = {"message": commit_message, "content": content_b64, "branch": branch}
    if sha:
        payload["sha"] = sha

    try:
        resp = requests.put(url, headers=_github_headers(token), json=payload, timeout=20)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "message": f"Falha de rede ao salvar no GitHub: {e}"}

    if resp.status_code in (200, 201):
        return {"ok": True, "message": f"Progresso salvo em {owner}/{repo}/{path} (branch {branch})."}
    try:
        detail = resp.json().get("message", resp.text)
    except Exception:  # noqa: BLE001
        detail = resp.text
    return {"ok": False, "message": f"GitHub retornou erro {resp.status_code}: {detail}"}


def github_load_json(token: str, owner: str, repo: str, path: str, branch: str = "main") -> dict:
    """Retorna {"ok": bool, "data": dict|None, "message": str}."""
    import requests
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    try:
        resp = requests.get(url, headers=_github_headers(token), params={"ref": branch}, timeout=15)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "data": None, "message": f"Falha de rede ao ler do GitHub: {e}"}

    if resp.status_code == 404:
        return {"ok": False, "data": None, "message": "Arquivo não encontrado nesse caminho/branch."}
    if resp.status_code != 200:
        try:
            detail = resp.json().get("message", resp.text)
        except Exception:  # noqa: BLE001
            detail = resp.text
        return {"ok": False, "data": None, "message": f"GitHub retornou erro {resp.status_code}: {detail}"}

    content_b64 = resp.json().get("content", "")
    try:
        raw = base64.b64decode(content_b64)
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "data": None, "message": f"Arquivo encontrado mas não é um progresso válido: {e}"}

    return {"ok": True, "data": data, "message": "Progresso carregado do GitHub."}
