"""
SNES/Super Famicom Fan Translator — app Streamlit
====================================================
Ferramenta de apoio à tradução de ROMs SNES para português do Brasil.

IMPORTANTE — leia antes de usar:
Detecção 100% automática de tabela de caracteres, ponteiros, compressão e
blocos de texto para QUALQUER jogo SNES sem nenhuma informação prévia não é
um problema resolvido — nem por ferramentas comerciais de ROM hacking. Este
app usa heurísticas reais (busca relativa, análise de frequência, escaneamento
de ponteiros de 16 bits) e reporta um nível de confiança explícito para cada
detecção. Ele nunca aplica uma alteração quando a confiança está abaixo do
limite de segurança — nesses casos, ele informa exatamente o que não pôde
ser identificado, em vez de "inventar" um resultado.
"""

from __future__ import annotations
import io
import json
import time
import sys
import hashlib
from pathlib import Path

import streamlit as st

# Garante que a pasta deste script (e portanto o pacote `core/` dentro dela)
# esteja no sys.path, independentemente do diretório de trabalho com que o
# Streamlit foi iniciado. Em alguns ambientes de deploy (ex.: Streamlit
# Community Cloud com uv + Python 3.14) o cwd do processo não é
# necessariamente a pasta do script, o que quebra imports relativos ao
# projeto como `from core import ...`.
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from core import (rom_io, tbl, text_scan, pointers, ips_patch, translator, relocation,
                  profiles, compression, web_intel, font_vision, block_classifier, persistence)

st.set_page_config(page_title="SNES ROM Translator PT-BR", layout="wide")

CONFIDENCE_SAFE = 0.60
CONFIDENCE_WARN = 0.40
LOCAL_CONFIG_PATH = APP_DIR / ".snes_translator_local_config.json"

# --------------------------------------------------------------------------
# configuração persistida localmente no servidor (opcional — ver aviso na sidebar)
# --------------------------------------------------------------------------
def _read_local_config() -> dict:
    if LOCAL_CONFIG_PATH.exists():
        try:
            return json.loads(LOCAL_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _write_local_config(data: dict) -> None:
    try:
        LOCAL_CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

# --------------------------------------------------------------------------
# estado da sessão
# --------------------------------------------------------------------------
def _init_state():
    local_cfg = _read_local_config()
    saved_model = local_cfg.get("gemini_model", "gemini-flash-latest")
    if saved_model in ("gemini-2.0-flash", "gemini-1.5-flash", "gemini-pro"):
        # migração automática: modelos antigos foram descontinuados pela Google:
        # https://ai.google.dev/gemini-api/docs/changelog — usa o alias que se
        # autoatualiza em vez de reintroduzir um modelo que já quebrou.
        saved_model = "gemini-flash-latest"
    defaults = {
        "gemini_api_key": local_cfg.get("gemini_api_key", ""),
        "gemini_model": saved_model,
        "github_token": local_cfg.get("github_token", ""),
        "github_owner": local_cfg.get("github_owner", ""),
        "github_repo": local_cfg.get("github_repo", ""),
        "github_path": local_cfg.get("github_path", "snes_translator_progress.json"),
        "github_branch": local_cfg.get("github_branch", "main"),
        "rom_info": None,
        "raw_bytes": None,
        "filename": None,
        "table_result": None,
        "text_blocks": [],
        "pointer_candidates": [],
        "translations": {},   # block_index -> texto traduzido
        "glossary": translator.TranslationGlossary(),
        "log": [],
        "step": 1,
        "modified_rom": None,
        "ips_bytes": None,
        "validation": None,
        "ai_classify_progress": 0,  # quantos blocos já foram classificados nesta sessão
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    st.session_state["log"].append(f"[{ts}] {msg}")


def _restore_session_from_data(data: dict) -> None:
    """Reconstrói o estado da sessão a partir de um progresso salvo (local ou GitHub)."""
    d = persistence.deserialize_session(data)
    if d.get("table_result"):
        tr = d["table_result"]
        byte_to_char = {int(k): v for k, v in tr["byte_to_char"].items()}
        st.session_state["table_result"] = tbl.build_table_result(
            tr["method"], byte_to_char, tr["confidence"], tr.get("notes", "")
        )
    st.session_state["text_blocks"] = [
        text_scan.TextBlock(
            start=b["start"], end=b["end"], raw=b["raw"], text=b["text"],
            confidence=b["confidence"], terminated_cleanly=b["terminated_cleanly"],
            category_hint=b.get("category_hint", "desconhecido"),
            ai_verdict=b.get("ai_verdict"), ai_confidence=b.get("ai_confidence"),
            ai_reason=b.get("ai_reason", ""),
        ) for b in d.get("text_blocks", [])
    ]
    st.session_state["translations"] = {int(k): v for k, v in d.get("translations", {}).items()}
    st.session_state["glossary"] = translator.TranslationGlossary(terms=d.get("glossary_terms", {}))
    st.session_state["pointer_candidates"] = [
        pointers.PointerTableCandidate(
            table_offset=c["table_offset"], entry_count=c["entry_count"],
            entry_size=c["entry_size"], matched_block_indices=c["matched_block_indices"],
            confidence=c["confidence"], kind=c.get("kind", "direto_16bit"),
        ) for c in d.get("pointer_candidates", [])
    ]
    if d.get("gemini_model"):
        restored_model = d["gemini_model"]
        if restored_model in ("gemini-2.0-flash", "gemini-1.5-flash", "gemini-pro"):
            restored_model = "gemini-flash-latest"
        st.session_state["gemini_model"] = restored_model
    log(f"Progresso restaurado: {len(st.session_state['text_blocks'])} blocos, "
        f"{len(st.session_state['translations'])} traduções, filename original: {d.get('filename')}.")


_init_state()

# --------------------------------------------------------------------------
# sidebar: configuração do Gemini + persistência + debug
# --------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Configuração")
    api_key_input = st.text_input(
        "Chave de API do Gemini", value=st.session_state["gemini_api_key"], type="password",
    )
    st.session_state["gemini_api_key"] = api_key_input
    st.session_state["gemini_model"] = st.text_input(
        "Modelo Gemini", value=st.session_state["gemini_model"],
        help="Padrão: 'gemini-flash-latest' — alias que a Google aponta automaticamente pro "
             "Flash mais recente, então não quebra quando um modelo específico é aposentado. "
             "Se quiser fixar uma versão exata (mais previsível, mas quebra quando descontinuada), "
             "use algo como 'gemini-3.6-flash'. Se aparecer erro 404 de modelo indisponível, "
             "troque aqui pelo modelo atual (confira em ai.google.dev/gemini-api/docs/models)."
    )
    remember_key = st.checkbox(
        "🔒 Lembrar esta chave neste servidor (arquivo local)",
        value=bool(_read_local_config().get("gemini_api_key")),
        help="Grava em um arquivo local no servidor onde este app está rodando — "
             "só faz sentido se o app for privado (só seu). Em hospedagens com disco "
             "efêmero (ex.: Streamlit Community Cloud após um redeploy), isso pode "
             "não sobreviver a um reinício; para persistência garantida entre "
             "redeploys, use 'Salvar no GitHub' abaixo.",
    )
    if remember_key and api_key_input:
        cfg = _read_local_config()
        if cfg.get("gemini_api_key") != api_key_input or cfg.get("gemini_model") != st.session_state["gemini_model"]:
            cfg["gemini_api_key"] = api_key_input
            cfg["gemini_model"] = st.session_state["gemini_model"]
            _write_local_config(cfg)
    elif not remember_key and _read_local_config().get("gemini_api_key"):
        cfg = _read_local_config()
        cfg.pop("gemini_api_key", None)
        _write_local_config(cfg)

    st.divider()
    st.header("💾 Progresso")
    st.caption("Salve seu progresso (tabela, blocos, traduções) para continuar depois — "
               "reenviando a mesma ROM na próxima sessão.")

    can_save = bool(st.session_state["text_blocks"] or st.session_state["table_result"])
    session_data = None
    if can_save:
        session_data = persistence.serialize_session(
            filename=st.session_state["filename"] or "",
            table_result=st.session_state["table_result"],
            text_blocks=st.session_state["text_blocks"],
            translations=st.session_state["translations"],
            glossary_terms=st.session_state["glossary"].terms,
            pointer_candidates=st.session_state["pointer_candidates"],
            gemini_model=st.session_state["gemini_model"],
            rom_sha1=hashlib.sha1(st.session_state["raw_bytes"]).hexdigest() if st.session_state["raw_bytes"] else "",
        )

    with st.expander("📄 Local (.json)"):
        if session_data:
            st.download_button(
                "⬇️ Baixar progresso", data=persistence.save_local_json(session_data),
                file_name="snes_translator_progress.json", mime="application/json",
            )
        else:
            st.caption("Nada para salvar ainda — escaneie a ROM primeiro.")
        uploaded_progress = st.file_uploader("⬆️ Carregar progresso (.json)", type=["json"], key="progress_upload")
        if uploaded_progress is not None:
            if st.button("Restaurar este progresso"):
                try:
                    data = persistence.load_local_json(uploaded_progress.getvalue())
                    _restore_session_from_data(data)
                    st.success("Progresso restaurado! Reenvie a mesma ROM para continuar.")
                    st.rerun()
                except Exception as e:  # noqa: BLE001
                    st.error(f"Falha ao restaurar progresso: {e}")

    with st.expander("🐙 GitHub (repositório privado recomendado)"):
        st.session_state["github_token"] = st.text_input(
            "Personal Access Token", value=st.session_state["github_token"], type="password",
            help="Precisa de escopo de escrita de conteúdo no repositório (classic: 'repo'; "
                 "fine-grained: Contents: Read and write)."
        )
        c1, c2 = st.columns(2)
        st.session_state["github_owner"] = c1.text_input("Dono/organização", value=st.session_state["github_owner"])
        st.session_state["github_repo"] = c2.text_input("Repositório", value=st.session_state["github_repo"])
        c3, c4 = st.columns(2)
        st.session_state["github_path"] = c3.text_input("Caminho do arquivo", value=st.session_state["github_path"])
        st.session_state["github_branch"] = c4.text_input("Branch", value=st.session_state["github_branch"])

        remember_github = st.checkbox(
            "🔒 Lembrar estas configurações do GitHub neste servidor (inclui o token!)",
            value=bool(_read_local_config().get("github_token")),
            help="⚠️ O token fica salvo em texto puro no disco do servidor. Só habilite se este "
                 "app for privado e só seu, e use um repositório PRIVADO no GitHub.",
        )
        if remember_github and st.session_state["github_token"]:
            cfg = _read_local_config()
            cfg.update({
                "github_token": st.session_state["github_token"],
                "github_owner": st.session_state["github_owner"],
                "github_repo": st.session_state["github_repo"],
                "github_path": st.session_state["github_path"],
                "github_branch": st.session_state["github_branch"],
            })
            _write_local_config(cfg)

        gh_ready = all([st.session_state["github_token"], st.session_state["github_owner"],
                         st.session_state["github_repo"], st.session_state["github_path"]])

        colg1, colg2 = st.columns(2)
        if colg1.button("⬆️ Salvar no GitHub", disabled=not (gh_ready and session_data)):
            with st.spinner("Salvando no GitHub..."):
                result = persistence.github_save_json(
                    st.session_state["github_token"], st.session_state["github_owner"],
                    st.session_state["github_repo"], st.session_state["github_path"],
                    session_data, branch=st.session_state["github_branch"],
                )
            (st.success if result["ok"] else st.error)(result["message"])
            log(f"Salvar no GitHub: ok={result['ok']} — {result['message']}")

        if colg2.button("⬇️ Carregar do GitHub", disabled=not gh_ready):
            with st.spinner("Carregando do GitHub..."):
                result = persistence.github_load_json(
                    st.session_state["github_token"], st.session_state["github_owner"],
                    st.session_state["github_repo"], st.session_state["github_path"],
                    branch=st.session_state["github_branch"],
                )
            if result["ok"]:
                try:
                    _restore_session_from_data(result["data"])
                    st.success("Progresso restaurado do GitHub! Reenvie a mesma ROM para continuar.")
                    st.rerun()
                except Exception as e:  # noqa: BLE001
                    st.error(f"Progresso encontrado, mas falhou ao restaurar: {e}")
            else:
                st.error(result["message"])
            log(f"Carregar do GitHub: ok={result['ok']} — {result['message']}")

    st.divider()
    st.header("🐞 Debug em tempo real")
    show_debug = st.toggle("Mostrar console de debug", value=False)
    if show_debug:
        st.text_area("Log", value="\n".join(st.session_state["log"][-200:]), height=300)
        if st.button("Limpar log"):
            st.session_state["log"] = []
            st.rerun()

st.title("🎮 Tradutor de ROMs SNES/Super Famicom → Português (BR)")
st.caption("Upload → Diagnóstico → Detecção de texto/ponteiros → Tradução (Gemini) → "
           "Revisão → Patch IPS validado")

# --------------------------------------------------------------------------
# ETAPA 1 — upload e diagnóstico
# --------------------------------------------------------------------------
st.header("1️⃣ Upload e diagnóstico técnico")

uploaded = st.file_uploader("Envie a ROM (.sfc ou .smc)", type=["sfc", "smc"])

if uploaded is not None:
    raw = uploaded.getvalue()
    if st.session_state["raw_bytes"] != raw:
        st.session_state["raw_bytes"] = raw
        st.session_state["filename"] = uploaded.name
        log(f"Arquivo recebido: {uploaded.name} ({len(raw)} bytes)")
        with st.spinner("Analisando ROM..."):
            info = rom_io.analyze_rom(uploaded.name, raw)
        st.session_state["rom_info"] = info
        st.session_state["table_result"] = None
        st.session_state["text_blocks"] = []
        st.session_state["pointer_candidates"] = []
        st.session_state["ai_classify_progress"] = 0
        st.session_state["translations"] = {}
        st.session_state["modified_rom"] = None
        st.session_state["ips_bytes"] = None
        st.session_state["validation"] = None
        log(f"Header de copiadora detectado: {info.has_copier_header}")
        if info.best_mapping:
            log(f"Mapeamento mais provável: {info.best_mapping.mapping} "
                f"(confiança {info.best_mapping.confidence:.0%})")

info: rom_io.RomInfo | None = st.session_state["rom_info"]

if info is not None:
    md5 = hashlib.md5(st.session_state["raw_bytes"]).hexdigest()
    sha1 = hashlib.sha1(st.session_state["raw_bytes"]).hexdigest()

    c1, c2, c3 = st.columns(3)
    c1.metric("Tamanho do arquivo", f"{info.raw_size:,} bytes")
    c2.metric("Header de copiadora (512B)", "Sim" if info.has_copier_header else "Não")
    c3.metric("Tamanho da ROM (sem header)", f"{len(info.rom):,} bytes")

    with st.expander("Hashes e detalhes brutos"):
        st.code(f"MD5:  {md5}\nSHA1: {sha1}")

    if info.best_mapping:
        bm = info.best_mapping
        conf_color = "🟢" if bm.confidence >= CONFIDENCE_SAFE else ("🟡" if bm.confidence >= CONFIDENCE_WARN else "🔴")
        st.subheader(f"{conf_color} Mapeamento detectado: {bm.mapping} — confiança {bm.confidence:.0%}")
        d1, d2, d3, d4 = st.columns(4)
        d1.write(f"**Título (header):** {bm.title or '(vazio)'}")
        d2.write(f"**Região:** {bm.region_name}")
        d3.write(f"**Checksum válido:** {'✅' if bm.checksum_valid else '❌'}")
        d4.write(f"**Versão:** {bm.version}")

        with st.expander("Ver todos os candidatos de mapeamento avaliados"):
            for c in info.candidates:
                st.write(f"- {c.mapping} @ 0x{c.header_offset:X} — confiança {c.confidence:.0%} "
                         f"(checksum válido: {c.checksum_valid})")
    else:
        st.error("Nenhum header interno válido foi localizado.")

    if info.risks:
        st.warning("**Riscos/avisos técnicos detectados:**\n\n" + "\n".join(f"- {r}" for r in info.risks))

    matched_profile = profiles.detect_profile(info)
    if matched_profile:
        st.success(f"Perfil de jogo dedicado encontrado: **{matched_profile.display_name}** "
                    f"— {matched_profile.notes}")
    else:
        st.info("Nenhum perfil dedicado para este jogo (ver `core/profiles.py`). "
                "Usando pipeline genérico por heurísticas.")

    rom_safe_to_continue = info.best_mapping is not None and info.best_mapping.confidence >= CONFIDENCE_WARN
else:
    rom_safe_to_continue = False
    st.info("Envie um arquivo .sfc ou .smc para iniciar o diagnóstico.")

# --------------------------------------------------------------------------
# ETAPA 2 — tabela de caracteres (TBL)
# --------------------------------------------------------------------------
if rom_safe_to_continue:
    st.header("2️⃣ Tabela de caracteres (TBL)")
    st.write("Escolha como a ROM mapeia bytes → caracteres. Isso é específico de cada jogo.")

    tbl_method = st.radio(
        "Método",
        ["Importar arquivo .tbl", "Busca relativa (palavra conhecida)", "Hipótese ASCII direta",
         "🎨 Detectar fonte via IA (visão computacional)", "🌐 Buscar documentação/TBL conhecida na web"],
        horizontal=False,
    )

    mapping_name = info.best_mapping.mapping

    if tbl_method == "Importar arquivo .tbl":
        tbl_file = st.file_uploader("Arquivo .tbl (formato XX=c)", type=["tbl", "txt"], key="tblfile")
        if tbl_file is not None:
            text = tbl_file.getvalue().decode("utf-8", errors="replace")
            mapping_dict = tbl.parse_tbl_text(text)
            if mapping_dict:
                st.session_state["table_result"] = tbl.build_table_result(
                    "tbl_import", mapping_dict, confidence=0.95,
                    notes="Tabela importada manualmente pelo usuário."
                )
                log(f"TBL importada com {len(mapping_dict)} entradas.")
                st.success(f"Tabela importada com {len(mapping_dict)} entradas.")
            else:
                st.error("Não foi possível ler entradas válidas do arquivo .tbl.")

    elif tbl_method == "Busca relativa (palavra conhecida)":
        known_word = st.text_input("Palavra que você sabe que existe no jogo (ex.: LEVEL, HP, um nome próprio)")
        if st.button("Buscar", disabled=not known_word):
            with st.spinner("Executando busca relativa na ROM..."):
                results = tbl.relative_search(info.rom, known_word)
            log(f"Busca relativa por '{known_word}': {len(results)} candidatos.")
            if not results:
                st.error("Nenhum candidato encontrado. Tente outra palavra ou use importação de .tbl.")
            else:
                st.session_state["_relative_results"] = results
                st.success(f"{len(results)} candidato(s) encontrado(s). Escolha o mais plausível abaixo.")

        results = st.session_state.get("_relative_results", [])
        if results:
            options = [f"offset 0x{r['offset']:06X} — shift de byte {r['byte_shift']:+d}" for r in results]
            choice = st.selectbox("Candidato", options)
            idx = options.index(choice)
            chosen = results[idx]
            if st.button("Usar este candidato como tabela"):
                st.session_state["table_result"] = tbl.build_table_result(
                    "relative_search", chosen["inferred_table"], confidence=0.55,
                    notes=f"Inferida por busca relativa a partir de '{known_word}' no offset 0x{chosen['offset']:06X}. "
                          f"Cobre apenas A-Z, a-z, 0-9 e espaço — revise manualmente."
                )
                log("Tabela definida via busca relativa.")
                st.success("Tabela parcial definida (apenas alfabeto/números/espaço). "
                            "Você pode complementar importando um .tbl depois.")

    elif tbl_method == "🎨 Detectar fonte via IA (visão computacional)":
        st.caption("Extrai tiles gráficos da ROM e usa o Gemini para *ler visualmente* a fonte "
                   "do jogo. Se você já tem uma TBL confirmada (importada ou de busca relativa), "
                   "ela é reaproveitada pra rotular a maioria dos tiles DE GRAÇA e só gastar IA no "
                   "que sobrar — muito mais barato que OCR completo.")

        has_confirmed_tbl = (st.session_state["table_result"] is not None
                              and st.session_state["table_result"].method != "font_vision")
        if has_confirmed_tbl:
            st.success(f"✅ TBL ativa detectada (`{st.session_state['table_result'].method}`, "
                       f"{len(st.session_state['table_result'].byte_to_char)} entradas) — será "
                       f"reaproveitada para economizar chamadas de IA nesta etapa.")
        else:
            st.info("Nenhuma TBL confirmada ainda — o OCR vai precisar ler todos os tiles (mais caro). "
                    "Se você já tem um .tbl, importe-o primeiro na opção acima.")

        if st.button("1) Escanear candidatos a região de fonte"):
            with st.spinner("Procurando regiões de tiles com aparência de glifos..."):
                cands = font_vision.scan_font_candidates(info.rom)
            st.session_state["_font_candidates"] = cands
            log(f"{len(cands)} candidato(s) de região de fonte encontrados.")

        cands = st.session_state.get("_font_candidates", [])
        if not cands and "_font_candidates" in st.session_state:
            st.warning("Nenhum candidato plausível encontrado. Isso quase sempre significa que os "
                      "gráficos estão COMPRIMIDOS nesta ROM (muito comum) — bytes crus de dado "
                      "comprimido não têm a 'forma' estatística de um tile de fonte. Tente o botão "
                      "de descompressão abaixo em regiões específicas.")

        manual_offset = st.number_input("Ou informe um offset manualmente (hex)", value=0,
                                          format="%d", help="Deixe 0 para usar a lista de candidatos.")
        manual_offset_hex = st.text_input("Offset em hex (opcional, sobrescreve o campo acima)", value="")

        if cands:
            options = [f"offset 0x{c.offset:06X}, {c.bpp}bpp, confiança {c.confidence:.0%} "
                       f"(densidade de tinta média {c.avg_ink_ratio:.0%})" for c in cands]
            choice = st.selectbox("Candidato de região de fonte", options)
            chosen = cands[options.index(choice)]
            chosen_offset, chosen_bpp = chosen.offset, chosen.bpp
        else:
            chosen_offset, chosen_bpp = 0, 2

        if manual_offset_hex.strip():
            try:
                chosen_offset = int(manual_offset_hex.strip(), 16)
            except ValueError:
                st.error("Offset em hex inválido.")

        col_bpp, col_try_decomp = st.columns([1, 2])
        chosen_bpp = col_bpp.radio("bpp", [2, 4], index=(0 if chosen_bpp == 2 else 1), horizontal=True)
        try_decompress = col_try_decomp.checkbox(
            "🗜️ Tentar descomprimir esta região antes de renderizar",
            help="Reaproveita a biblioteca de descompressão validada por round-trip. Só funciona "
                 "se o esquema for RLE simples ou LZSS genérico — muitos jogos usam compressão "
                 "proprietária de gráficos não coberta aqui."
        )

        if st.button("2) Renderizar tileset para conferência visual"):
            render_rom = info.rom
            render_offset = chosen_offset
            if try_decompress:
                with st.spinner("Tentando descomprimir..."):
                    result = font_vision.try_decompress_region_for_tiles(info.rom, chosen_offset)
                if result:
                    render_rom = result["decompressed"]
                    render_offset = 0
                    st.success(f"Descompressão bem-sucedida: {result['scheme']} "
                               f"(confiança {result['confidence']:.0%}). Renderizando a partir dos "
                               f"dados descomprimidos.")
                    log(f"Fonte: descompressão {result['scheme']} aplicada antes de renderizar.")
                else:
                    st.warning("Nenhum esquema conhecido conseguiu descomprimir esta região com "
                              "segurança (round-trip). Renderizando os bytes crus mesmo assim — "
                              "se aparecer ruído, é provável que a compressão seja proprietária.")
            img, cols, rows = font_vision.render_tileset_image(
                render_rom, render_offset, chosen_bpp, tile_count=128, cols=16
            )
            st.session_state["_font_image"] = img
            st.session_state["_font_grid"] = (cols, rows, render_offset, chosen_bpp)
            st.session_state["_font_render_rom"] = render_rom

        if "_font_image" in st.session_state:
            st.image(st.session_state["_font_image"],
                      caption="Isto precisa parecer letras/símbolos legíveis. Se for ruído visual "
                              "(alto contraste aleatório, sem forma), o offset está errado ou os "
                              "gráficos estão comprimidos — tente outro candidato ou a descompressão.")

            cols, rows, off, bpp = st.session_state["_font_grid"]

            if has_confirmed_tbl:
                hypothesis_labels = font_vision.label_tiles_from_known_table(
                    st.session_state["table_result"].byte_to_char, base_byte=0x00, tile_count=128,
                )
                st.write(f"💰 **{len(hypothesis_labels)} tiles já rotulados de graça pela TBL** "
                        f"(hipótese: índice do tile = valor do byte). Vamos validar com uma "
                        f"amostra pequena antes de confiar no resto.")

                if st.button("3) Validar hipótese com amostra pequena (barato)",
                              disabled=not st.session_state["gemini_api_key"]):
                    with st.spinner("Checando uma amostra de tiles..."):
                        try:
                            result = font_vision.validate_tile_hypothesis(
                                st.session_state["_font_image"], cols, rows,
                                st.session_state["gemini_api_key"], st.session_state["gemini_model"],
                                hypothesis_labels, sample_size=10,
                            )
                            st.session_state["_font_validation"] = result
                            log(f"Validação de hipótese de fonte: {result['verdict']} "
                                f"({result['agreement_rate']:.0%} de concordância).")
                        except Exception as e:  # noqa: BLE001
                            st.error(f"Erro na validação: {e}")

                validation = st.session_state.get("_font_validation")
                if validation:
                    icon = {"confirmado": "✅", "parcial": "🟡", "nao_confirmado": "🔴",
                            "sem_hipotese": "⚪"}.get(validation["verdict"], "⚪")
                    st.write(f"{icon} **{validation['verdict']}** — concordância "
                            f"{validation['agreement_rate']:.0%}. {validation['note']}")
                    with st.expander("Ver amostra checada"):
                        st.dataframe(validation["checked"], use_container_width=True)

                    if validation["verdict"] in ("confirmado", "parcial"):
                        unknown_indices = [i for i in range(128) if i not in hypothesis_labels]
                        st.write(f"4) Restam **{len(unknown_indices)} tiles** sem explicação pela "
                                f"TBL (comandos/bytes não mapeados) — só esses vão para OCR completo.")
                        if st.button("Rodar OCR só nos tiles desconhecidos (econômico)",
                                      disabled=not st.session_state["gemini_api_key"]):
                            with st.spinner(f"Gemini lendo {len(unknown_indices)} tiles..."):
                                try:
                                    mappings = font_vision.run_font_ocr_unknown_only(
                                        st.session_state["_font_image"], cols, rows,
                                        st.session_state["gemini_api_key"], st.session_state["gemini_model"],
                                        unknown_indices,
                                    )
                                    st.session_state["_font_ocr_result"] = mappings
                                    st.session_state["_font_hypothesis_labels"] = hypothesis_labels
                                    log(f"OCR econômico (só desconhecidos): {len(mappings)} tiles lidos, "
                                        f"{len(hypothesis_labels)} já vieram de graça da TBL.")
                                except Exception as e:  # noqa: BLE001
                                    st.error(f"Erro no OCR: {e}")
                    else:
                        st.warning("Hipótese não confirmada — reaproveitar a TBL por posição não é "
                                  "seguro aqui. Use OCR completo (mais caro) se quiser mesmo assim.")
                        if st.button("Rodar OCR completo mesmo assim (gasta mais tokens)",
                                      disabled=not st.session_state["gemini_api_key"]):
                            with st.spinner("Gemini lendo todos os tiles..."):
                                try:
                                    mappings = font_vision.run_font_ocr(
                                        st.session_state["_font_image"], cols, rows,
                                        st.session_state["gemini_api_key"], st.session_state["gemini_model"],
                                    )
                                    st.session_state["_font_ocr_result"] = mappings
                                    st.session_state["_font_hypothesis_labels"] = {}
                                    log(f"OCR completo: {len(mappings)} tiles lidos.")
                                except Exception as e:  # noqa: BLE001
                                    st.error(f"Erro no OCR: {e}")
            else:
                if st.button("3) Rodar OCR completo com Gemini (sem TBL prévia pra economizar)",
                              disabled=not st.session_state["gemini_api_key"]):
                    with st.spinner("Gemini lendo os glifos..."):
                        try:
                            mappings = font_vision.run_font_ocr(
                                st.session_state["_font_image"], cols, rows,
                                st.session_state["gemini_api_key"], st.session_state["gemini_model"],
                            )
                            st.session_state["_font_ocr_result"] = mappings
                            st.session_state["_font_hypothesis_labels"] = {}
                            log(f"OCR de fonte retornou {len(mappings)} mapeamentos propostos.")
                        except Exception as e:  # noqa: BLE001
                            st.error(f"Erro no OCR: {e}")

        ocr_result = st.session_state.get("_font_ocr_result")
        if ocr_result is not None:
            hyp_labels = st.session_state.get("_font_hypothesis_labels", {})
            total_labeled = len(hyp_labels) + len(ocr_result)
            st.write(f"**{total_labeled} caracteres identificados no total** "
                    f"({len(hyp_labels)} de graça via TBL + {len(ocr_result)} via OCR) "
                    f"— revise antes de aceitar:")
            tile_size = 16 if st.session_state["_font_grid"][3] == 2 else 32
            base_offset = st.session_state["_font_grid"][2]
            edited_rows = []
            for idx, char in sorted(hyp_labels.items()):
                edited_rows.append({
                    "tile_index": idx, "byte": f"0x{idx:02X} (via TBL, de graça)",
                    "caractere_proposto": char, "origem": "TBL",
                })
            for m in ocr_result[:200]:
                edited_rows.append({
                    "tile_index": m.get("tile_index"),
                    "byte": f"0x{(base_offset + m.get('tile_index', 0) * tile_size) & 0xFF:02X} (aprox., via OCR)",
                    "caractere_proposto": m.get("character"), "origem": "IA (OCR)",
                })
            st.dataframe(edited_rows, use_container_width=True, height=300)
            st.warning("Nota técnica: o índice do tile precisa ser mapeado para o BYTE real usado "
                       "no texto do jogo (que pode não ser sequencial ao tile) — confirme manualmente "
                       "antes de aceitar esta tabela, ou combine com busca relativa para validar.")

    elif tbl_method == "🌐 Buscar documentação/TBL conhecida na web":
        st.caption("Busca se este jogo já tem tabela/patch/documentação publicados pela comunidade "
                   "(romhacking.net e web em geral) — encontrar trabalho já feito é sempre melhor "
                   "que redescobrir do zero.")
        game_title = info.best_mapping.title if info.best_mapping else ""
        search_title = st.text_input("Título para buscar", value=game_title)
        if st.button("Buscar na web"):
            with st.spinner("Buscando..."):
                results = web_intel.search_known_game_resources(search_title)
            if results.get("erro"):
                st.error(results["erro"])
            else:
                for categoria, label in [("patches", "Patches de tradução existentes"),
                                          ("tbl", "Tabelas .tbl / documentação de caracteres"),
                                          ("tecnico", "Notas técnicas (ponteiros/compressão)")]:
                    items = results.get(categoria, [])
                    if items:
                        st.subheader(label)
                        for r in items:
                            st.markdown(f"**[{r.title}]({r.url})**  \n{r.snippet}")
                if not any(results.get(c) for c in ("patches", "tbl", "tecnico")):
                    st.info("Nenhum resultado relevante encontrado — este jogo provavelmente "
                            "não tem documentação pública de ROM hacking.")

    else:  # Hipótese ASCII direta
        conf = tbl.score_ascii_hypothesis(info.rom)
        color = "🟢" if conf >= 0.6 else ("🟡" if conf >= 0.35 else "🔴")
        st.write(f"{color} Confiança da hipótese ASCII (teste de frequência de letras): **{conf:.0%}**")
        if conf < 0.35:
            st.warning("Confiança muito baixa — este jogo provavelmente usa uma tabela de caracteres "
                       "customizada (comum na maioria dos jogos originais SNES/Famicom). "
                       "Prefira importar um .tbl ou usar busca relativa.")
        if st.button("Usar hipótese ASCII mesmo assim"):
            st.session_state["table_result"] = tbl.build_table_result(
                "ascii_identity", tbl.identity_ascii_table(), confidence=conf,
                notes="Hipótese de ASCII direto, validada por teste estatístico de frequência de letras."
            )
            log(f"Tabela ASCII definida com confiança {conf:.0%}.")

    tr: tbl.TableResult | None = st.session_state["table_result"]
    if tr:
        conf_color = "🟢" if tr.confidence >= CONFIDENCE_SAFE else ("🟡" if tr.confidence >= CONFIDENCE_WARN else "🔴")
        st.info(f"{conf_color} Tabela ativa: método `{tr.method}`, {len(tr.byte_to_char)} entradas, "
                f"confiança {tr.confidence:.0%}. {tr.notes}")
        with st.expander("Baixar tabela atual (.tbl)"):
            st.download_button("Baixar .tbl", data=tbl.table_to_tbl_text(tr.byte_to_char),
                                file_name="tabela.tbl", mime="text/plain")

# --------------------------------------------------------------------------
# ETAPA 3 — detecção de blocos de texto e ponteiros
# --------------------------------------------------------------------------
if rom_safe_to_continue and st.session_state["table_result"]:
    st.header("3️⃣ Detecção de compressão")
    st.caption("Verifica se há regiões comprimidas na ROM antes de procurar texto — texto "
               "comprimido não aparece como texto legível numa varredura direta.")
    if st.button("🗜️ Escanear regiões possivelmente comprimidas"):
        with st.spinner("Calculando entropia por blocos..."):
            fingerprints = compression.scan_for_compressed_regions(info.rom, block_size=512, stride=1024)
        st.session_state["_compressed_regions"] = fingerprints
        log(f"{len(fingerprints)} região(ões) com indícios de compressão encontradas.")

    fingerprints = st.session_state.get("_compressed_regions", [])
    if fingerprints:
        st.warning(f"{len(fingerprints)} região(ões) com entropia típica de dado comprimido. "
                   "Texto dentro dessas regiões NÃO aparecerá na varredura de texto normal — "
                   "veja abaixo se algum esquema conhecido consegue reverter algum trecho.")
        sample = fingerprints[:5]
        for fp in sample:
            with st.expander(f"Região em 0x{fp.offset:06X} ({fp.reason})"):
                if st.button(f"Tentar reverter (RLE/LZSS genérico)", key=f"decomp_{fp.offset}"):
                    with st.spinner("Testando esquemas conhecidos..."):
                        matches = compression.try_all_schemes(info.rom, fp.offset, search_window=1024)
                    consistent = [m for m in matches if m.self_consistent]
                    if consistent:
                        best = consistent[0]
                        st.success(f"✅ {best.scheme} — {best.notes}")
                        st.code(best.decompressed[:300])
                    else:
                        st.error("Nenhum esquema conhecido (RLE simples, LZSS genérico) reverteu "
                                "esta região com segurança. Provavelmente usa compressão "
                                "proprietária — precisa de um perfil de jogo dedicado "
                                "(core/profiles.py) feito via engenharia reversa manual.")
    else:
        st.caption("Nenhuma varredura executada ainda, ou nenhuma região suspeita encontrada.")

    st.header("4️⃣ Detecção de blocos de texto e ponteiros")

    colA, colB, colC = st.columns(3)
    min_len = colA.number_input("Comprimento mínimo do bloco", 2, 100, 4)
    min_conf = colB.slider("Confiança mínima do bloco", 0.0, 1.0, 0.35, 0.05)
    scan_full = colC.checkbox("Escanear ROM inteira (mais lento)", value=True)

    term_input = st.text_input(
        "Byte(s) terminador(es) de string, em hex separados por vírgula",
        value="00",
        help="Padrão é 0x00, mas NEM TODO jogo usa isso — confira se sua tabela .tbl "
             "define algum byte como fim de string antes de confiar no padrão. Se sua "
             "tabela não define terminador (comum em jogos com DTE/MTE), prefira a "
             "segmentação por ponteiros abaixo, que não depende de terminador nenhum."
    )
    try:
        custom_terminators = {int(t.strip(), 16) for t in term_input.split(",") if t.strip()}
    except ValueError:
        st.error("Terminadores inválidos — use hex separado por vírgula, ex: 00,FF")
        custom_terminators = {0x00}

    if st.button("🔍 Escanear ROM (varredura cega por terminador)"):
        tr = st.session_state["table_result"]
        with st.spinner("Procurando blocos de texto..."):
            scan_end = len(info.rom) if scan_full else min(len(info.rom), 0x80000)
            blocks = text_scan.find_text_blocks(
                info.rom, tr.byte_to_char, terminators=custom_terminators,
                min_len=min_len, min_confidence=min_conf, scan_end=scan_end,
            )
            blocks = text_scan.merge_overlapping(blocks)
        st.session_state["text_blocks"] = blocks
        st.session_state["ai_classify_progress"] = 0
        log(f"{len(blocks)} blocos de texto candidatos encontrados (varredura cega).")

        with st.spinner("Procurando tabelas de ponteiros..."):
            cands = pointers.find_pointer_candidates(info.rom, blocks, info.best_mapping.mapping)
        st.session_state["pointer_candidates"] = cands
        log(f"{len(cands)} candidatos de tabela de ponteiros encontrados.")

    blocks = st.session_state["text_blocks"]
    cands = st.session_state["pointer_candidates"]

    if blocks:
        if len(blocks) > 2000 and info.best_mapping and st.session_state.get("pointer_candidates"):
            st.warning(f"⚠️ **{len(blocks)} blocos vieram da varredura cega — isso é normal em "
                      f"jogos com DTE/MTE (cobertura quase total de bytes gera muito falso "
                      f"positivo), mas classificar {len(blocks)} blocos com IA é caro e lento "
                      f"mesmo em lotes.** Se alguma tabela de ponteiros abaixo tiver confiança "
                      f"razoável, clique em **'Usar p/ segmentar'** primeiro — isso costuma "
                      f"reduzir para dezenas de blocos limpos, e SÓ ENTÃO vale a pena rodar a "
                      f"classificação por IA (ou nem precisa, a segmentação por ponteiro já é "
                      f"confiável por construção).")

        st.subheader("🤖 Refinar candidatos com IA (econômico, em lotes)")
        st.caption("Heurística estatística (proporção de vogais, formato de palavra) tem teto — "
                   "ela não sabe inglês, só conta padrão. A IA *lê* cada trecho de verdade e julga "
                   "se faz sentido como texto de jogo ou é ruído. Processa em lotes pequenos e "
                   "retomáveis — nunca tenta tudo de uma vez, o que trava e estoura custo com "
                   "milhares de blocos.")

        ai_context = st.text_input("Contexto do jogo (opcional, ajuda a IA a julgar)",
                                    value=(info.best_mapping.title if info.best_mapping else ""),
                                    key="ai_classify_context")

        colf1, colf2, colf3 = st.columns(3)
        heuristic_floor = colf1.slider(
            "Pré-filtro heurístico (economiza IA)", 0.0, 1.0, 0.30, 0.05,
            help="Blocos com confiança heurística ABAIXO disto são marcados como ruído sem "
                 "gastar nenhuma chamada de IA — normalmente a maioria dos blocos de uma "
                 "varredura cega cai aqui. Suba se quiser ser mais rigoroso (menos chamadas), "
                 "baixe se quiser que a IA reveja mais casos duvidosos."
        )
        batch_size = colf2.number_input("Blocos por lote (chamada de API)", 5, 50, 20)
        chunk_size = colf3.number_input("Blocos a processar neste clique", 20, 2000, 100, step=20)

        eligible_indices = [i for i, b in enumerate(blocks) if b.confidence >= heuristic_floor]
        below_floor_count = len(blocks) - len(eligible_indices)

        # marca de uma vez (sem gastar IA) os blocos abaixo do piso heurístico, se ainda não marcados
        for i, b in enumerate(blocks):
            if b.confidence < heuristic_floor and b.ai_verdict is None:
                b.ai_verdict = "ruido"
                b.ai_confidence = None
                b.ai_reason = "Abaixo do piso heurístico configurado — não enviado à IA (economia)."

        progress_done = st.session_state["ai_classify_progress"]
        total_eligible = len(eligible_indices)
        remaining = max(total_eligible - progress_done, 0)
        est_calls = -(-min(chunk_size, remaining) // batch_size) if remaining else 0

        st.write(f"📊 **{below_floor_count}** blocos descartados de graça pelo piso heurístico "
                f"(0 chamadas). **{total_eligible}** blocos elegíveis para IA. "
                f"Progresso: **{min(progress_done, total_eligible)}/{total_eligible}**.")
        if total_eligible:
            st.progress(min(progress_done / total_eligible, 1.0))
        st.caption(f"Este clique vai processar até {min(chunk_size, remaining)} blocos "
                   f"em ≈{est_calls} chamada(s) de API (lotes de {batch_size}).")

        col_ai1, col_ai2, col_ai3 = st.columns(3)
        run_chunk = col_ai1.button(
            f"🤖 Processar próximo lote (~{min(chunk_size, remaining)} blocos)",
            disabled=not st.session_state["gemini_api_key"] or remaining == 0,
        )
        if col_ai2.button("🔁 Reiniciar progresso de classificação"):
            st.session_state["ai_classify_progress"] = 0
            for b in blocks:
                b.ai_verdict = None
                b.ai_confidence = None
                b.ai_reason = ""
            st.rerun()
        if not st.session_state["gemini_api_key"]:
            col_ai3.warning("Informe a chave do Gemini na barra lateral.")

        if run_chunk:
            to_process_idx = eligible_indices[progress_done:progress_done + chunk_size]
            to_process_blocks = [blocks[i] for i in to_process_idx]
            with st.spinner(f"IA analisando {len(to_process_blocks)} blocos "
                            f"({est_calls} chamada(s))..."):
                try:
                    progress_bar = st.progress(0.0, text="Classificando...")
                    for start in range(0, len(to_process_blocks), batch_size):
                        chunk = to_process_blocks[start:start + batch_size]
                        block_classifier.classify_blocks_with_ai(
                            chunk, st.session_state["gemini_api_key"],
                            st.session_state["gemini_model"], game_context=ai_context,
                            batch_size=batch_size,
                        )
                        progress_bar.progress(min((start + batch_size) / len(to_process_blocks), 1.0))
                    st.session_state["ai_classify_progress"] = progress_done + len(to_process_blocks)
                    st.session_state["text_blocks"] = blocks
                    n_real = sum(1 for b in to_process_blocks if b.ai_verdict == "texto_real")
                    n_ruido = sum(1 for b in to_process_blocks if b.ai_verdict == "ruido")
                    n_falha = sum(1 for b in to_process_blocks if b.ai_verdict is None)
                    log(f"IA classificou lote de {len(to_process_blocks)} blocos: {n_real} texto "
                        f"real, {n_ruido} ruído, {n_falha} falhas.")
                    st.success(f"✅ Lote concluído: {n_real} texto real, {n_ruido} ruído"
                               f"{f', {n_falha} falharam (tente reprocessar depois)' if n_falha else ''}.")
                    st.rerun()
                except Exception as e:  # noqa: BLE001
                    st.error(f"Erro na classificação: {e}")

        if any(b.ai_verdict is not None for b in blocks):
            only_real = st.checkbox(
                "Mostrar só os blocos que a IA (ou o pré-filtro heurístico) NÃO marcou como ruído "
                "(a lista abaixo só exibe esses — os índices continuam intactos "
                "para tradução e aplicação)",
                value=True,
            )
        else:
            only_real = False

        avg_conf = sum(b.confidence for b in blocks) / len(blocks)
        st.success(f"{len(blocks)} blocos encontrados — confiança média {avg_conf:.0%}. "
                    f"{len(cands)} possíveis tabelas de ponteiros associadas.")

        with st.expander(f"Ver candidatos de tabela de ponteiros ({len(cands)})"):
            if not cands:
                st.warning("Nenhuma tabela de ponteiros de 16 bits identificada com segurança. "
                           "Blocos que precisarem crescer além do espaço original NÃO poderão ser "
                           "realocados automaticamente — só editados para caber no espaço original.")
            for i, c in enumerate(cands):
                col1, col2 = st.columns([4, 1])
                col1.write(f"- offset 0x{c.table_offset:06X}, {c.entry_count} entradas, "
                           f"confiança {c.confidence:.0%}, blocos associados: {len(c.matched_block_indices)}")
                if col2.button("Usar p/ segmentar", key=f"reseg_16_{i}"):
                    targets = sorted({blocks[idx].start for idx in c.matched_block_indices
                                       if idx < len(blocks)})
                    with st.spinner("Re-segmentando blocos usando esta tabela de ponteiros..."):
                        new_blocks = text_scan.segment_blocks_by_pointers(
                            info.rom, st.session_state["table_result"].byte_to_char,
                            pointer_targets=targets, terminators=custom_terminators,
                        )
                    st.session_state["text_blocks"] = new_blocks
                    st.session_state["ai_classify_progress"] = 0
                    log(f"Re-segmentado por ponteiros: {len(new_blocks)} blocos "
                        f"(a partir da tabela em 0x{c.table_offset:06X}).")
                    st.rerun()

            st.info("💡 **Se os textos acima aparecem 'colados' ou com pedaços de mais de um "
                    "diálogo misturados**, isso geralmente significa que o terminador configurado "
                    "está errado para este jogo (comum em jogos com tabela DTE/MTE, que cobre quase "
                    "todo o espaço de bytes). Clique em **'Usar p/ segmentar'** numa tabela de "
                    "ponteiros acima — isso re-segmenta os blocos usando os próprios ponteiros como "
                    "limite de cada string, sem depender de adivinhar o terminador.")

            if st.button("🔎 Também buscar ponteiros de 24 bits e indiretos"):
                with st.spinner("Buscando ponteiros de 24 bits..."):
                    cands24 = pointers.find_24bit_pointer_candidates(info.rom, blocks, info.best_mapping.mapping)
                with st.spinner("Buscando ponteiros indiretos (nível 2)..."):
                    cands_indirect = pointers.find_indirect_pointer_candidates(
                        info.rom, cands24 or cands, info.best_mapping.mapping)
                st.session_state["pointer_candidates_24"] = cands24
                st.session_state["pointer_candidates_indirect"] = cands_indirect
                log(f"{len(cands24)} candidatos de 24 bits, {len(cands_indirect)} indiretos encontrados.")

            cands24 = st.session_state.get("pointer_candidates_24", [])
            cands_indirect = st.session_state.get("pointer_candidates_indirect", [])
            if cands24:
                st.write("**Ponteiros de 24 bits (banco explícito) — mais específicos, geralmente "
                         "mais confiáveis que os de 16 bits:**")
                for i, c in enumerate(cands24):
                    col1, col2 = st.columns([4, 1])
                    col1.write(f"- offset 0x{c.table_offset:06X}, {c.entry_count} entradas, "
                               f"confiança {c.confidence:.0%}")
                    if col2.button("Usar p/ segmentar", key=f"reseg_24_{i}"):
                        targets = sorted({blocks[idx].start for idx in c.matched_block_indices
                                           if idx < len(blocks)})
                        new_blocks = text_scan.segment_blocks_by_pointers(
                            info.rom, st.session_state["table_result"].byte_to_char,
                            pointer_targets=targets, terminators=custom_terminators,
                        )
                        st.session_state["text_blocks"] = new_blocks
                        st.session_state["ai_classify_progress"] = 0
                        log(f"Re-segmentado por ponteiros de 24 bits: {len(new_blocks)} blocos.")
                        st.rerun()
            if cands_indirect:
                st.write("**Ponteiros indiretos (tabela aponta para outra tabela de ponteiros):**")
                for c in cands_indirect[:10]:
                    st.write(f"- offset 0x{c.table_offset:06X}, confiança {c.confidence:.0%} "
                             f"(indireção reduz a certeza — confirme manualmente)")

        st.subheader("Blocos detectados")
        low_conf_count = sum(1 for b in blocks if b.confidence < CONFIDENCE_WARN)
        if low_conf_count:
            st.warning(f"{low_conf_count} bloco(s) com confiança baixa (<{CONFIDENCE_WARN:.0%}) — "
                       "revise com atenção antes de traduzir.")

        preview_rows = []
        for i, b in enumerate(blocks[:500]):
            if only_real and b.ai_verdict == "ruido":
                continue
            preview_rows.append({
                "idx": i, "offset": f"0x{b.start:06X}", "tamanho": len(b.raw),
                "confiança": f"{b.confidence:.0%}", "categoria": b.category_hint,
                "IA": b.ai_verdict or "não avaliado",
                "conf. IA": f"{b.ai_confidence:.0%}" if b.ai_confidence is not None else "—",
                "texto": b.text[:120],
            })
        st.dataframe(preview_rows, use_container_width=True, height=350)
        if len(blocks) > 500:
            st.caption(f"Mostrando os primeiros 500 de {len(blocks)} blocos "
                       f"(idx corresponde à posição real na lista — usado nas etapas seguintes).")
    else:
        st.info("Clique em 'Escanear ROM' para localizar os textos.")

# --------------------------------------------------------------------------
# ETAPA 4 — seleção, tradução e revisão manual
# --------------------------------------------------------------------------
if st.session_state["text_blocks"]:
    st.header("5️⃣ Tradução (Gemini) e revisão manual")

    blocks = st.session_state["text_blocks"]
    min_select_conf = st.slider("Traduzir apenas blocos com confiança mínima de", 0.0, 1.0, CONFIDENCE_SAFE, 0.05,
                                 key="select_conf")
    exclude_ai_noise = st.checkbox(
        "Excluir automaticamente blocos que a IA classificou como ruído (recomendado)",
        value=True,
    )
    selected_indices = [
        i for i, b in enumerate(blocks)
        if b.confidence >= min_select_conf and not (exclude_ai_noise and b.ai_verdict == "ruido")
    ]
    st.write(f"**{len(selected_indices)}** blocos selecionados para tradução automática "
             f"(de {len(blocks)} candidatos totais).")

    game_context = st.text_input("Contexto do jogo (opcional, ajuda a IA)",
                                  placeholder="Ex.: RPG de fantasia medieval, tom sério...")

    col_t1, col_t2 = st.columns([1, 3])
    with col_t1:
        run_translation = st.button("🌐 Traduzir com Gemini", type="primary",
                                     disabled=not st.session_state["gemini_api_key"])
    if not st.session_state["gemini_api_key"]:
        col_t2.warning("Informe a chave de API do Gemini na barra lateral para habilitar a tradução.")

    if run_translation:
        try:
            gt = translator.GeminiTranslator(
                st.session_state["gemini_api_key"], st.session_state["gemini_model"]
            )
            texts = [blocks[i].text for i in selected_indices]
            hints = [blocks[i].category_hint for i in selected_indices]
            progress = st.progress(0.0, text="Traduzindo...")
            batch_size = 20
            all_translated = []
            for start in range(0, len(texts), batch_size):
                chunk = texts[start:start + batch_size]
                chunk_hints = hints[start:start + batch_size]
                translated = gt.translate_batch(
                    chunk, st.session_state["glossary"], chunk_hints, game_context, batch_size=batch_size
                )
                all_translated.extend(translated)
                progress.progress(min((start + batch_size) / len(texts), 1.0),
                                   text=f"Traduzido {min(start + batch_size, len(texts))}/{len(texts)}")
            for idx, translated_text in zip(selected_indices, all_translated):
                st.session_state["translations"][idx] = translated_text
            log(f"{len(all_translated)} blocos traduzidos com sucesso via {st.session_state['gemini_model']}.")
            st.success(f"{len(all_translated)} blocos traduzidos.")
        except Exception as e:  # noqa: BLE001
            log(f"ERRO na tradução: {e}")
            st.error(f"Erro ao traduzir: {e}")

    if st.session_state["translations"]:
        st.subheader("Revisão manual")
        st.caption("Edite livremente. Tokens `{XX}` são códigos de controle do jogo — não remova nem invente novos.")

        review_indices = sorted(st.session_state["translations"].keys())
        for i in review_indices[:80]:
            b = blocks[i]
            tr_len_bytes = None
            table_result = st.session_state["table_result"]
            current_translation = st.session_state["translations"][i]

            with st.container(border=True):
                c1, c2 = st.columns(2)
                c1.markdown(f"**Original** (offset 0x{b.start:06X}, {len(b.raw)} bytes, categoria: {b.category_hint})")
                c1.code(b.text)
                new_text = c2.text_area(f"Tradução #{i}", value=current_translation, key=f"trans_{i}",
                                         label_visibility="collapsed")
                st.session_state["translations"][i] = new_text

                encoded = tbl.encode_text(new_text, table_result.char_to_byte,
                                           terminator_byte=None)
                if encoded is None:
                    st.error("⚠️ Esta tradução contém caractere(s) que não existem na tabela do jogo "
                             "(sem acentos suportados?). Ajuste o texto ou adicione o caractere na tabela.")
                else:
                    fits = len(encoded) <= (len(b.raw) - (1 if b.terminated_cleanly else 0))
                    if fits:
                        st.caption(f"✅ Cabe no espaço original ({len(encoded)}/{len(b.raw)} bytes).")
                    else:
                        st.warning(f"📏 Texto traduzido ({len(encoded)} bytes) é maior que o espaço original "
                                   f"({len(b.raw)} bytes). Será necessário realocar este bloco (se houver "
                                   f"ponteiro confiável associado) ou reduzir o texto.")

        if len(review_indices) > 80:
            st.info(f"Mostrando os primeiros 80 de {len(review_indices)} blocos traduzidos "
                    "(edite em lotes para melhor performance).")

# --------------------------------------------------------------------------
# ETAPA 5 — aplicação, validação e geração do IPS
# --------------------------------------------------------------------------
if st.session_state["translations"]:
    st.header("6️⃣ Aplicar tradução, validar e gerar patch IPS")

    header_option = st.radio(
        "O patch IPS deve ser gerado para aplicação em uma ROM:",
        ["Sem header (.sfc padrão, mais comum)", "Com header de 512 bytes (.smc)"],
        horizontal=False,
    )
    offset_shift = 512 if header_option.startswith("Com header") else 0

    if st.button("🛠️ Aplicar tradução e gerar patch IPS", type="primary"):
        blocks = st.session_state["text_blocks"]
        table_result = st.session_state["table_result"]
        rom_buffer = bytearray(info.rom)
        used_free_ranges: list = []
        free_regions = None
        risks_apply = []
        applied = 0
        skipped = 0

        cands = st.session_state["pointer_candidates"]
        pointer_lookup = {}
        for c in cands:
            for order, block_idx in enumerate(c.matched_block_indices):
                pointer_lookup[block_idx] = (c.table_offset, order)

        for idx, new_text in st.session_state["translations"].items():
            b = blocks[idx]
            term = 1 if b.terminated_cleanly else 0
            terminator_byte = b.raw[-1] if term else None
            encoded = tbl.encode_text(new_text, table_result.char_to_byte, terminator_byte)
            if encoded is None:
                risks_apply.append(f"Bloco #{idx} (0x{b.start:06X}): caractere fora da tabela — NÃO aplicado.")
                skipped += 1
                continue

            available = len(b.raw)
            if len(encoded) <= available:
                padded = encoded + b.raw[len(encoded):] if len(encoded) < available else encoded
                # preenche sobra com o próprio terminador/padding original para não deixar lixo
                if len(encoded) < available:
                    pad_byte = terminator_byte if terminator_byte is not None else b.raw[-1]
                    padded = encoded + bytes([pad_byte]) * (available - len(encoded))
                rom_buffer[b.start:b.start + available] = padded[:available]
                applied += 1
            else:
                if free_regions is None:
                    free_regions = relocation.find_free_space(info.rom)
                ptr_info = pointer_lookup.get(idx)
                if ptr_info is None:
                    risks_apply.append(
                        f"Bloco #{idx} (0x{b.start:06X}): tradução maior que o espaço original e SEM "
                        f"ponteiro confiável associado — NÃO aplicado. Edite o texto para caber."
                    )
                    skipped += 1
                    continue
                table_offset, entry_index = ptr_info
                result = relocation.try_relocate_block(
                    rom_buffer, encoded, free_regions, used_free_ranges,
                    table_offset, entry_index, info.best_mapping.mapping,
                )
                if result.success:
                    applied += 1
                    log(f"Bloco #{idx} realocado: {result.message}")
                else:
                    risks_apply.append(f"Bloco #{idx} (0x{b.start:06X}): {result.message} — NÃO aplicado.")
                    skipped += 1

        st.session_state["modified_rom"] = bytes(rom_buffer)
        log(f"Aplicação concluída: {applied} blocos aplicados, {skipped} ignorados por segurança.")

        if risks_apply:
            st.warning("**Blocos NÃO aplicados por segurança:**\n\n" + "\n".join(f"- {r}" for r in risks_apply))
        st.success(f"{applied} blocos aplicados na ROM traduzida (em memória). {skipped} ignorados por segurança.")

        original_for_diff = info.rom
        modified = st.session_state["modified_rom"]
        try:
            patch = ips_patch.create_ips(original_for_diff, modified, offset_shift=offset_shift)
        except Exception as e:  # noqa: BLE001
            st.error(f"Erro ao gerar patch IPS: {e}")
            patch = None

        if patch is not None:
            base_for_validation = (
                (st.session_state["rom_info"].copier_header_bytes + original_for_diff)
                if offset_shift == 512 else original_for_diff
            )
            target_for_validation = (
                (st.session_state["rom_info"].copier_header_bytes + modified)
                if offset_shift == 512 else modified
            )
            validation = ips_patch.validate_round_trip(base_for_validation, target_for_validation, patch)
            st.session_state["validation"] = validation
            st.session_state["ips_bytes"] = patch if validation.ok else None
            log(f"Validação do IPS: ok={validation.ok} — {validation.message}")

    validation = st.session_state.get("validation")
    if validation:
        if validation.ok:
            st.success(f"✅ {validation.message} ({validation.record_count} registros, "
                       f"{validation.total_bytes_changed} bytes alterados no total)")
            st.download_button(
                "⬇️ Baixar patch .ips",
                data=st.session_state["ips_bytes"],
                file_name=(st.session_state["filename"] or "rom").rsplit(".", 1)[0] + "_ptbr.ips",
                mime="application/octet-stream",
            )
            st.caption(f"⚠️ Este patch foi gerado para ser aplicado em uma ROM "
                       f"{'COM' if offset_shift == 512 else 'SEM'} header de 512 bytes, "
                       f"idêntica em conteúdo à ROM original enviada (mesmo hash de dados).")
        else:
            st.error(f"❌ Validação falhou: {validation.message}. O patch NÃO foi liberado para download "
                     f"por segurança — nenhuma alteração arriscada é entregue ao usuário.")

st.divider()
with st.expander("ℹ️ Limitações honestas desta ferramenta"):
    st.markdown("""
- **Compressão de texto** (LZ, RLE proprietário, dicionários de tokens) não é detectada nem
  descomprimida automaticamente. Jogos que usam texto comprimido precisam de um
  perfil de jogo dedicado (`core/profiles.py`) feito via engenharia reversa manual.
- **Ponteiros de 24 bits ou indiretos** (tabela de tabelas) não são recalculados automaticamente.
- A **detecção de tabela de caracteres** sem nenhuma pista do usuário é, na melhor das hipóteses,
  uma hipótese estatística — sempre revise a confiança reportada antes de confiar nos resultados.
- Esta ferramenta **nunca aplica** uma alteração cuja segurança não possa ser validada por
  round-trip (ROM original + IPS = ROM traduzida, byte a byte).
""")
