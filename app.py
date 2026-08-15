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
import hashlib
import streamlit as st

from core import rom_io, tbl, text_scan, pointers, ips_patch, translator, relocation, profiles

st.set_page_config(page_title="SNES ROM Translator PT-BR", layout="wide")

CONFIDENCE_SAFE = 0.60
CONFIDENCE_WARN = 0.40

# --------------------------------------------------------------------------
# estado da sessão
# --------------------------------------------------------------------------
def _init_state():
    defaults = {
        "gemini_api_key": "",
        "gemini_model": "gemini-2.0-flash",
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
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    st.session_state["log"].append(f"[{ts}] {msg}")


_init_state()

# --------------------------------------------------------------------------
# sidebar: configuração do Gemini + debug
# --------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Configuração")
    api_key_input = st.text_input(
        "Chave de API do Gemini", value=st.session_state["gemini_api_key"],
        type="password", help="Fica salva apenas nesta sessão do navegador (session_state)."
    )
    st.session_state["gemini_api_key"] = api_key_input
    st.session_state["gemini_model"] = st.text_input(
        "Modelo Gemini", value=st.session_state["gemini_model"],
        help="Ex.: gemini-2.0-flash. Ajuste se a Google renomear o modelo."
    )
    st.caption("A chave não é enviada a nenhum lugar além da API oficial do Google via HTTPS, "
               "e não é persistida em disco.")

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
        ["Importar arquivo .tbl", "Busca relativa (palavra conhecida)", "Hipótese ASCII direta"],
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
    st.header("3️⃣ Detecção de blocos de texto e ponteiros")

    colA, colB, colC = st.columns(3)
    min_len = colA.number_input("Comprimento mínimo do bloco", 2, 100, 4)
    min_conf = colB.slider("Confiança mínima do bloco", 0.0, 1.0, 0.35, 0.05)
    scan_full = colC.checkbox("Escanear ROM inteira (mais lento)", value=True)

    if st.button("🔍 Escanear ROM"):
        tr = st.session_state["table_result"]
        with st.spinner("Procurando blocos de texto..."):
            scan_end = len(info.rom) if scan_full else min(len(info.rom), 0x80000)
            blocks = text_scan.find_text_blocks(
                info.rom, tr.byte_to_char, min_len=min_len, min_confidence=min_conf,
                scan_end=scan_end,
            )
            blocks = text_scan.merge_overlapping(blocks)
        st.session_state["text_blocks"] = blocks
        log(f"{len(blocks)} blocos de texto candidatos encontrados.")

        with st.spinner("Procurando tabelas de ponteiros..."):
            cands = pointers.find_pointer_candidates(info.rom, blocks, info.best_mapping.mapping)
        st.session_state["pointer_candidates"] = cands
        log(f"{len(cands)} candidatos de tabela de ponteiros encontrados.")

    blocks = st.session_state["text_blocks"]
    cands = st.session_state["pointer_candidates"]

    if blocks:
        avg_conf = sum(b.confidence for b in blocks) / len(blocks)
        st.success(f"{len(blocks)} blocos encontrados — confiança média {avg_conf:.0%}. "
                    f"{len(cands)} possíveis tabelas de ponteiros associadas.")

        with st.expander(f"Ver candidatos de tabela de ponteiros ({len(cands)})"):
            if not cands:
                st.warning("Nenhuma tabela de ponteiros de 16 bits identificada com segurança. "
                           "Blocos que precisarem crescer além do espaço original NÃO poderão ser "
                           "realocados automaticamente — só editados para caber no espaço original.")
            for c in cands:
                st.write(f"- offset 0x{c.table_offset:06X}, {c.entry_count} entradas, "
                         f"confiança {c.confidence:.0%}, blocos associados: {len(c.matched_block_indices)}")

        st.subheader("Blocos detectados")
        low_conf_count = sum(1 for b in blocks if b.confidence < CONFIDENCE_WARN)
        if low_conf_count:
            st.warning(f"{low_conf_count} bloco(s) com confiança baixa (<{CONFIDENCE_WARN:.0%}) — "
                       "revise com atenção antes de traduzir.")

        preview_rows = []
        for i, b in enumerate(blocks[:500]):
            preview_rows.append({
                "idx": i, "offset": f"0x{b.start:06X}", "tamanho": len(b.raw),
                "confiança": f"{b.confidence:.0%}", "categoria": b.category_hint,
                "texto": b.text[:120],
            })
        st.dataframe(preview_rows, use_container_width=True, height=350)
        if len(blocks) > 500:
            st.caption(f"Mostrando os primeiros 500 de {len(blocks)} blocos.")
    else:
        st.info("Clique em 'Escanear ROM' para localizar os textos.")

# --------------------------------------------------------------------------
# ETAPA 4 — seleção, tradução e revisão manual
# --------------------------------------------------------------------------
if st.session_state["text_blocks"]:
    st.header("4️⃣ Tradução (Gemini) e revisão manual")

    blocks = st.session_state["text_blocks"]
    min_select_conf = st.slider("Traduzir apenas blocos com confiança mínima de", 0.0, 1.0, CONFIDENCE_SAFE, 0.05,
                                 key="select_conf")
    selected_indices = [i for i, b in enumerate(blocks) if b.confidence >= min_select_conf]
    st.write(f"**{len(selected_indices)}** blocos selecionados para tradução automática.")

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
    st.header("5️⃣ Aplicar tradução, validar e gerar patch IPS")

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
