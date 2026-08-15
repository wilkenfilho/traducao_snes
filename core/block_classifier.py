"""
core.block_classifier
-----------------------
Heurísticas estatísticas (proporção de vogais, formato de "palavra", etc.)
têm um teto: elas não sabem inglês, só contam padrões. Quando a tabela de
caracteres é DTE/MTE (cobre quase todo o espaço de bytes) ou a segmentação
por terminador é imperfeita, blocos que são estatisticamente "parecidos com
texto" mas não fazem sentido nenhum passam pela heurística.

Este módulo manda os blocos candidatos para o Gemini e pede um julgamento
real de linguagem: "isto parece texto de jogo de verdade (mesmo fragmentado)
ou é ruído/dado binário mal decodificado?". Isso é MUITO melhor que
heurística estatística nisso especificamente, porque o modelo realmente
"lê" o trecho em vez de só medir proporções.

Importante: isto FILTRA e PRIORIZA candidatos, não decide sozinho o que vai
pro ROM final — a tradução e aplicação continuam exigindo os mesmos
critérios de segurança (encaixe de bytes, ponteiro confiável, validação de
round-trip) de sempre. O veredito da IA é só mais um sinal de confiança,
sempre visível e revisável na interface, nunca oculto.
"""

from __future__ import annotations
import json
import time

CLASSIFY_SYSTEM_PROMPT = """Você está analisando trechos extraídos automaticamente de uma ROM \
de Super Nintendo por um scanner heurístico de texto. Cada trecho foi decodificado usando a \
tabela de caracteres do jogo, que pode incluir DTE/MTE (um único byte representa uma palavra \
ou fragmento inteiro, ex.: "you", "the", "ing") e tokens de controle entre chaves {{XX}} (byte \
não mapeado pela tabela) ou colchetes [CMD_XX] (comando do jogo, ex.: quebra de linha, cor, \
pausa). Esses tokens são NORMAIS dentro de texto real e não devem, por si só, ser tratados \
como sinal de ruído.

Para cada trecho, julgue se ele é genuinamente texto do jogo (diálogo, menu, item, mensagem \
de sistema, nome — mesmo que apareça cortado no início ou no fim, isso é esperado) ou se é \
ruído: uma sequência de fragmentos de palavras sem coerência linguística real, típica de \
dado binário não-textual (tabela de ponteiros, gráficos, código) que por coincidência também \
decodifica em "algo parecido com palavras" através da mesma tabela.

Sinais de RUÍDO: fragmentos de palavra que não formam nenhuma frase ou expressão plausível em \
inglês mesmo lendo com tolerância a cortes; mistura de fragmentos de palavras completamente \
não relacionados entre si sem nexo (ex.: "again" seguido de pontuação estranha seguido de mais \
fragmentos desconexos); presença de MUITOS tokens {{XX}} intercalados de forma que quebra \
qualquer leitura corrida.

Sinais de TEXTO REAL: mesmo fragmentado, dá pra "ouvir" uma frase, expressão idiomática, nome \
de item/habilidade, ou instrução de menu plausível em inglês.

Responda SOMENTE em JSON, no formato exato:
{{"results": [{{"index": 0, "is_real_text": true, "confidence": 0.85, "reason": "breve motivo"}}, ...]}}
Mesma ordem e mesma quantidade de itens recebidos.
"""


def classify_blocks_with_ai(
    blocks: list,
    api_key: str,
    model_name: str = "gemini-2.0-flash",
    game_context: str = "",
    batch_size: int = 30,
    max_retries: int = 3,
) -> list:
    """
    Classifica cada bloco em `blocks` (lista de TextBlock) como texto real
    ou ruído, usando o Gemini. Retorna a MESMA lista de blocos com os campos
    ai_verdict / ai_confidence / ai_reason preenchidos (não filtra nada —
    quem decide o que mostrar/usar é a camada de UI).
    """
    if not api_key:
        raise ValueError("Chave de API do Gemini não fornecida.")
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)

    for start in range(0, len(blocks), batch_size):
        chunk = blocks[start:start + batch_size]
        payload = [{"index": i, "texto": b.text[:300]} for i, b in enumerate(chunk)]
        prompt = (
            f"{CLASSIFY_SYSTEM_PROMPT}\n\n"
            f"Contexto do jogo (se disponível): {game_context or 'não informado'}\n\n"
            f"Trechos a avaliar:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
        )

        last_error = None
        for attempt in range(max_retries):
            try:
                response = model.generate_content(
                    prompt,
                    generation_config={"temperature": 0.1, "response_mime_type": "application/json"},
                )
                data = json.loads(response.text)
                results = data["results"]
                if len(results) != len(chunk):
                    raise ValueError(f"Modelo retornou {len(results)} itens, esperado {len(chunk)}.")
                for r in results:
                    idx = r["index"]
                    blk = chunk[idx]
                    blk.ai_verdict = "texto_real" if r.get("is_real_text") else "ruido"
                    blk.ai_confidence = float(r.get("confidence", 0.5))
                    blk.ai_reason = r.get("reason", "")
                break
            except Exception as e:  # noqa: BLE001
                last_error = e
                time.sleep(1.2 * (attempt + 1))
        else:
            # se todas as tentativas falharem para este lote, marca como não avaliado
            # em vez de derrubar o processo inteiro — blocos já classificados em
            # lotes anteriores permanecem válidos.
            for blk in chunk:
                blk.ai_verdict = None
                blk.ai_reason = f"Falha ao classificar via IA: {last_error}"

    return blocks
