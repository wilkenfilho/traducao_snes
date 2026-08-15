"""
core.translator
----------------
Integração com a API do Gemini (google-generativeai) para tradução
contextual PT-BR, com:

- proteção de tokens de controle ({XX}, {END}, quebras de linha etc.) para
  que o modelo NUNCA os altere ou remova;
- glossário de consistência (nomes próprios, termos do jogo) mantido ao
  longo de toda a sessão e reforçado a cada chamada;
- tradução em lote com contexto (categoria do texto: diálogo, menu, item,
  etc.) para ajudar o modelo a manter o tom correto;
- saída estritamente estruturada (JSON) para permitir parsing seguro.
"""

from __future__ import annotations
import json
import re
import time
from dataclasses import dataclass, field

CONTROL_TOKEN_RE = re.compile(r"\{[A-Za-z0-9_]+\}")

SYSTEM_PROMPT = """Você é um tradutor profissional especializado em localização de \
jogos clássicos de Super Nintendo / Super Famicom para português do Brasil.

Regras OBRIGATÓRIAS:
1. Preserve EXATAMENTE todos os tokens no formato {XX} ou {NOME} (códigos de \
controle do jogo, como quebras de linha, cores, nomes de variáveis, pausas). \
Nunca remova, traduza ou altere esses tokens; apenas reposicione se a ordem \
da frase em português exigir.
2. Mantenha nomes próprios de personagens e lugares, a menos que o glossário \
fornecido indique uma tradução oficial para aquele termo.
3. Use um tom natural em português do Brasil, adequado ao gênero do jogo \
(RPG, ação, etc.), respeitando o contexto de cada trecho (diálogo, menu, \
item, mensagem de sistema).
4. Seja o mais conciso possível sem perder o sentido — o espaço na ROM \
original é limitado.
5. Responda SOMENTE em JSON válido, no formato:
   {"translations": ["texto 1 traduzido", "texto 2 traduzido", ...]}
   na MESMA ORDEM e MESMA QUANTIDADE de itens recebidos. Não adicione texto \
fora do JSON.
"""


@dataclass
class TranslationGlossary:
    terms: dict = field(default_factory=dict)  # original -> tradução fixada

    def as_prompt_block(self) -> str:
        if not self.terms:
            return "(nenhum termo fixado ainda)"
        return "\n".join(f"- {k} => {v}" for k, v in self.terms.items())


class GeminiTranslator:
    def __init__(self, api_key: str, model_name: str = "gemini-flash-latest"):
        if not api_key:
            raise ValueError("Chave de API do Gemini não fornecida.")
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        self._genai = genai
        self.model_name = model_name
        self.model = genai.GenerativeModel(model_name)

    def translate_batch(
        self,
        texts: list[str],
        glossary: TranslationGlossary,
        category_hints: list[str] | None = None,
        game_context: str = "",
        max_retries: int = 3,
        batch_size: int = 20,
    ) -> list[str]:
        results: list[str] = []
        category_hints = category_hints or ["" for _ in texts]

        for start in range(0, len(texts), batch_size):
            chunk = texts[start:start + batch_size]
            hints = category_hints[start:start + batch_size]
            translated_chunk = self._translate_chunk(chunk, hints, glossary, game_context, max_retries)
            results.extend(translated_chunk)
        return results

    def _translate_chunk(self, chunk, hints, glossary, game_context, max_retries) -> list[str]:
        payload_items = [{"index": i, "categoria": h, "texto": t} for i, (t, h) in enumerate(zip(chunk, hints))]
        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Contexto do jogo (se disponível): {game_context or 'não informado'}\n\n"
            f"Glossário fixado até agora (respeite rigorosamente):\n{glossary.as_prompt_block()}\n\n"
            f"Traduza os seguintes {len(chunk)} textos, na ordem, para português do Brasil:\n"
            f"{json.dumps(payload_items, ensure_ascii=False, indent=2)}"
        )

        last_error = None
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(
                    prompt,
                    generation_config={"temperature": 0.3, "response_mime_type": "application/json"},
                )
                data = json.loads(response.text)
                translations = data["translations"]
                if len(translations) != len(chunk):
                    raise ValueError(
                        f"Modelo retornou {len(translations)} itens, esperado {len(chunk)}."
                    )
                self._validate_control_tokens(chunk, translations)
                return translations
            except Exception as e:  # noqa: BLE001
                last_error = e
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"Falha ao traduzir lote após {max_retries} tentativas: {last_error}")

    @staticmethod
    def _validate_control_tokens(originals: list[str], translations: list[str]) -> None:
        """Garante que nenhum token de controle {XX} foi perdido ou inventado."""
        for orig, trans in zip(originals, translations):
            orig_tokens = sorted(CONTROL_TOKEN_RE.findall(orig))
            trans_tokens = sorted(CONTROL_TOKEN_RE.findall(trans))
            if orig_tokens != trans_tokens:
                raise ValueError(
                    f"Divergência de tokens de controle. Original: {orig_tokens} "
                    f"Traduzido: {trans_tokens}. Texto original: {orig!r}"
                )

    def update_glossary_from_names(self, glossary: TranslationGlossary, candidate_names: list[str]) -> None:
        """Placeholder para reforço futuro de glossário via IA (mantém API extensível)."""
        return None
