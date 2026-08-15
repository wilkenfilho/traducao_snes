# Tradutor de ROMs SNES/Super Famicom → PT-BR (Streamlit)

Ferramenta para apoiar a tradução fanmade de ROMs SNES/Super Famicom para
português do Brasil, com diagnóstico técnico automático, detecção
heurística de texto/tabela de caracteres/ponteiros, tradução assistida por
IA (Gemini Flash) e geração de patch **.ips** validado por round-trip.

## Como rodar

```bash
pip install -r requirements.txt
streamlit run app.py
```

Você vai precisar de uma **chave de API do Google Gemini** (informada na
barra lateral do app, fica salva só na sessão do navegador).

## Fluxo do app

1. **Upload + diagnóstico**: envia `.sfc`/`.smc`, detecta header de
   copiadora (512 bytes), calcula checksum interno, detecta mapeamento
   (LoROM/HiROM/ExHiROM) e mostra riscos técnicos.
2. **Tabela de caracteres (TBL)**: importe um `.tbl` pronto (formato padrão
   `XX=c` usado pela comunidade), use **busca relativa** (técnica clássica:
   informe uma palavra que você sabe que existe no jogo) ou teste a
   hipótese de ASCII direto — cada método reporta confiança explícita.
3. **Detecção de texto e ponteiros**: escaneia a ROM em busca de blocos de
   texto plausíveis e tabelas de ponteiros de 16 bits associadas.
4. **Tradução + revisão manual**: traduz em lote via Gemini (com glossário
   de consistência e proteção de tokens de controle `{XX}`), com revisão e
   edição manual de cada trecho antes de aplicar.
5. **Aplicação + patch IPS**: aplica a tradução em uma cópia da ROM em
   memória, realoca blocos que não couberem (somente quando há ponteiro
   confiável), gera o `.ips` e **valida por round-trip** (ROM original +
   IPS deve reconstruir exatamente a ROM traduzida) antes de liberar o
   download.

## Arquitetura (módulos em `core/`)

- `rom_io.py` — header, checksum, mapeamento LoROM/HiROM/ExHiROM, conversão
  de endereços SNES↔offset físico.
- `tbl.py` — parsing/geração de `.tbl`, hipótese ASCII, busca relativa.
- `text_scan.py` — varredura heurística de blocos de texto com confiança.
- `pointers.py` — detecção heurística de tabelas de ponteiros de 16 bits.
- `relocation.py` — busca de espaço livre e realocação segura de blocos.
- `ips_patch.py` — criação/aplicação/validação de patches IPS.
- `translator.py` — integração com Gemini (tradução em lote, glossário,
  proteção de tokens de controle).
- `profiles.py` — sistema de extensão para adicionar suporte dedicado a
  jogos específicos (compressão, ponteiros de 24 bits, tabela fixa etc.)
  sem alterar o pipeline genérico.

## Limitações honestas (leia antes de confiar cegamente no resultado)

Isto **não é mágica**: descobrir 100% da estrutura interna de qualquer jogo
SNES sem nenhuma pista prévia é um problema aberto até para ferramentas
comerciais de ROM hacking (Cartographer, Thingy32, Atlas etc.), que também
dependem de trabalho manual de engenharia reversa por jogo.

O que este app faz **de forma automática e confiável**:
- Header, checksum e mapeamento (determinístico, baseado em especificação
  pública do SNES).
- Geração e validação de IPS (formato bem definido, testado por round-trip).
- Tradução de texto já corretamente identificado, com Gemini.

O que exige **revisão humana ou um perfil de jogo dedicado**:
- Tabela de caracteres customizada sem nenhuma pista (a busca relativa e a
  hipótese ASCII são heurísticas, não certezas).
- Texto comprimido (LZ, RLE proprietário, dicionário de tokens).
- Ponteiros de 24 bits, indiretos ou calculados.

Nesses casos o app **recusa aplicar alterações arriscadas** e informa
exatamente o que não pôde ser identificado, em vez de inventar um
resultado.
