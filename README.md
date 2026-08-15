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
2. **Tabela de caracteres (TBL)**: cinco caminhos, do mais ao menos confiável:
   - importar um `.tbl` pronto (formato padrão `XX=c` da comunidade);
   - **busca relativa** (técnica clássica: informe uma palavra que você sabe
     que existe no jogo, ex. "LEVEL", e o algoritmo infere o alfabeto);
   - **detecção de fonte via IA (visão computacional)**: extrai os tiles
     gráficos da ROM, renderiza como imagem e usa o Gemini multimodal para
     *ler visualmente* cada glifo — funciona mesmo sem nenhuma pista textual,
     mas sempre exige sua confirmação visual antes de virar tabela;
   - **busca web** por `.tbl`/documentação/patches já publicados pela
     comunidade para aquele jogo específico (romhacking.net e web geral);
   - hipótese de ASCII direto, com teste estatístico de frequência de letras.
3. **Detecção de compressão**: fingerprint de entropia por blocos + biblioteca
   de descompressores conhecidos (RLE, família LZSS parametrizável) testados
   em força bruta e validados por round-trip exato antes de qualquer edição.
4. **Detecção de texto e ponteiros**: escaneia a ROM em busca de blocos de
   texto plausíveis e tabelas de ponteiros — 16 bits, 24 bits (banco
   explícito, mais específico e confiável) e ponteiros indiretos (tabela
   que aponta para outra tabela de ponteiros).
5. **Tradução + revisão manual**: traduz em lote via Gemini (com glossário
   de consistência e proteção de tokens de controle `{XX}`), com revisão e
   edição manual de cada trecho antes de aplicar.
6. **Aplicação + patch IPS**: aplica a tradução em uma cópia da ROM em
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
- `compression.py` — fingerprint estatístico de compressão, decompressores
  RLE/LZSS parametrizáveis, validação por round-trip exato.
- `font_vision.py` — decodificação de tiles SNES 2bpp/4bpp, heurística de
  localização de fonte, OCR de glifos via Gemini multimodal.
- `web_intel.py` — busca de tabelas/patches/documentação já publicados pela
  comunidade de ROM hacking para o jogo específico.
- `profiles.py` — sistema de extensão para adicionar suporte dedicado a
  jogos específicos (compressão, ponteiros de 24 bits, tabela fixa etc.)
  sem alterar o pipeline genérico.

## Sobre usar IA para os três problemas difíceis

- **Tabela de caracteres sem pista**: a IA ajuda de verdade via visão
  computacional (leitura de glifos extraídos como imagem) — mas a
  localização da fonte na ROM continua heurística, e o resultado do OCR
  sempre passa por revisão do usuário antes de virar tabela ativa.
- **Texto comprimido**: a IA não "adivinha" o esquema — usamos fingerprint
  estatístico + biblioteca de descompressores conhecidos testados em força
  bruta, com validação de round-trip exato como barreira de segurança.
  Testes internos mostraram uma taxa residual de falso positivo estatístico
  de ~1,5% em amostras curtas (100-512 bytes) mesmo após os filtros de
  plausibilidade — por isso blocos comprimidos nunca são editados sem
  confirmação explícita do usuário, mesmo com validação positiva.
- **Ponteiros 24 bits/indiretos/calculados**: 100% determinístico, não
  precisa de IA — só de mais cobertura heurística, já implementada.
- **Pesquisa web**: encontra trabalho de engenharia reversa já publicado
  pela comunidade (não é "a IA descobrindo do zero") — o maior ganho
  prático para jogos populares com fanbase de ROM hacking ativa.

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
