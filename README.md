# L1ght Recon

**Scanning & Enumeration** para laboratórios e CTFs.

## Instalação

```bash
git clone https://github.com/LightReven/l1ght_recon.git && cd l1ght_recon && sudo bash setup_tools.sh
```

> **Importante:** faça o `git clone` como usuário comum. Use `sudo` somente no `setup_tools.sh`. Clonar o repositório com `sudo git clone` pode deixar a pasta pertencendo ao root e impedir a gravação dos resultados.

O instalador valida as ferramentas pelo executável correto, não apenas pelo nome. Isso é especialmente importante no Kali: o pacote `python3-httpx` também pode fornecer um comando chamado `httpx`, enquanto a ferramenta usada pelo L1ght Recon é o **httpx da ProjectDiscovery**, empacotado pelo Kali como `httpx-toolkit`.

Em Kali o setup prioriza os pacotes da própria distribuição (`httpx-toolkit`, `katana` e `nuclei`). Em Debian/Ubuntu e derivados, quando esses pacotes não estão disponíveis, o instalador usa os binários pré-compilados oficiais dos projetos. O fluxo suporta Linux x86_64/amd64 e arm64/aarch64, preserva bibliotecas Python já fornecidas pelo APT quando compatíveis e aplica fallbacks para FFUF, WAFW00F, Nikto, WhatWeb e SecLists quando necessário.

O caminho padrão da SecLists também é normalizado para `/usr/share/wordlists/seclists`. Quando as listas necessárias não existem, o setup baixa somente `Discovery/Web-Content` e `Discovery/DNS`, evitando instalar o pacote completo da SecLists apenas para usar as wordlists do L1ght Recon.

Na primeira execução real, o L1ght Recon ainda revalida as dependências. Se algo estiver ausente e houver um terminal interativo, ele pode solicitar `sudo` automaticamente para executar `setup_tools.sh`. Em WSL, o Katana é usado no fluxo CLI normal do L1ght Recon; não é necessário instalar Chromium ou suporte gráfico apenas para a ferramenta. Se o diretório atual não permitir escrita, a saída padrão passa automaticamente para `~/l1ght_recon_results/`.

O script registra automaticamente o comando `l1ght_recon` no PATH. Depois do preparo do ambiente, o uso normal fica assim:

```bash
l1ght_recon -t 192.168.92.206
```

## Continuidade e follow-up

O L1ght Recon mantém `session_state.json` dentro de cada execução. Se uma execução da mesma versão for interrompida com `Ctrl+C`, os resultados concluídos são preservados e a próxima chamada para o mesmo alvo pode retomar automaticamente a sessão incompleta encontrada no diretório atual ou em `~/l1ght_recon_results`.

Também é possível solicitar explicitamente:

```bash
l1ght_recon -t 192.168.92.206 --resume
l1ght_recon -t 192.168.92.206 --resume recon_192.168.92.206_20260914_120000
```

O `--resume` reutiliza fases já concluídas, como Nmap, HTTPX, Katana e scanners Web. No FFUF cada base finalizada ganha um checkpoint `.done`; se a interrupção ocorrer no meio da enumeração, as bases concluídas não são executadas novamente.

Para uma **segunda passagem** que aprofunda o que já foi encontrado, use:

```bash
l1ght_recon -t 192.168.92.206 --follow-up
```

O `--follow-up` cria uma nova execução, importa URLs e resultados da execução anterior e prioriza os diretórios mais profundos já descobertos. Assim, se a primeira passagem encontrou `/admin/bkp`, a próxima pode iniciar o FFUF diretamente nessa árvore em vez de repetir a raiz. O Nmap/HTTPX continuam sendo refeitos para confirmar que o alvo e os serviços permanecem disponíveis.

Use `--fresh` quando quiser ignorar uma sessão incompleta e começar do zero.

### Git exposto

Serviços Web recebem uma verificação básica de exposição de `.git`. A enumeração só é apresentada quando `.git/HEAD` é confirmado e coleta apenas metadados úteis, como branch, commit atual, remotes, packed refs e últimas entradas de `logs/HEAD`. O L1ght Recon não reconstrói automaticamente os objetos do repositório. Use `--skip-git-enum` para desabilitar.

## Perfis

O perfil padrão prioriza equilíbrio entre cobertura, velocidade e fluidez. O UDP testa as **200 portas mais frequentes** e confirma de forma direcionada candidatos `open|filtered`; somente portas efetivamente confirmadas como `open` são contabilizadas como abertas.

Para uma passagem rápida e direcionada, use `--fast`:

```bash
l1ght_recon -t 192.168.92.206 --fast
```

O perfil **fast** usa top 2000 portas TCP, UDP top 100, Katana depth 2, FFUF com `common.txt`, recursão depth 2 e no máximo duas extensões escolhidas conforme a tecnologia observada. O Nmap usa identificação leve de versão, o Nikto restringe categorias e tempo, e o Nuclei prioriza severidades medium/high/critical. É um perfil com perda consciente de cobertura em troca de velocidade; o modo padrão continua recomendado quando o tempo permite.

Para uma enumeração mais completa, sem priorizar tanto o tempo, use `--full`:

```bash
l1ght_recon -t 192.168.92.206 --full
```

O `--full` aumenta automaticamente o Katana para depth 5, o FFUF para depth 2, a análise de fonte para até 60 páginas e o UDP para **400 portas**. Mesmo no modo full o UDP permanece limitado a um conjunto razoável. O ajuste manual fica disponível em `--udp-top N`, com máximo de 500.

## Exemplos

```bash
l1ght_recon -t 192.168.92.206:8080
l1ght_recon -t 192.168.92.206 --log
l1ght_recon -t 192.168.92.206 --full --log
l1ght_recon -t 192.168.92.206 --skip-wpscan
l1ght_recon -t 192.168.92.206 --udp-top 300
l1ght_recon -t 192.168.92.206 --vhost-domain alvo.local
l1ght_recon --check-update
```

`--log` grava um log detalhado para auditoria, incluindo comandos, stdout/stderr, códigos de retorno, duração das fases e exceções. Cookies e segredos conhecidos são redigidos. Frames repetitivos de barras de progresso são removidos do `debug.log`, mas os logs brutos das ferramentas continuam preservados nos artefatos. Sem indicar um nome, o arquivo fica em `recon_<host>_<data_hora>/debug.log`, e o caminho completo também é exibido na seção **ARTEFATOS** ao final.

O relatório final é gerado em **HTML**. Ele contém detalhes adicionais que não são exibidos no terminal para manter a execução mais limpa e fluida.

## Otimizações do fluxo

A enumeração Web utiliza sementes canonicalizadas, baseline própria de wildcard/soft-404 antes do FFUF, filtros conservadores de respostas genéricas e apresentação progressiva de FFUF, Nuclei e Nikto. Redirecionadores canônicos HTTP→HTTPS que preservam qualquer path são reconhecidos antes do fuzzing e não geram milhares de resultados falsos.

Bases obtidas de sementes confiáveis, como `/pdf_generator/`, são sempre fuzzadas diretamente. O L1ght Recon não considera mais uma base totalmente coberta apenas porque uma recursão pai encontrou algum filho abaixo dela; isso melhora a descoberta de diretórios simples em aplicações aninhadas.

Os JSON/logs brutos do FFUF permanecem preservados, enquanto o terminal, o `ffuf_content.json` consolidado e o HTML exibem os resultados após a validação. O arquivo `ffuf_filter_summary.json` registra as baselines e a quantidade de respostas descartadas.

Limites concorrentes por ferramenta pesada continuam ativos e os resultados de background são exibidos assim que ficam disponíveis, em blocos atômicos, sem misturar linhas de ferramentas diferentes.

### WordPress / WPScan

O L1ght Recon confirma WordPress antes de executar o WPScan. A decisão combina fingerprint do HTTPX/WhatWeb, caminhos característicos como `/wp-content/`, `/wp-includes/`, `/wp-admin/`, `wp-login.php` e `wp-json`, headers como `X-Pingback`/REST API e evidências no HTML. Um serviço Web comum não recebe WPScan.

Quando WordPress é confirmado, o resultado fica em `web_<porta>_<scheme>/wpscan.json` e o terminal mostra somente um resumo de versão, tema, plugins, usuários e vulnerabilidades. O HTML mantém os detalhes.

Perfis:
- `--fast`: usuários + plugins/temas populares/observáveis, detecção passiva e limite curto;
- padrão: usuários, plugins/temas populares, backups de configuração e exports de banco;
- `--full`: enumeração ampla de plugins/temas, TimThumb, backups e exports.

Se a variável `WPSCAN_API_TOKEN` estiver definida, ela é usada automaticamente para enriquecer a consulta de vulnerabilidades e é redigida do `debug.log`. Sem token, a enumeração continua normalmente. Use `--skip-wpscan` para desabilitar essa etapa.

Exemplo com token:

```bash
export WPSCAN_API_TOKEN='seu_token'
l1ght_recon -t alvo.local --log
```

A enumeração de MySQL inclui `mysql-empty-password` para testar somente os casos triviais de **root sem senha** e **anonymous sem senha**; o resultado só é exibido quando o login vazio é aceito. Serviços Web também recebem uma verificação direcionada com o NSE `http-shellshock`, incluindo URIs CGI descobertas pelo recon e um pequeno conjunto de caminhos comuns. A seção só aparece quando o NSE marca explicitamente o alvo como vulnerável.

## Versão 2.5.0

A versão 2.5.0 adiciona sessões retomáveis com `session_state.json`, auto-resume após interrupção, `--resume`, `--follow-up` e `--fresh`. O follow-up reaproveita URLs/diretórios da passagem anterior e inicia o FFUF pelas árvores já descobertas. Também adiciona enumeração básica de `.git` exposto e corrige falsos positivos de FFUF em serviços que respondem 503/429/5xx de forma uniforme para caminhos inexistentes.

## Versão 2.4.0

A versão 2.4.0 adiciona detecção automática e contextual de WordPress e integração com WPScan. O scanner só é iniciado quando WordPress é confirmado por evidências suficientes, respeita os perfis `--fast`, padrão e `--full`, aceita `WPSCAN_API_TOKEN` por variável de ambiente e pode ser desabilitado com `--skip-wpscan`. O setup instala WPScan pelo pacote da distribuição quando disponível e usa RubyGems como fallback.

## Versão 2.3.0

A versão 2.3.0 adiciona o perfil `--fast`, verificação positiva-only de Shellshock, teste MySQL de root/anonymous com senha vazia, fallback TCP `-sT` para execução sem privilégios, saída automática no HOME quando o diretório atual não é gravável e novas proteções no instalador para WSL, pacotes Python do APT, ferramentas já instaladas e downloads de releases corrompidos/incompletos.

## Versão 2.2.1

A versão 2.2.1 corrige a instalação em sistemas Kali/Debian/Ubuntu limpos: evita que o pip tente substituir o `requests` instalado pelo APT, valida o httpx da ProjectDiscovery pelas flags do CLI, usa binários oficiais como fallback e prepara apenas a parte necessária da SecLists. A enumeração FFUF permanece com as correções da 2.2.0.

## Versão 2.2.0

A versão 2.2.0 concentra-se em confiabilidade do content discovery e instalação: validação adicional de wildcard/soft-404 no FFUF, eliminação de redirecionamentos HTTP→HTTPS falsos positivos, fuzzing direto de todas as bases confiáveis, redução de falsos positivos do detector de segredos em JavaScript minificado e um instalador resiliente que diferencia o httpx da ProjectDiscovery do python-httpx.

## Versão 2.0.0

A versão 2.0.0 consolida a nova arquitetura operacional do L1ght Recon: scheduler para ferramentas pesadas, FFUF adaptativo, resultados progressivos, métricas internas, UDP em duas fases com distinção entre `open` e `open|filtered`, perfil padrão otimizado e modo `--full` para maior cobertura.

O perfil padrão usa UDP top 200. O modo `--full` usa UDP top 400 e amplia profundidade do Katana, FFUF e análise de código-fonte, sem recorrer a 1000 portas UDP.

Histórico principal: `1.8.1` base estável; `1.8.2` updater/FFUF; `1.8.3` desempenho, HTML, log e SMB; `1.8.4` updater/cleanup; `1.8.5` build intermediário da nova arquitetura; `2.0.0` consolidação da nova geração.

## Versão 2.0.1

A versão 2.0.1 adiciona discretamente o tempo total da enumeração ao final da execução e registra a duração total também no `debug.log`.

## Versão 2.1.0

A versão 2.1.0 adiciona análise contextual de possíveis credenciais, hashes e segredos em recursos descobertos pelo FFUF/Katana, seleção inteligente de código-fonte e reutilização de respostas HTTP entre as fases.

## Análise de possíveis credenciais e segredos

A partir da versão 2.1.0, recursos textuais descobertos pelo Katana e FFUF passam por uma análise contextual de dados sensíveis. Arquivos com nomes como `users`, `credentials`, `config`, `database`, `backup`, `hash`, `secret` e semelhantes são priorizados e não consomem o limite normal de páginas da análise de fonte.

O detector correlaciona pares como `user/password`, `user/hash`, `login/senha`, `DB_USER/DB_PASSWORD` e `client_id/client_secret`; reconhece formatos estruturais de hashes e tokens; usa entropia apenas como evidência complementar; atribui score/confiança e evita tratar simples ocorrências de palavras como credenciais confirmadas.

O terminal exibe somente um resumo. Valores e contexto completos ficam no relatório HTML e em `sensitive_findings.json` dentro do diretório do serviço Web. O `debug.log` registra apenas contagens e metadados da análise, sem copiar os valores sensíveis encontrados. Respostas HTTP já coletadas são reutilizadas entre as fases para evitar requisições duplicadas.

## Versão 2.1.1

A versão 2.1.1 corrige a correlação de pares em blocos de múltiplas credenciais e inclui `client_id/client_secret` como par contextual.

## Atualização

A ferramenta verifica silenciosamente se há uma versão estável mais nova **antes de processar os argumentos da execução normal**. Isso permite atualizar primeiro e só depois interpretar parâmetros adicionados por versões novas. Se estiver atualizada ou não houver conectividade, não imprime mensagem. Quando existe atualização, valida SHA-256 e sintaxe antes de substituir o script.

`--check-update` instala imediatamente a versão mais nova quando ela existe. `--update` é mantido como comando equivalente por compatibilidade. O updater não cria backups `.bak` persistentes; backups legados criados por versões antigas são removidos antes de qualquer fluxo de saída antecipada.

```bash
l1ght_recon --check-update
l1ght_recon --update
l1ght_recon -t 192.168.92.206 --no-update
```
