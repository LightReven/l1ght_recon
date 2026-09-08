# L1ght Recon

**Scanning & Enumeration** para laboratórios e CTFs.

## Instalação

```bash
git clone https://github.com/LightReven/l1ght_recon.git && cd l1ght_recon && python3 l1ght_recon.py -h
```

Na primeira execução real, o L1ght Recon verifica as dependências Python e as ferramentas externas. Se algo obrigatório estiver ausente, tenta executar automaticamente `requirements.txt` e `setup_tools.sh`. Em Kali/Debian, a instalação de pacotes pode solicitar privilégios administrativos.

O script também registra automaticamente o comando `l1ght_recon` no PATH. Depois do primeiro preparo do ambiente, o uso normal fica assim:

```bash
l1ght_recon -t 192.168.92.206
```

## Perfis

O perfil padrão prioriza equilíbrio entre cobertura, velocidade e fluidez. O UDP testa as **200 portas mais frequentes** e confirma de forma direcionada candidatos `open|filtered`; somente portas efetivamente confirmadas como `open` são contabilizadas como abertas.

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
l1ght_recon -t 192.168.92.206 --udp-top 300
l1ght_recon -t 192.168.92.206 --vhost-domain alvo.local
l1ght_recon --check-update
```

`--log` grava um log detalhado para auditoria, incluindo comandos, stdout/stderr, códigos de retorno, duração das fases e exceções. Cookies e segredos conhecidos são redigidos. Frames repetitivos de barras de progresso são removidos do `debug.log`, mas os logs brutos das ferramentas continuam preservados nos artefatos. Sem indicar um nome, o arquivo fica em `recon_<host>_<data_hora>/debug.log`, e o caminho completo também é exibido na seção **ARTEFATOS** ao final.

O relatório final é gerado em **HTML**. Ele contém detalhes adicionais que não são exibidos no terminal para manter a execução mais limpa e fluida.

## Otimizações do fluxo

A enumeração Web utiliza sementes canonicalizadas, FFUF adaptativo para evitar fuzzing duplicado de caminhos já cobertos pela recursão, limites concorrentes por ferramenta pesada e apresentação progressiva de FFUF, Nuclei e Nikto. Resultados de tarefas de background são exibidos assim que ficam disponíveis, em blocos atômicos, sem misturar linhas de ferramentas diferentes.

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
