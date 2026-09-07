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

## Exemplos

```bash
l1ght_recon -t 192.168.92.206:8080
l1ght_recon -t 192.168.92.206 --log
l1ght_recon -t 192.168.92.206 --vhost-domain alvo.local
l1ght_recon --check-update
```

`--log` grava um log detalhado para auditoria, incluindo comandos, stdout/stderr, códigos de retorno, duração das etapas e exceções. Cookies e segredos conhecidos são redigidos no log. Sem indicar um nome, o arquivo fica em `recon_<host>_<data_hora>/debug.log`, e o caminho completo também é exibido na seção **ARTEFATOS** ao final.

O relatório final é gerado em **HTML**. Ele contém detalhes adicionais que não são exibidos no terminal para manter a execução mais limpa e fluida.

## Atualização

A ferramenta verifica silenciosamente se há uma versão estável mais nova **antes de processar os argumentos da execução normal**. Isso permite atualizar primeiro e só depois interpretar parâmetros adicionados por versões novas. Se estiver atualizada ou não houver conectividade, não imprime mensagem. Quando existe atualização, valida SHA-256 e sintaxe antes de substituir o script.

`--check-update` agora também instala imediatamente a versão mais nova quando ela existe. `--update` é mantido como comando equivalente por compatibilidade. O updater não deixa arquivos `.bak` persistentes; backups legados criados por versões anteriores são removidos automaticamente.

```bash
l1ght_recon --check-update
l1ght_recon --update
l1ght_recon -t 192.168.92.206 --no-update
```
