# Security Policy

## Uso Responsavel

O Leviathan-VS e um ambiente de pesquisa em seguranca. Todas as ferramentas integradas devem ser usadas **apenas em ambientes autorizados** (laboratorio, CTFs, dispositivos proprios, ou com permissao explicita por escrito do proprietario).

**SAFE_MODE** esta ativado por padrao (`LEVIATHAN_SAFE_MODE=1`) e:
- Exclui metodos HTTP destrutivos (DELETE) em scans automaticos
- Exige confirmacao para operacoes irreversiveis
- Gera logs de auditoria local em `.leviathan_audit.log`

Para desativar (sob sua responsabilidade):
```bash
set LEVIATHAN_SAFE_MODE=0
```

## Reportando Vulnerabilidades

Se voce encontrou uma vulnerabilidade no Leviathan-VS (nao nas ferramentas alvo):

1. **NAO abra issue publica**
2. Envie email para o maintainer ou use GitHub Security Advisories
3. Inclua: descricao do problema, impacto, passos para reproduzir
4. Aguarde resposta em ate 72 horas

## Escopo

Consideramos vulnerabilidades:
- Execucao de codigo arbitrario via configs maliciosos
- Vazamento de credenciais/paths via logs ou output
- Bypass de SAFE_MODE sem flag explicito
- MCP servers executando comandos sem sanitizacao

Fora de escopo:
- Bugs em ferramentas externas (Frida, Ghidra, etc.)
- Uso indevido por operadores com acesso local

## Versoes Suportadas

| Versao | Suportada |
| ------ | --------- |
| 14.x   | Sim       |
| < 14   | Nao       |
