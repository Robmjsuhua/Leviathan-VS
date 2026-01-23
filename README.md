#  THE HAND OF GOD

## Semantic Translation Engine v3.0

Uma ferramenta avançada para normalização semântica de código, permitindo traduzir termos sensíveis para termos neutros antes de enviar para IAs e restaurar os termos originais depois.

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

##  Início Rápido

### Windows (Recomendado)
```batch
# Duplo-clique no arquivo:
START_HOG.bat
```

### Linha de Comando
```bash
# Sanitizar código (antes de enviar para IA)
python translator.py encode

# Restaurar termos originais (depois de receber resposta)
python translator.py restore

# Ver estatísticas
python translator.py stats

# Modo interativo
python translator.py interactive
```

---

##  Requisitos

- **Python 3.8+** - [Download](https://python.org/downloads)
- **Windows/Linux/macOS**

---

##  Instalação

```bash
# Clone o repositório
git clone https://github.com/ThiagoFrag/hand-of-god.git

# Entre na pasta
cd hand-of-god

# Execute
python translator.py
```

---

##  Comandos Disponíveis

| Comando | Alias | Descrição |
|---------|-------|-----------|
| `encode` | `e`, `sanitize`, `clean` | Sanitiza o conteúdo |
| `decode` | `d`, `r`, `restore`, `revert` | Restaura os termos originais |
| `stats` | `s` | Mostra estatísticas |
| `history` | `h` | Mostra histórico de operações |
| `undo` | `u` | Desfaz a última operação |
| `validate` | `v` | Valida o arquivo de configuração |
| `preview` | `p` | Preview das alterações |
| `interactive` | `i` | Modo interativo |
| `help` | `-h`, `--help` | Mostra ajuda |

---

##  Fluxo de Trabalho

```

                                                             
  1. Cole seu código em work.txt                             
                                                            
  2. Execute ENCODE (opção 1)                                
     - "exploit"  "performance_case"                        
     - "bypass"  "bridge_compatibility"                     
                                                            
  3. Envie o código sanitizado para a IA                     
                                                            
  4. Cole a resposta da IA em work.txt                       
                                                            
  5. Execute RESTORE (opção 2)                               
     - "performance_case"  "exploit"                        
     - "bridge_compatibility"  "bypass"                     
                                                            
  6. Pronto! Código original restaurado                      
                                                             

```

---

##  Estrutura de Arquivos

```
hand-of-god/
 START_HOG.bat       # Interface gráfica (Windows)
 translator.py       # Motor de tradução (Python)
 config.json         # Regras de tradução (104 regras)
 work.txt            # Arquivo de trabalho
 README.md           # Documentação
 .gitignore          # Arquivos ignorados pelo git
 backups/            # Backups automáticos (ignorado pelo git)
```

---

##  Configuração

Edite o arquivo `config.json` para adicionar ou modificar regras:

```json
{
    "termo_original": "termo_sanitizado",
    "exploit": "performance_case",
    "bypass": "bridge_compatibility"
}
```

###  Regras Incluídas (104 regras)

| Categoria | Exemplos |
|-----------|----------|
|  Segurança | bypass, exploit, vulnerability, injection |
|  Malware | virus, trojan, backdoor, rootkit, keylogger |
|  Ataques | xss, csrf, ddos, sql_injection, bruteforce |
|  Ferramentas | scanner, fuzzer, debugger, decompiler |
|  Acesso | privilege, root, admin, shell, terminal |

---

##  Recursos

-  **Backup Automático** - Cada operação cria um backup
-  **Histórico** - Registra as últimas 50 operações
-  **Undo** - Desfaz a última operação
-  **Preview** - Vê as alterações antes de aplicar
-  **Validação** - Verifica conflitos na configuração
-  **Case Preserving** - Mantém maiúsculas/minúsculas
-  **Word Boundaries** - Só substitui palavras completas
-  **Estatísticas** - Contagem detalhada de alterações
-  **Hash Tracking** - Rastreia alterações por hash MD5
-  **Cores no Terminal** - Feedback visual colorido

---

##  Menu Interativo

```

                    THE HAND OF GOD                         
                 Semantic Engine v3.0                       

                                                            
   [1] ENCODE     - Preparar código para IA                 
   [2] RESTORE    - Restaurar termos originais              
   [3] PREVIEW    - Ver preview das alterações              
   [4] STATS      - Ver estatísticas completas              
   [5] HISTORY    - Ver histórico de operações              
   [6] UNDO       - Desfazer última operação                
   [7] VALIDATE   - Validar configuração                    
                                                            
   [E] EDIT       - Abrir work.txt                          
   [C] CONFIG     - Editar regras                           
   [B] BACKUPS    - Ver backups                             
   [I] INTERACTIVE- Modo interativo Python                  
                                                            
   [0] EXIT       - Sair                                    
                                                            

```

---

##  Contribuição

1. Faça um Fork do projeto
2. Crie sua Feature Branch (`git checkout -b feature/NovaRegra`)
3. Commit suas mudanças (`git commit -m 'Add: nova regra de tradução'`)
4. Push para a Branch (`git push origin feature/NovaRegra`)
5. Abra um Pull Request

---

##  Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

##  Autor

**ThiagoFrag**

- GitHub: [@ThiagoFrag](https://github.com/ThiagoFrag)

---

<p align="center">
  <b>THE HAND OF GOD</b> - Semantic Engine v3.0<br>
  <i>Traduzindo o impossível em possível</i> 
</p>