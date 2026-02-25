# Contributing to Leviathan-VS

Obrigado por considerar contribuir! Siga as diretrizes abaixo.

## Quick Start para Desenvolvimento

```bash
# Clone
git clone https://github.com/ThiagoFrag/Leviathan-VS.git
cd Leviathan-VS

# Instale dependencias de dev
pip install -e ".[dev]"

# Rode os testes
pytest tests/ -v

# Rode o doctor
python core/doctor.py

# Valide os configs
python core/config_schema.py

# Lint (opcional)
ruff check core/
```

## Estrutura de PRs

- PRs pequenos e focados (1 feature ou 1 fix por PR)
- Titulo: `[AREA] Descricao curta` (ex: `[CORE] Fix bare except in http_toolkit`)
- Inclua testes para funcionalidade nova
- Rode `pytest` e `python core/config_schema.py` antes de abrir PR

## Padrao de Codigo

- Python 3.9+ (compativel com 3.9 a 3.14)
- UTF-8 sem BOM em todos os arquivos
- Docstrings para classes e funcoes publicas
- `ruff` para lint (config em `pyproject.toml`)
- Sem output colorido quando `--json` flag presente

## Padrao de MCP Servers

Novos MCP servers devem seguir a mesma estrutura:
1. Criar `core/<nome>/mcp_mcp_<nome>.py`
2. Criar `core/<nome>/__init__.py`
3. Registrar em `.vscode/mcp.json`
4. Documentar em `copilot-instructions.md`
5. Adicionar tasks em `tasks.json` (pelo menos 2)

## Testes

```bash
# Rodar tudo
pytest tests/ -v

# Com coverage
pytest tests/ --cov=core --cov-report=term-missing

# Arquivo especifico
pytest tests/test_translator.py -v
```

## Checklist para PRs

- [ ] Testes passam (`pytest`)
- [ ] Configs validos (`python core/config_schema.py`)
- [ ] Doctor OK (`python core/doctor.py`)
- [ ] Sem secrets ou dados pessoais no codigo
- [ ] Documentacao atualizada se necessario
- [ ] CHANGELOG.md atualizado

## Seguranca

Se encontrar uma vulnerabilidade, **NAO abra uma issue publica**.
Consulte [SECURITY.md](SECURITY.md) para reportar de forma responsavel.
