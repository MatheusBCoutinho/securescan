# 🔎 SecureScan | Scanner de Segurança para Python

**PT-BR** | [English](#english)

> Scanner educacional de análise estática (SAST) que encontra padrões potencialmente inseguros em arquivos Python sem executar o código analisado.

## Objetivo
Demonstrar conceitos básicos de segurança de aplicações, automação em Python, AST, expressões regulares, testes e integração contínua. O projeto identifica **indícios**, não confirma que uma vulnerabilidade seja explorável.

## Funcionalidades
- Procura possíveis credenciais atribuídas diretamente a variáveis (`password`, `api_key`, `secret`, `token`) com Regex.
- Inspeciona chamadas a `eval`, `exec`, `os.system`, `os.popen`, `pickle.load`, `pickle.loads` e chamadas `subprocess.*` com `shell=True` literal via AST.
- Aceita um arquivo `.py` ou um diretório, ignorando pastas de ambiente virtual e build predefinidas.
- Produz saída no terminal ou JSON; retorna código 1 quando há alertas médios ou altos.
- Executa três testes automatizados com `unittest` via GitHub Actions.

## Requisitos
Python 3.10+ (sem dependências externas).

## Como executar
```bash
python -m unittest discover -s tests -v
python -m securescan examples/insecure_example.py
python -m securescan examples --json
```
**Observação:** o exemplo contém padrões inseguros propositalmente. O comando do scanner retorna status `1` quando detecta alertas; não é erro inesperado.

## Estrutura
```text
securescan/
  __init__.py        # versão
  __main__.py        # ponto de entrada do CLI
  scanner.py         # detecção, varredura e apresentação
examples/
  insecure_example.py
 tests/
  test_scanner.py
.github/workflows/
  ci.yml
.gitignore
README.md
```

## Como funciona
1. `main()` interpreta o caminho e a opção `--json` via `argparse`.
2. `scan_path()` valida o destino e lista os arquivos `.py` (ignorando diretórios configurados).
3. `scan_file()` lê o texto; usa Regex para possível segredo e `ast.parse()` + `ast.walk()` para chamadas potencialmente perigosas.
4. Os achados recebem arquivo, linha, identificador de regra, severidade e mensagem.
5. O CLI imprime a saída e retorna código 1 se houver alerta `medium` ou `high`.

## Exemplo de saída
```text
HIGH    examples/insecure_example.py:3 [POSSIBLE_SECRET] Possível credencial fixa no código
HIGH    examples/insecure_example.py:4 [SUBPROCESS_SHELL] subprocess com shell=True
```

## Limitações conhecidas
- Busca de segredos baseada em Regex é heurística; pode gerar falsos positivos ou ignorar senhas em formatos diferentes.
- A AST busca nomes sintáticos; não resolve alias de imports, fluxo de dados ou contexto de exploração.
- O uso de `shell=True`, `pickle` ou `eval` exige revisão contextual; nem toda ocorrência é uma vulnerabilidade explorável.
- Arquivos com sintaxe inválida geram alerta informativo, não análise completa de chamadas.
- Não substitui Semgrep, Bandit, revisão humana ou análise dinâmica.

## Próximas melhorias
Suporte a aliases, configurações de regras, testes adicionais, relatório SARIF e comparação com ferramentas maduras.

## Segurança e ética
Analise somente arquivos e repositórios que você possui ou está autorizado a avaliar. Não inclua credenciais reais nos exemplos ou commits.

---

<a id="english"></a>
# English

**SecureScan** is an educational Python static-analysis (SAST) CLI tool that flags potentially insecure code patterns **without executing scanned code**. It is designed to demonstrate application-security fundamentals, Python automation, AST inspection, regular expressions, unit tests, and continuous integration.

## Features
- Heuristic detection of potentially hardcoded credentials through Regex.
- AST-based detection of `eval()`, `exec()`, `os.system()`, `os.popen()`, `pickle.load(s)()`, and `subprocess.*` calls using literal `shell=True`.
- Scans individual Python files or directories while excluding common virtual environment and build folders.
- Human-readable and JSON output; exit code 1 for medium/high findings.
- Three `unittest` checks run by GitHub Actions.

## Requirements and usage
Python 3.10+, no third-party dependencies.
```bash
python -m unittest discover -s tests -v
python -m securescan examples/insecure_example.py
python -m securescan examples --json
```
The intentionally vulnerable example produces findings and returns exit code 1 by design.

## Architecture
`__main__.py` invokes `main()`; `scan_path()` selects files; `scan_file()` uses Regex and Python's AST to generate findings; the CLI formats the report. See `scanner.py` for the rule definitions and `tests/test_scanner.py` for validation.

## Limitations
This is a heuristic educational scanner, not a production-grade vulnerability assessment tool. It does not perform data-flow analysis, resolve import aliases, or prove exploitability. Both false positives and false negatives are possible. Scan only code you own or are authorized to inspect.
