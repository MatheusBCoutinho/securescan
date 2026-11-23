"""Scanner educacional de padrões inseguros em Python (análise estática)."""
import argparse
import ast
import json
import re
from pathlib import Path

SKIP = {".git", "venv", ".venv", "node_modules", "__pycache__", "dist"}
SECRET = re.compile(r"(?i)(?:password|api_key|secret|token)\s*=\s*['\"]([^'\"]{8,})['\"]")


def scan_file(path: Path) -> list[dict]:
    findings = []
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [{"file": str(path), "line": 0, "rule": "READ_ERROR", "severity": "info", "message": str(exc)}]
    for number, line in enumerate(source.splitlines(), start=1):
        if SECRET.search(line) and not line.lstrip().startswith("#"):
            findings.append(_finding(path, number, "POSSIBLE_SECRET", "high", "Possível credencial fixa no código"))
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return findings + [_finding(path, exc.lineno or 0, "SYNTAX_ERROR", "info", "Arquivo Python com sintaxe inválida")]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in {"eval", "exec"}:
            findings.append(_finding(path, node.lineno, "DYNAMIC_EXEC", "high", f"Execução dinâmica: {name}"))
        if name in {"os.system", "os.popen"}:
            findings.append(_finding(path, node.lineno, "SHELL_COMMAND", "medium", f"Comando de shell: {name}"))
        if name.startswith("subprocess.") and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            findings.append(_finding(path, node.lineno, "SUBPROCESS_SHELL", "high", "subprocess com shell=True"))
        if name in {"pickle.loads", "pickle.load"}:
            findings.append(_finding(path, node.lineno, "UNSAFE_DESERIALIZATION", "high", "Desserialização pickle; não usar dados não confiáveis"))
    return findings


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}"
    return ""


def _finding(path, line, rule, severity, message):
    return {"file": str(path), "line": line, "rule": rule, "severity": severity, "message": message}


def scan_path(target: Path) -> list[dict]:
    if not target.exists():
        raise FileNotFoundError(target)
    if target.is_file():
        if target.suffix != ".py":
            raise ValueError("Informe um arquivo .py ou diretório")
        return scan_file(target)
    findings = []
    for file in sorted(target.rglob("*.py")):
        if not any(part in SKIP for part in file.parts):
            findings.extend(scan_file(file))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="SecureScan: análise estática simples de Python")
    parser.add_argument("path", help="Arquivo Python ou diretório")
    parser.add_argument("--json", action="store_true", help="Saída JSON")
    args = parser.parse_args(argv)
    try:
        findings = scan_path(Path(args.path))
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(findings, ensure_ascii=False, indent=2))
    else:
        for issue in findings:
            print(f"{issue['severity'].upper():7} {issue['file']}:{issue['line']} [{issue['rule']}] {issue['message']}")
        print(f"\n{len(findings)} achado(s). Atenção: heurísticas podem gerar falsos positivos.")
    return 1 if any(item["severity"] in {"high", "medium"} for item in findings) else 0
