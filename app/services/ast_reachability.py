from __future__ import annotations

import ast
from pathlib import Path

from app.schemas.scan import Dependency


SENSITIVE_KEYWORDS = {
    "authentication": {"auth", "login", "password", "session", "jwt", "token", "oauth", "otp", "mfa"},
    "payments": {"payment", "transaction", "upi", "card", "wallet", "settlement", "invoice", "amount"},
    "kyc": {"kyc", "pan", "aadhaar", "ssn", "passport", "identity", "verification"},
    "pii": {"email", "phone", "address", "dob", "accountnumber", "account_number", "ifsc", "customer"},
    "crypto": {"crypto", "cipher", "hash", "encrypt", "decrypt", "signature", "privatekey", "secret"},
    "database-write": {"save", "insert", "update", "delete", "repository", "sequelize", "prisma", "mongoose"},
}


def find_python_dependency_usage(project_path: Path, source_path: Path, text: str, dependency: Dependency) -> dict | None:
    if source_path.suffix.lower() != ".py" or dependency.ecosystem != "PyPI":
        return None
    try:
        tree = ast.parse(text, filename=str(source_path))
    except SyntaxError:
        return None

    package = dependency.name.lower().replace("-", "_")
    import_node = None
    aliases: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".", 1)[0].lower().replace("-", "_")
                if root == package or item.name.lower().replace("-", "_") == package:
                    import_node = node
                    aliases.append(item.asname or item.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0].lower().replace("-", "_")
            if root == package or node.module.lower().replace("-", "_") == package:
                import_node = node
                aliases.extend(item.asname or item.name for item in node.names)

    if not import_node:
        return None

    contexts = _contexts(source_path, tree, text)
    if not contexts:
        return None

    routes = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            route = _route_from_decorator(decorator)
            if route:
                routes.append(route | {"line_number": getattr(decorator, "lineno", node.lineno), "code": _line(text, getattr(decorator, "lineno", node.lineno))})

    import_line = getattr(import_node, "lineno", 1)
    return {
        "path": str(source_path.relative_to(project_path)),
        "contexts": contexts,
        "import_line": import_line,
        "import_code": _line(text, import_line),
        "import_aliases": aliases,
        "sensitive_lines": _sensitive_lines(text),
        "routes": routes[:10],
        "analysis": "python-ast",
        "confidence": 0.9,
    }


def _contexts(path: Path, tree: ast.AST, text: str) -> list[str]:
    haystack = f"{path.as_posix()}\n{text[:50000]}".lower().replace("-", "_")
    contexts = [name for name, keywords in SENSITIVE_KEYWORDS.items() if any(keyword in haystack for keyword in keywords)]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name.lower()
            for context, keywords in SENSITIVE_KEYWORDS.items():
                if any(keyword in name for keyword in keywords) and context not in contexts:
                    contexts.append(context)
    return contexts


def _route_from_decorator(node: ast.expr) -> dict | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr.lower() not in {"get", "post", "put", "patch", "delete", "route"} or not node.args:
        return None
    path = node.args[0]
    if not isinstance(path, ast.Constant) or not isinstance(path.value, str):
        return None
    return {"framework": "Python AST", "method": node.func.attr.upper(), "path": path.value}


def _sensitive_lines(text: str) -> list[dict]:
    results = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        lower = line.lower().replace("-", "_")
        contexts = [name for name, keywords in SENSITIVE_KEYWORDS.items() if any(keyword in lower for keyword in keywords)]
        if contexts:
            results.append({"line_number": line_number, "code": line[:220], "contexts": contexts, "dependency_usage": False})
    return results[:10]


def _line(text: str, number: int) -> str:
    lines = text.splitlines()
    return lines[number - 1].strip()[:220] if 0 < number <= len(lines) else ""
