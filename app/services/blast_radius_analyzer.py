from __future__ import annotations

import re
from pathlib import Path

from app.schemas.scan import (
    Dependency,
    DependencyRiskFinding,
    FixSuggestion,
    RiskChainFinding,
    RiskChainTraceStep,
    Severity,
    VulnerabilityFinding,
)
from app.services.osv_client import SEVERITY_ORDER
from app.services.ast_reachability import find_python_dependency_usage


SOURCE_SUFFIXES = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".py",
    ".java",
    ".kt",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "target", "__pycache__", "vendor"}

SENSITIVE_RULES = {
    "authentication": ["auth", "login", "password", "session", "jwt", "token", "oauth", "otp", "mfa"],
    "payments": ["payment", "transaction", "upi", "card", "wallet", "settlement", "invoice", "amount"],
    "kyc": ["kyc", "pan", "aadhaar", "ssn", "passport", "identity", "verification"],
    "pii": ["email", "phone", "address", "dob", "accountnumber", "account_number", "ifsc", "customer"],
    "crypto": ["crypto", "cipher", "hash", "encrypt", "decrypt", "signature", "privatekey", "secret"],
    "database-write": ["save(", "insert", "update", "delete", "repository", "sequelize", "prisma", "mongoose"],
    "webhook": ["webhook", "callback", "signature", "x-hub-signature", "x-signature"],
    "file-upload": ["upload", "multipart", "multer", "formidable", "file", "blob"],
    "network-egress": ["fetch(", "axios", "request(", "http.", "https.", "socket", "webclient"],
}

ROUTE_PATTERNS = [
    ("Express", re.compile(r"\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['\"`]([^'\"`]+)", re.IGNORECASE)),
    ("FastAPI/Flask", re.compile(r"@\s*(?:app|router|api|bp|blueprint)\s*\.\s*(get|post|put|patch|delete|route)\s*\(\s*['\"`]([^'\"`]+)", re.IGNORECASE)),
    ("Django", re.compile(r"\b(?:path|re_path)\s*\(\s*['\"`]([^'\"`]+)", re.IGNORECASE)),
    ("Spring", re.compile(r"@\s*(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*(?:\(\s*(?:value\s*=\s*)?)?['\"`]([^'\"`]+)", re.IGNORECASE)),
    ("Gin/Echo", re.compile(r"\b(?:r|router|engine|group|e)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*['\"`]([^'\"`]+)", re.IGNORECASE)),
    ("ASP.NET", re.compile(r"\[\s*(HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\s*(?:\(\s*['\"`]([^'\"`]+))?", re.IGNORECASE)),
]


def analyze_blast_radius(
    project_path: Path,
    dependencies: list[Dependency],
    findings: list[VulnerabilityFinding],
    dependency_risks: list[DependencyRiskFinding],
) -> list[RiskChainFinding]:
    source_files = _source_files(project_path)
    if not source_files:
        return []

    vulnerable_by_dep = {(item.ecosystem, item.package_name.lower()): item for item in findings}
    risks_by_dep: dict[tuple[str, str], list[DependencyRiskFinding]] = {}
    for risk in dependency_risks:
        if risk.dependency_name:
            risks_by_dep.setdefault(("any", risk.dependency_name.lower()), []).append(risk)

    chains: list[RiskChainFinding] = []
    for dep in _dedupe_dependencies(dependencies):
        usage = _find_dependency_usage(project_path, source_files, dep)
        if not usage:
            continue

        sensitive_contexts = sorted({context for item in usage for context in item["contexts"]})
        if not sensitive_contexts:
            continue

        vuln = vulnerable_by_dep.get((dep.ecosystem, dep.name.lower()))
        hygiene_risks = risks_by_dep.get(("any", dep.name.lower()), [])
        if not vuln and not hygiene_risks and dep.scope == "development":
            continue

        severity = _chain_severity(vuln, hygiene_risks, sensitive_contexts)
        rel_files = [item["path"] for item in usage[:5]]
        evidence = [item["import_code"] for item in usage[:5] if item.get("import_code")]
        risk_chain = _risk_chain(dep, vuln, hygiene_risks, sensitive_contexts, usage)
        trace = _trace_steps(dep, vuln, hygiene_risks, usage[:5])
        chains.append(
            RiskChainFinding(
                id=f"blast-radius:{dep.ecosystem}:{dep.name}",
                dependency_name=dep.name,
                ecosystem=dep.ecosystem,
                severity=severity,
                title=f"{dep.name} reaches sensitive {', '.join(sensitive_contexts[:3])} code",
                risk_chain=risk_chain,
                trace=trace,
                manifest_path=dep.manifest_path,
                sensitive_contexts=sensitive_contexts,
                used_in_files=rel_files,
                evidence=evidence,
                fix=FixSuggestion(
                    title="Review dependency blast radius",
                    description="Prioritize this dependency because it is used near sensitive banking code. Upgrade, pin, sandbox, or replace it before lower-impact packages.",
                    auto_remediable=False,
                ),
                reachability_confidence=max(float(item.get("confidence", 0.5)) for item in usage),
                analysis_method=",".join(sorted({item.get("analysis", "regex-fallback") for item in usage})),
            )
        )

    return sorted(chains, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)[:50]


def _source_files(project_path: Path) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for path in project_path.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                files.append((path, text))
            except OSError:
                continue
            if len(files) >= 2000:
                break
    return files


def _find_dependency_usage(project_path: Path, source_files: list[tuple[Path, str]], dep: Dependency) -> list[dict]:
    patterns = _dependency_patterns(dep)
    if not patterns:
        return []

    quick_match_str = dep.name.split("/")[-1].split(":")[-1]

    usage: list[dict] = []
    for path, text in source_files:
        ast_usage = find_python_dependency_usage(project_path, path, text, dep)
        if ast_usage:
            usage.append(ast_usage)
            continue
        if quick_match_str not in text:
            continue

        import_match = _first_matching_line(text, patterns)
        if not import_match:
            continue
        contexts = _sensitive_contexts(path, text)
        if not contexts:
            continue
        rel_path = str(path.relative_to(project_path))
        usage_patterns = [*patterns, *import_match["alias_patterns"]]
        sensitive_lines = _sensitive_lines(text, usage_patterns)
        routes = _route_lines(text)
        usage.append(
            {
                "path": rel_path,
                "contexts": contexts,
                "import_line": import_match["line_number"],
                "import_code": import_match["code"],
                "import_aliases": import_match["aliases"],
                "sensitive_lines": sensitive_lines[:5],
                "routes": routes[:5],
                "analysis": "regex-fallback",
                "confidence": 0.55,
            }
        )
    return usage


def _dependency_patterns(dep: Dependency) -> list[str]:
    name = dep.name
    escaped = re.escape(name)
    base = name.split("/")[-1].split(":")[-1]
    escaped_base = re.escape(base)
    patterns = [
        rf"from\s+['\"]{escaped}['\"]",
        rf"require\(\s*['\"]{escaped}['\"]\s*\)",
        rf"import\s+.*?['\"]{escaped}['\"]",
        rf"import\s+{escaped_base}\b",
        rf"using\s+{escaped_base}\b",
        rf"<PackageReference[^>]+Include=['\"]{escaped}['\"]",
    ]
    if dep.ecosystem == "Go":
        patterns.append(rf"['\"]{escaped}['\"]")
    if dep.ecosystem == "Maven" and ":" in name:
        patterns.append(re.escape(name.split(":", 1)[1]))
    return patterns


def _sensitive_contexts(path: Path, text: str) -> list[str]:
    haystack = f"{path.as_posix().lower()}\n{text[:50000].lower()}"
    contexts = []
    for context, keywords in SENSITIVE_RULES.items():
        if any(keyword in haystack for keyword in keywords):
            contexts.append(context)
    return contexts


def _first_matching_line(text: str, patterns: list[str]) -> dict | None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if any(re.search(pattern, stripped, re.IGNORECASE) for pattern in patterns):
            aliases = _import_aliases(stripped)
            alias_patterns = [rf"\b{re.escape(alias)}\s*(?:\.|\()" for alias in aliases]
            return {"line_number": line_number, "code": stripped[:220], "aliases": aliases, "alias_patterns": alias_patterns}
    return None


def _import_aliases(line: str) -> list[str]:
    aliases: list[str] = []
    patterns = [
        r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*require\(",
        r"\blet\s+([A-Za-z_$][\w$]*)\s*=\s*require\(",
        r"\bvar\s+([A-Za-z_$][\w$]*)\s*=\s*require\(",
        r"\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+['\"]",
        r"\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['\"]",
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            aliases.append(match.group(1))
    return aliases


def _sensitive_lines(text: str, dependency_patterns: list[str]) -> list[dict]:
    hits: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        matched_contexts = [
            context
            for context, keywords in SENSITIVE_RULES.items()
            if any(keyword in lower for keyword in keywords)
        ]
        dependency_usage = any(re.search(pattern, stripped, re.IGNORECASE) for pattern in dependency_patterns)
        if matched_contexts or dependency_usage:
            hits.append(
                {
                    "line_number": line_number,
                    "code": stripped[:220],
                    "contexts": matched_contexts or ["dependency-call"],
                    "dependency_usage": dependency_usage,
                }
            )
    return sorted(hits, key=lambda item: (not item["dependency_usage"], item["line_number"]))


def _route_lines(text: str) -> list[dict]:
    routes: list[dict] = []
    pending_route_prefix: str | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for framework, pattern in ROUTE_PATTERNS:
            match = pattern.search(stripped)
            if not match:
                continue

            method, route_path = _route_match_parts(framework, match)
            if framework == "ASP.NET" and method == "ROUTE":
                pending_route_prefix = route_path or pending_route_prefix
                continue
            if pending_route_prefix and route_path and not route_path.startswith("/"):
                route_path = f"{pending_route_prefix.rstrip('/')}/{route_path.lstrip('/')}"

            routes.append(
                {
                    "framework": framework,
                    "method": method,
                    "path": route_path or "(route path not specified)",
                    "line_number": line_number,
                    "code": stripped[:220],
                }
            )
            if len(routes) >= 10:
                return routes
    return routes


def _route_match_parts(framework: str, match: re.Match) -> tuple[str, str | None]:
    groups = match.groups()
    if framework in {"Express", "Gin/Echo"}:
        return groups[0].upper(), groups[1]
    if framework == "FastAPI/Flask":
        method = groups[0].upper()
        return ("ANY" if method == "ROUTE" else method), groups[1]
    if framework == "Django":
        return "ROUTE", groups[0]
    if framework == "Spring":
        method_map = {
            "GETMAPPING": "GET",
            "POSTMAPPING": "POST",
            "PUTMAPPING": "PUT",
            "PATCHMAPPING": "PATCH",
            "DELETEMAPPING": "DELETE",
            "REQUESTMAPPING": "REQUEST",
        }
        return method_map.get(groups[0].upper(), groups[0].upper()), groups[1]
    if framework == "ASP.NET":
        method_map = {
            "HTTPGET": "GET",
            "HTTPPOST": "POST",
            "HTTPPUT": "PUT",
            "HTTPPATCH": "PATCH",
            "HTTPDELETE": "DELETE",
            "ROUTE": "ROUTE",
        }
        return method_map.get(groups[0].upper(), groups[0].upper()), groups[1]
    return "ROUTE", None


def _chain_severity(
    vuln: VulnerabilityFinding | None,
    hygiene_risks: list[DependencyRiskFinding],
    contexts: list[str],
) -> Severity:
    base = vuln.severity if vuln else Severity.medium
    if hygiene_risks:
        base = max([base, *[risk.severity for risk in hygiene_risks]], key=lambda item: SEVERITY_ORDER[item])
    if {"payments", "authentication", "crypto"} & set(contexts) and SEVERITY_ORDER[base] < SEVERITY_ORDER[Severity.high]:
        return Severity.high
    return base


def _risk_chain(
    dep: Dependency,
    vuln: VulnerabilityFinding | None,
    hygiene_risks: list[DependencyRiskFinding],
    contexts: list[str],
    usage: list[dict],
) -> list[str]:
    first_usage = usage[0] if usage else None
    chain = [f"{dep.name} declared in {dep.manifest_path}"]
    if first_usage:
        if first_usage["routes"]:
            route = first_usage["routes"][0]
            chain.append(f"Route {route['method']} {route['path']} reaches {first_usage['path']}")
        chain.append(f"Imported in {first_usage['path']}:{first_usage['import_line']}")
    if vuln:
        chain.append(f"Known vulnerability {vuln.id} affects the installed version")
    if hygiene_risks:
        chain.append(f"Dependency hygiene issue detected: {hygiene_risks[0].title}")
    if first_usage and first_usage["sensitive_lines"]:
        sensitive = first_usage["sensitive_lines"][0]
        chain.append(f"Sensitive operation in {first_usage['path']}:{sensitive['line_number']}")
    else:
        chain.append(f"Sensitive context detected: {', '.join(contexts[:4])}")
    return chain


def _trace_steps(
    dep: Dependency,
    vuln: VulnerabilityFinding | None,
    hygiene_risks: list[DependencyRiskFinding],
    usage: list[dict],
) -> list[RiskChainTraceStep]:
    steps: list[RiskChainTraceStep] = [
        RiskChainTraceStep(
            step=1,
            kind="manifest",
            label="Dependency declared",
            file_path=dep.manifest_path,
            details=[f"{dep.name} {dep.version or '(floating/unpinned)'}", dep.ecosystem, dep.scope],
        )
    ]

    step_number = 2
    if vuln:
        steps.append(
            RiskChainTraceStep(
                step=step_number,
                kind="risk",
                label="Known vulnerability matched",
                file_path=vuln.manifest_path,
                details=[vuln.id, vuln.summary],
            )
        )
        step_number += 1

    if hygiene_risks:
        risk = hygiene_risks[0]
        steps.append(
            RiskChainTraceStep(
                step=step_number,
                kind="risk",
                label="Dependency hygiene risk",
                file_path=risk.manifest_path,
                details=[risk.title, risk.description],
            )
        )
        step_number += 1

    for item in usage:
        for route in item["routes"][:3]:
            steps.append(
                RiskChainTraceStep(
                    step=step_number,
                    kind="route",
                    label=f"API entry point: {route['method']} {route['path']}",
                    file_path=item["path"],
                    line_number=route["line_number"],
                    code=route["code"],
                    details=[route["framework"], *item["contexts"]],
                )
            )
            step_number += 1

        steps.append(
            RiskChainTraceStep(
                step=step_number,
                kind="import",
                label="Imported or referenced by application code",
                file_path=item["path"],
                line_number=item["import_line"],
                code=item["import_code"],
                details=[*item["contexts"], *[f"alias:{alias}" for alias in item["import_aliases"]]],
            )
        )
        step_number += 1

        for sensitive_line in item["sensitive_lines"][:2]:
            steps.append(
                RiskChainTraceStep(
                    step=step_number,
                    kind="sensitive-use",
                    label=f"Sensitive code path: {', '.join(sensitive_line['contexts'][:3])}",
                    file_path=item["path"],
                    line_number=sensitive_line["line_number"],
                    code=sensitive_line["code"],
                    details=sensitive_line["contexts"],
                )
            )
            step_number += 1

    steps.append(
        RiskChainTraceStep(
            step=step_number,
            kind="fix",
            label="Priority remediation",
            details=["Upgrade vulnerable versions, pin floating ranges, or isolate this dependency before lower-impact packages."],
        )
    )
    return steps


def _dedupe_dependencies(dependencies: list[Dependency]) -> list[Dependency]:
    seen = set()
    unique = []
    for dep in dependencies:
        key = (dep.ecosystem, dep.name.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(dep)
    return unique
