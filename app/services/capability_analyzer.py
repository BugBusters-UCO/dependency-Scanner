from __future__ import annotations

import json
import re
from pathlib import Path

from app.schemas.scan import CapabilityFinding, FixSuggestion, Severity


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "target", "__pycache__", "vendor"}
SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".kt", ".go", ".rs", ".rb", ".php", ".cs", ".sh", ".ps1"}

CAPABILITY_RULES = [
    (
        "install-time-exec",
        Severity.high,
        re.compile(r"\b(preinstall|install|postinstall|prepare)\b", re.IGNORECASE),
        "Install-time script can execute during CI dependency installation",
        "Treat install-time code execution as a supply-chain execution point. In banking CI this can expose build secrets or signing tokens.",
    ),
    (
        "shell-exec",
        Severity.high,
        re.compile(r"\b(child_process|execSync|spawn\(|subprocess\.|os\.system|Runtime\.getRuntime|ProcessBuilder|shell_exec|popen|powershell|cmd\.exe)\b", re.IGNORECASE),
        "Code can execute shell or child processes",
        "Shell execution near dependency installation or sensitive flows can become credential theft, lateral movement, or build compromise.",
    ),
    (
        "network-download",
        Severity.medium,
        re.compile(r"\b(curl|wget|Invoke-WebRequest|fetch\(|axios\.|requests\.|urllib|http\.Get|net/http)\b", re.IGNORECASE),
        "Code can contact external network resources",
        "Unexpected outbound network calls can leak tokens, customer data, or fetch unreviewed binaries during builds.",
    ),
    (
        "credential-touch",
        Severity.high,
        re.compile(r"(\.ssh|\.npmrc|pypirc|id_rsa|GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET|AZURE_|GOOGLE_APPLICATION_CREDENTIALS|secret|private[_-]?key)", re.IGNORECASE),
        "Code references credential or secret material",
        "Credential-touching behavior inside dependency or build paths is high-risk for financial software supply chains.",
    ),
    (
        "binary-drop",
        Severity.medium,
        re.compile(r"\b(\.exe|\.dll|\.so|\.dylib|chmod\s+\+x|tar\s+-|unzip|base64\s+-d)\b", re.IGNORECASE),
        "Code can unpack, write, or execute binary artifacts",
        "Binary drops reduce reviewability and can hide malicious payloads before a CVE exists.",
    ),
    (
        "obfuscation",
        Severity.medium,
        re.compile(r"\b(eval\(|Function\(|atob\(|fromCharCode|base64|rot13|exec\(Buffer\.from)\b", re.IGNORECASE),
        "Code contains obfuscation or dynamic evaluation indicators",
        "Obfuscation makes dependency behavior harder to audit and is suspicious in bank-critical code paths.",
    ),
]


def analyze_capabilities(project_path: Path) -> list[CapabilityFinding]:
    findings: list[CapabilityFinding] = []
    findings.extend(_package_script_capabilities(project_path))
    findings.extend(_source_capabilities(project_path))
    return _dedupe(findings)[:100]


def _package_script_capabilities(project_path: Path) -> list[CapabilityFinding]:
    findings: list[CapabilityFinding] = []
    for manifest in project_path.rglob("package.json"):
        if _skip(manifest):
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            continue
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            continue
        for script_name, command in scripts.items():
            if script_name not in {"preinstall", "install", "postinstall", "prepare"}:
                continue
            text = f"{script_name}: {command}"
            for capability, severity, pattern, title, impact in CAPABILITY_RULES:
                if pattern.search(text):
                    findings.append(
                        _finding(
                            project_path,
                            manifest,
                            capability,
                            severity,
                            title,
                            f"npm lifecycle script `{script_name}` contains: {command}",
                            impact,
                            code=text,
                        )
                    )
    return findings


def _source_capabilities(project_path: Path) -> list[CapabilityFinding]:
    findings: list[CapabilityFinding] = []
    for path in project_path.rglob("*"):
        if _skip(path) or not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#")):
                continue
            for capability, severity, pattern, title, impact in CAPABILITY_RULES[1:]:
                if pattern.search(stripped):
                    findings.append(
                        _finding(
                            project_path,
                            path,
                            capability,
                            severity,
                            title,
                            f"Static capability fingerprint matched `{capability}`.",
                            impact,
                            line_number=line_number,
                            code=stripped[:220],
                        )
                    )
    return findings


def _finding(
    project_path: Path,
    path: Path,
    capability: str,
    severity: Severity,
    title: str,
    description: str,
    impact: str,
    line_number: int | None = None,
    code: str | None = None,
) -> CapabilityFinding:
    rel_path = str(path.relative_to(project_path))
    return CapabilityFinding(
        id=f"capability:{capability}:{rel_path}:{line_number or 0}",
        capability=capability,
        severity=severity,
        title=title,
        description=description,
        file_path=rel_path,
        line_number=line_number,
        code=code,
        banking_impact=impact,
        fix=FixSuggestion(
            title="Review suspicious dependency capability",
            description="Require owner approval, pin the dependency, sandbox install steps, or block install-time/network/shell behavior in CI.",
            command="npm ci --ignore-scripts",
            auto_remediable=False,
        ),
    )


def _skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _dedupe(findings: list[CapabilityFinding]) -> list[CapabilityFinding]:
    seen = set()
    unique: list[CapabilityFinding] = []
    for finding in findings:
        key = (finding.capability, finding.file_path, finding.line_number, finding.code)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return sorted(unique, key=lambda item: 2 if item.severity == Severity.high else 1, reverse=True)
