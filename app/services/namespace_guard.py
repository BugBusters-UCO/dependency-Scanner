from __future__ import annotations

import json
import re
from pathlib import Path

from app.schemas.scan import Dependency, FixSuggestion, NamespaceRiskFinding, Severity


INTERNAL_HINTS = ("internal", "private", "bank", "core", "auth", "payment", "kyc", "ledger", "uco")
REGISTRY_FILES = {
    ".npmrc",
    "pip.conf",
    "pip.ini",
    "poetry.toml",
    "NuGet.Config",
    "settings.xml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Dockerfile",
}


def analyze_namespace_risks(project_path: Path, dependencies: list[Dependency]) -> list[NamespaceRiskFinding]:
    findings: list[NamespaceRiskFinding] = []
    registry_files = _registry_files(project_path)
    findings.extend(_registry_fallback_risks(project_path, registry_files))
    findings.extend(_unscoped_internal_name_risks(project_path, dependencies))
    findings.extend(_git_mutable_reference_risks(project_path))
    return _dedupe(findings)[:100]


def _registry_files(project_path: Path) -> list[Path]:
    files: list[Path] = []
    for path in project_path.rglob("*"):
        if any(part in {".git", "node_modules", ".venv", "venv", "dist", "build", "target", "vendor"} for part in path.parts):
            continue
        if path.is_file() and path.name in REGISTRY_FILES:
            files.append(path)
    return files


def _registry_fallback_risks(project_path: Path, files: list[Path]) -> list[NamespaceRiskFinding]:
    risks: list[NamespaceRiskFinding] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lower = text.lower()
        evidence = []
        if path.name == ".npmrc":
            if "registry=https://registry.npmjs.org" in lower or "registry=http://registry.npmjs.org" in lower:
                evidence.append("npm public registry fallback is configured")
            if "always-auth=true" not in lower and "@" in lower:
                evidence.append("always-auth is not enforced for npm registry access")
        elif path.name in {"pip.conf", "pip.ini"}:
            if "extra-index-url" in lower:
                evidence.append("pip extra-index-url can enable dependency confusion fallback")
            if "pypi.org" in lower:
                evidence.append("public PyPI index appears in dependency resolution")
        elif path.name == "NuGet.Config":
            if "nuget.org" in lower:
                evidence.append("nuget.org source is enabled alongside configured feeds")
        elif path.name in {"pom.xml", "settings.xml", "build.gradle", "build.gradle.kts"}:
            if "mavencentral" in lower or "repo.maven.apache.org" in lower or "mavenCentral()" in text:
                evidence.append("Maven Central is enabled in dependency resolution")
        if evidence:
            risks.append(
                _risk(
                    project_path,
                    path,
                    Severity.medium,
                    "registry-fallback",
                    "Registry fallback can enable dependency confusion",
                    "Public registry fallback is present. Internal packages should be scoped and resolved only from approved private feeds.",
                    evidence,
                )
            )
    return risks


def _unscoped_internal_name_risks(project_path: Path, dependencies: list[Dependency]) -> list[NamespaceRiskFinding]:
    risks: list[NamespaceRiskFinding] = []
    for dep in dependencies:
        name = dep.name.lower()
        if dep.ecosystem != "npm":
            continue
        if dep.name.startswith("@"):
            continue
        if any(hint in name for hint in INTERNAL_HINTS):
            risks.append(
                NamespaceRiskFinding(
                    id=f"namespace-confusion:{dep.name}:{dep.manifest_path}",
                    severity=Severity.high,
                    category="namespace-confusion",
                    title="Internal-looking npm package is unscoped",
                    description=f"{dep.name} looks like an internal banking package but is not protected by an npm scope.",
                    file_path=_rel(project_path, dep.manifest_path),
                    dependency_name=dep.name,
                    evidence=["Unscoped package name", f"Internal naming hint matched in `{dep.name}`"],
                    banking_impact="A public package with the same name could be resolved in CI or developer machines if registry rules drift.",
                    fix=FixSuggestion(
                        title="Enforce private package namespace",
                        description="Move internal packages under an approved npm scope, enforce always-auth, and block public fallback for private scopes.",
                        auto_remediable=False,
                    ),
                )
            )
    return risks


def _git_mutable_reference_risks(project_path: Path) -> list[NamespaceRiskFinding]:
    risks: list[NamespaceRiskFinding] = []
    for manifest in project_path.rglob("package.json"):
        if any(part in {".git", "node_modules", "dist", "build"} for part in manifest.parts):
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            continue
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(data.get(key), dict):
                deps.update(data[key])
        for name, value in deps.items():
            if isinstance(value, str) and ("github:" in value or value.startswith("git+")) and not re.search(r"#[0-9a-f]{12,40}$", value):
                risks.append(
                    NamespaceRiskFinding(
                        id=f"mutable-git-dependency:{name}:{manifest}",
                        severity=Severity.medium,
                        category="mutable-git-reference",
                        title="Git dependency is not pinned to an immutable commit",
                        description=f"{name} uses mutable Git reference `{value}`.",
                        file_path=str(manifest.relative_to(project_path)),
                        dependency_name=name,
                        evidence=[value],
                        banking_impact="Mutable Git dependencies can change without manifest review, weakening auditability for regulated builds.",
                        fix=FixSuggestion(
                            title="Pin Git dependency by commit",
                            description="Replace branch or tag references with an approved immutable commit SHA.",
                            auto_remediable=False,
                        ),
                    )
                )
    return risks


def _risk(
    project_path: Path,
    path: Path,
    severity: Severity,
    category: str,
    title: str,
    description: str,
    evidence: list[str],
) -> NamespaceRiskFinding:
    return NamespaceRiskFinding(
        id=f"{category}:{path}",
        severity=severity,
        category=category,
        title=title,
        description=description,
        file_path=str(path.relative_to(project_path)),
        evidence=evidence,
        banking_impact="Registry ambiguity can let untrusted public packages enter private banking builds.",
        fix=FixSuggestion(
            title="Harden registry resolution",
            description="Enforce scoped private registries, disable public fallback for internal packages, and require authenticated registry access in CI.",
            auto_remediable=False,
        ),
    )


def _rel(project_path: Path, raw_path: str) -> str:
    try:
        return str(Path(raw_path).resolve().relative_to(project_path))
    except (OSError, ValueError):
        return raw_path


def _dedupe(findings: list[NamespaceRiskFinding]) -> list[NamespaceRiskFinding]:
    seen = set()
    unique: list[NamespaceRiskFinding] = []
    for finding in findings:
        key = (finding.category, finding.file_path, finding.dependency_name)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return sorted(unique, key=lambda item: 2 if item.severity == Severity.high else 1, reverse=True)
