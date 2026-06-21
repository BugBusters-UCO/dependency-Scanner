from __future__ import annotations

import json
import re
from pathlib import Path

from app.schemas.scan import Dependency, DependencyRiskFinding, FixSuggestion, ManifestReport, Severity


FLOATING_VERSION_RE = re.compile(r"(^|\s)(latest|\*|x|X)(\s|$)")
RANGE_VERSION_RE = re.compile(r"^\s*(\^|~|>=|>|<=|<|!=)")
INSTALL_SCRIPT_KEYS = {"preinstall", "install", "postinstall", "prepare"}


def analyze_dependency_risks(
    project_path: Path,
    manifests: list[ManifestReport],
    dependencies: list[Dependency],
) -> list[DependencyRiskFinding]:
    risks: list[DependencyRiskFinding] = []
    manifest_paths = {Path(item.path) for item in manifests}
    manifest_names = {path.name for path in manifest_paths}

    for dep in dependencies:
        risks.extend(_dependency_hygiene_risks(dep))

    risks.extend(_lockfile_risks(project_path, manifest_names))
    risks.extend(_npm_lifecycle_script_risks(manifest_paths))
    return risks


def _dependency_hygiene_risks(dep: Dependency) -> list[DependencyRiskFinding]:
    risks: list[DependencyRiskFinding] = []
    if not dep.version:
        risks.append(
            _risk(
                dep,
                Severity.medium,
                "dependency-versioning",
                "Dependency is not pinned",
                f"{dep.name} does not have an exact resolved version, so builds may drift between releases.",
                "Pin this dependency through a lockfile or exact version.",
            )
        )
        return risks

    version = dep.version.strip()
    if FLOATING_VERSION_RE.search(version) or version.lower() == "latest":
        risks.append(
            _risk(
                dep,
                Severity.high,
                "dependency-versioning",
                "Floating dependency version",
                f"{dep.name} uses a floating version ({version}), which can pull unreviewed code into banking builds.",
                "Replace floating versions with exact approved versions.",
            )
        )
    elif RANGE_VERSION_RE.match(version):
        risks.append(
            _risk(
                dep,
                Severity.medium,
                "dependency-versioning",
                "Version range allows drift",
                f"{dep.name} uses a range ({version}); dependency updates can enter without review.",
                "Use a lockfile and review dependency updates through CI.",
            )
        )

    if dep.ecosystem == "Docker" and version in {"latest", "stable", "edge", "alpine"}:
        risks.append(
            _risk(
                dep,
                Severity.high,
                "container-base-image",
                "Mutable Docker base image tag",
                f"{dep.name}:{version} is mutable and can change without a code change.",
                "Pin Docker images by immutable digest or approved release tag.",
            )
        )
    return risks


def _lockfile_risks(project_path: Path, manifest_names: set[str]) -> list[DependencyRiskFinding]:
    risks: list[DependencyRiskFinding] = []
    checks = [
        ("package.json", {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}, "JavaScript project has no lockfile"),
        ("pyproject.toml", {"poetry.lock", "Pipfile.lock"}, "Python project may be missing a lockfile"),
        ("Gemfile", {"Gemfile.lock"}, "Ruby project has no Gemfile.lock"),
        ("composer.json", {"composer.lock"}, "PHP project has no composer.lock"),
        ("Cargo.toml", {"Cargo.lock"}, "Rust project has no Cargo.lock"),
    ]
    for manifest, locks, title in checks:
        if manifest in manifest_names and not (manifest_names & locks):
            risks.append(
                DependencyRiskFinding(
                    id=f"missing-lockfile:{manifest}",
                    dependency_name=None,
                    manifest_path=str(project_path / manifest),
                    severity=Severity.medium,
                    category="dependency-locking",
                    title=title,
                    description="Missing lockfiles reduce reproducibility and make supply-chain review harder.",
                    fix=FixSuggestion(
                        title="Commit a dependency lockfile",
                        description="Generate and commit the package manager lockfile, then enforce it in CI.",
                        auto_remediable=False,
                    ),
                )
            )
    return risks


def _npm_lifecycle_script_risks(manifest_paths: set[Path]) -> list[DependencyRiskFinding]:
    risks: list[DependencyRiskFinding] = []
    for manifest in manifest_paths:
        if manifest.name != "package.json":
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            continue
        scripts = data.get("scripts", {})
        for script_name in sorted(INSTALL_SCRIPT_KEYS & set(scripts)):
            risks.append(
                DependencyRiskFinding(
                    id=f"npm-lifecycle-script:{manifest}:{script_name}",
                    dependency_name=None,
                    manifest_path=str(manifest),
                    severity=Severity.medium,
                    category="install-time-code-execution",
                    title=f"npm lifecycle script `{script_name}` runs during install",
                    description="Install-time scripts can execute arbitrary code during CI/CD dependency installation.",
                    fix=FixSuggestion(
                        title="Review install-time script",
                        description="Remove the lifecycle script if possible, or enforce npm ci --ignore-scripts for scanner jobs.",
                        command="npm ci --ignore-scripts",
                        auto_remediable=False,
                    ),
                )
            )
    return risks


def _risk(
    dep: Dependency,
    severity: Severity,
    category: str,
    title: str,
    description: str,
    fix_description: str,
) -> DependencyRiskFinding:
    return DependencyRiskFinding(
        id=f"{category}:{dep.ecosystem}:{dep.name}:{dep.manifest_path}",
        dependency_name=dep.name,
        manifest_path=dep.manifest_path,
        severity=severity,
        category=category,
        title=title,
        description=description,
        fix=FixSuggestion(title="Harden dependency declaration", description=fix_description, auto_remediable=False),
    )
