from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app.schemas.scan import FixSuggestion, PackageIntelligenceFinding, Severity, Dependency

POPULAR_DEFAULT = {"express", "lodash", "axios", "react", "requests", "django", "flask", "numpy", "pytest", "urllib3"}


async def analyze_package_intelligence(dependencies: list[Dependency]) -> tuple[list[PackageIntelligenceFinding], dict]:
    findings: list[PackageIntelligenceFinding] = []
    enabled = os.getenv("SCANNER_PACKAGE_INTELLIGENCE_ENABLED", "false").lower() == "true"
    if os.getenv("SCANNER_OFFLINE_MODE", "true").lower() == "true":
        enabled = False
    popular = _popular_names()
    for dep in dependencies:
        findings.extend(_local_rules(dep, popular))
    status = {"enabled": enabled, "packagesInspected": len(dependencies), "registryLookups": 0, "mode": "local_and_allowlisted_registry"}
    if not enabled:
        status["registry"] = "disabled_offline_mode" if os.getenv("SCANNER_OFFLINE_MODE", "true").lower() == "true" else "disabled"
        return _dedupe(findings), status

    timeout = float(os.getenv("SCANNER_PACKAGE_INTELLIGENCE_TIMEOUT_SECONDS", "8"))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        tasks = [_lookup_registry(client, dep) for dep in dependencies if dep.version]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            status["registryLookups"] += 1
            continue
        status["registryLookups"] += 1
        findings.extend(result)
    status["registry"] = "queried"
    return _dedupe(findings), status


def _local_rules(dep: Dependency, popular: set[str]) -> list[PackageIntelligenceFinding]:
    name = dep.name.lower()
    result: list[PackageIntelligenceFinding] = []
    internal_markers = tuple(x.strip().lower() for x in os.getenv("PACKAGE_INTELLIGENCE_INTERNAL_MARKERS", "bank,banking,internal,corp,company,private,uco,sbi").split(",") if x.strip())
    if any(marker in name for marker in internal_markers) and not name.startswith("@"):
        result.append(_finding(dep, "dependency-confusion", Severity.high, "Public package name resembles an internal dependency.", "Use the bank's internal registry and namespace ownership controls; do not resolve this name directly from a public registry."))
    for trusted in popular:
        if name != trusted and _distance(name, trusted) <= 1:
            result.append(_finding(dep, "typosquatting", Severity.high, f"Package name is suspiciously similar to {trusted}.", "Confirm the package owner, source repository, provenance and intended dependency before approval."))
    if dep.version and (dep.version.startswith("0.") or dep.version in {"latest", "*"}):
        result.append(_finding(dep, "unbounded-or-early-version", Severity.medium, "Dependency uses an early or unbounded version pattern.", "Pin an approved version and lock the resolved artifact digest."))
    return result


async def _lookup_registry(client: httpx.AsyncClient, dep: Dependency) -> list[PackageIntelligenceFinding]:
    url = _registry_url(dep)
    if not url:
        return []
    response = await client.get(url, headers={"accept": "application/json"})
    if response.status_code >= 400:
        return [_finding(dep, "registry-lookup-failed", Severity.medium, "Approved registry metadata could not be retrieved.", f"Registry returned HTTP {response.status_code}; verify mirror availability before relying on reputation data.")]
    payload = response.json()
    findings: list[PackageIntelligenceFinding] = []
    published = _published_at(payload, dep)
    if published and (datetime.now(timezone.utc) - published).days < int(os.getenv("PACKAGE_INTELLIGENCE_NEW_PACKAGE_DAYS", "30")):
        findings.append(_finding(dep, "recent-release", Severity.medium, "Dependency version was published recently.", "Require provenance, source review and staged approval for newly published versions."))
    maintainers = _maintainer_count(payload)
    baseline = _baseline().get(_key(dep))
    if baseline and maintainers and baseline.get("maintainerCount") and maintainers != baseline["maintainerCount"]:
        findings.append(_finding(dep, "maintainer-change", Severity.high, "Maintainer metadata changed from the recorded baseline.", "Review ownership, MFA, release provenance and package contents before promotion."))
    if not _has_provenance(payload):
        findings.append(_finding(dep, "provenance-missing", Severity.low, "Registry metadata does not expose trusted provenance for this version.", "Prefer signed, internally mirrored artifacts with source-to-build provenance."))
    return findings


def _registry_url(dep: Dependency) -> str | None:
    if dep.ecosystem == "npm":
        return f"https://registry.npmjs.org/{dep.name.replace('/', '%2F')}"
    if dep.ecosystem == "PyPI":
        return f"https://pypi.org/pypi/{dep.name}/json"
    return None


def _published_at(payload: dict, dep: Dependency):
    try:
        if dep.ecosystem == "npm":
            value = payload.get("time", {}).get(dep.version)
        else:
            value = (payload.get("releases", {}).get(dep.version) or [{}])[0].get("upload_time_iso_8601")
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except (AttributeError, TypeError, ValueError):
        return None


def _maintainer_count(payload: dict) -> int:
    maintainers = payload.get("maintainers") or payload.get("info", {}).get("maintainers") or []
    return len(maintainers) if isinstance(maintainers, list) else 0


def _has_provenance(payload: dict) -> bool:
    dist = payload.get("dist") or {}
    info = payload.get("info") or {}
    return bool(dist.get("integrity") or dist.get("provenance") or info.get("project_urls", {}).get("Provenance"))


def _baseline() -> dict:
    path = os.getenv("PACKAGE_INTELLIGENCE_BASELINE_PATH")
    if not path or not Path(path).is_file(): return {}
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): return {}


def _key(dep): return f"{dep.ecosystem}:{dep.name}@{dep.version}"


def _popular_names() -> set[str]:
    return {x.strip().lower() for x in os.getenv("PACKAGE_INTELLIGENCE_POPULAR_NAMES", ",".join(POPULAR_DEFAULT)).split(",") if x.strip()}


def _distance(a: str, b: str) -> int:
    if abs(len(a)-len(b)) > 1: return 99
    row=list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        new=[i]
        for j, cb in enumerate(b, 1): new.append(min(new[-1]+1, row[j]+1, row[j-1]+(ca != cb)))
        row=new
    return row[-1]


def _finding(dep, rule_id, severity, title, description):
    return PackageIntelligenceFinding(id=f"package:{rule_id}:{dep.ecosystem}:{dep.name}:{dep.version}", rule_id=rule_id, package_name=dep.name, version=dep.version, ecosystem=dep.ecosystem, severity=severity, title=title, description=description, manifest_path=dep.manifest_path, evidence={"package": dep.name, "version": dep.version}, fix=FixSuggestion(title="Review package trust and provenance", description=description, auto_remediable=False))


def _dedupe(findings):
    seen=set(); result=[]
    for finding in findings:
        if finding.id in seen: continue
        seen.add(finding.id); result.append(finding)
    return result[:500]
