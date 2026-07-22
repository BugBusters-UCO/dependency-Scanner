`from __future__ import annotations
import os
import asyncio
import json
from pathlib import Path
import logging

from collections.abc import Iterable

logger = logging.getLogger(__name__)

import httpx

from app.schemas.scan import Dependency, Severity, VulnerabilityFinding, FixSuggestion


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_ECOSYSTEMS = {"npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "Packagist", "NuGet"}
SEVERITY_ORDER = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.unknown: 1,
}


class OSVClient:
    def __init__(self, timeout_seconds: float = 20.0) -> None:
        self.timeout_seconds = timeout_seconds
        self.mode = os.getenv("SCANNER_ADVISORY_MODE", "manual").lower()
        self.offline = os.getenv("SCANNER_OFFLINE_MODE", "true").lower() == "true"
        self.allow_external = self.mode == "auto" and os.getenv("SCANNER_ALLOW_EXTERNAL_ADVISORIES", "false").lower() == "true" and not self.offline
        self.local_path = Path(os.getenv("SCANNER_ADVISORY_DB_PATH", "/var/lib/bugbusters/advisories.json"))
        self.last_status = "local_snapshot_not_found"

    def status(self) -> str:
        return self.last_status

    async def query(self, dependencies: Iterable[Dependency]) -> list[VulnerabilityFinding]:
        pinned = [dep for dep in dependencies if dep.version and dep.ecosystem in OSV_ECOSYSTEMS]
        if not pinned:
            self.last_status = "no_pinned_dependencies"
            return []

        local_findings = self._query_local(pinned)
        if self.mode in {"manual", "internal", "offline"} or self.offline or not self.allow_external:
            self.last_status = "local_snapshot" if self._local_exists() else "local_snapshot_missing"
            logger.info(f"OSVClient is in offline/manual mode (mode={self.mode}, offline={self.offline}). Returning {len(local_findings)} local findings. Status: {self.last_status}")
            return local_findings

        queries = [
            {
                "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                "version": dep.version,
            }
            for dep in pinned
        ]

        findings: list[VulnerabilityFinding] = []
        batch_size = 100

        async def fetch_batch(client: httpx.AsyncClient, batch_queries: list[dict], batch_pinned: list[Dependency]) -> None:
            response = await client.post(OSV_BATCH_URL, json={"queries": batch_queries})
            response.raise_for_status()
            payload = response.json()
            for dep, result in zip(batch_pinned, payload.get("results", []), strict=False):
                for vuln in result.get("vulns", []):
                    findings.append(_to_finding(dep, vuln))

        try:
            logger.info(f"OSVClient querying external batch API for {len(pinned)} dependencies...")
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                tasks = []
                for i in range(0, len(queries), batch_size):
                    tasks.append(fetch_batch(client, queries[i : i + batch_size], pinned[i : i + batch_size]))
                for i in range(0, len(tasks), 5): await asyncio.gather(*tasks[i:i+5])
            self.last_status = "osv_auto"
            logger.info(f"OSVClient external batch API returned {len(findings)} findings.")
            return findings
        except httpx.HTTPError as exc:
            self.last_status = "osv_auto_failed_using_local_snapshot" if self._local_exists() else "osv_auto_failed_no_local_snapshot"
            logger.error(f"OSVClient HTTPError querying external API: {exc}. Returning {len(local_findings)} local findings.")
            return local_findings

    def _local_exists(self) -> bool:
        return self.local_path.is_file()

    def _query_local(self, dependencies: list[Dependency]) -> list[VulnerabilityFinding]:
        if not self._local_exists(): return []
        try:
            payload = json.loads(self.local_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        records = payload if isinstance(payload, list) else payload.get("advisories", payload.get("vulnerabilities", []))
        findings=[]
        for dep in dependencies:
            for vuln in records if isinstance(records, list) else []:
                if _advisory_matches(vuln, dep): findings.append(_to_finding(dep, vuln))
        return _dedupe_findings(findings)


def _to_finding(dep: Dependency, vuln: dict) -> VulnerabilityFinding:
    fixed_versions = _fixed_versions(vuln)
    severity = _severity(vuln)
    target_version = fixed_versions[0] if fixed_versions else None
    return VulnerabilityFinding(
        id=vuln.get("id", "UNKNOWN"),
        package_name=dep.name,
        installed_version=dep.version,
        ecosystem=dep.ecosystem,
        severity=severity,
        summary=vuln.get("summary") or vuln.get("details") or "Known vulnerability reported by OSV.",
        details_url=_details_url(vuln),
        aliases=vuln.get("aliases", []),
        fixed_versions=fixed_versions,
        manifest_path=dep.manifest_path,
        fix=FixSuggestion(
            title=f"Upgrade {dep.name}",
            description=_fix_description(dep, target_version),
            command=_fix_command(dep, target_version),
            target_version=target_version,
            auto_remediable=target_version is not None,
        ),
    )


def _severity(vuln: dict) -> Severity:
    severities: list[Severity] = []

    database_specific = vuln.get("database_specific", {})
    raw = str(database_specific.get("severity", "")).lower()
    if raw in Severity._value2member_map_:
        severities.append(Severity(raw))

    for item in vuln.get("severity", []):
        score = str(item.get("score", "")).upper()
        if score.startswith("CVSS:"):
            severities.append(_cvss_vector_to_severity(score))

    if not severities:
        return Severity.unknown
    return max(severities, key=lambda item: SEVERITY_ORDER[item])


def _cvss_vector_to_severity(vector: str) -> Severity:
    if "/AV:N" in vector and "/PR:N" in vector and "/UI:N" in vector:
        return Severity.critical
    if "/AV:N" in vector:
        return Severity.high
    return Severity.medium


def _fixed_versions(vuln: dict) -> list[str]:
    versions: list[str] = [str(value) for value in vuln.get("fixedVersions", []) if value]
    for affected in vuln.get("affected", []):
        for range_data in affected.get("ranges", []):
            for event in range_data.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed not in versions:
                    versions.append(fixed)
    return versions


def _details_url(vuln: dict) -> str | None:
    references = vuln.get("references", [])
    for reference in references:
        url = reference.get("url")
        if url:
            return url
    vuln_id = vuln.get("id")
    return f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else None


def _fix_description(dep: Dependency, target_version: str | None) -> str:
    if target_version:
        return f"Update {dep.name} from {dep.version} to {target_version} or newer."
    return f"Review {dep.name} and upgrade to a non-vulnerable version recommended by the maintainer."


def _fix_command(dep: Dependency, target_version: str | None) -> str | None:
    if not target_version:
        return None
    if dep.ecosystem == "npm":
        return f"npm install {dep.name}@{target_version}"
    if dep.ecosystem == "PyPI":
        return f"pip install --upgrade {dep.name}=={target_version}"
    if dep.ecosystem == "Maven":
        return f"Set {dep.name} version to {target_version} in the Maven/Gradle manifest."
    return None


def _advisory_matches(vuln: dict, dep: Dependency) -> bool:
    affected = vuln.get("affected", []) or []
    top_package = vuln.get("package") or {}
    if top_package and top_package.get("name"):
        affected = [*affected, {"package": top_package, "versions": vuln.get("versions", [])}]
    for item in affected:
        package = item.get("package", {}) if isinstance(item, dict) else {}
        name = package.get("name") or item.get("packageName") or item.get("name")
        ecosystem = package.get("ecosystem") or item.get("ecosystem")
        if name and str(name).lower() != dep.name.lower(): continue
        if ecosystem and str(ecosystem).lower() not in {dep.ecosystem.lower(), "pypi" if dep.ecosystem == "PyPI" else dep.ecosystem.lower()}: continue
        versions = item.get("versions", []) or []
        if dep.version in versions: return True
        for range_data in item.get("ranges", []) or []:
            events = range_data.get("events", [])
            introduced = "0"
            fixed = None
            for event in events:
                if event.get("introduced") is not None: introduced = str(event["introduced"])
                if event.get("fixed") is not None: fixed = str(event["fixed"])
            if _version_gte(dep.version, introduced) and (not fixed or _version_lt(dep.version, fixed)): return True
        if not versions and not item.get("ranges") and name: return True
    return False


def _version_parts(value: str) -> tuple:
    values=[]
    for part in str(value).lstrip("v").split("."):
        digits="".join(char for char in part if char.isdigit())
        values.append(int(digits or 0))
    return tuple((values + [0, 0, 0])[:3])


def _version_gte(left: str, right: str) -> bool: return _version_parts(left) >= _version_parts(right)
def _version_lt(left: str, right: str) -> bool: return _version_parts(left) < _version_parts(right)


def _dedupe_findings(findings):
    seen=set(); result=[]
    for finding in findings:
        key=(finding.id, finding.package_name, finding.installed_version)
        if key in seen: continue
        seen.add(key); result.append(finding)
    return result
