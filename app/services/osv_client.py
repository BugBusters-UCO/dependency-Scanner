from __future__ import annotations
import asyncio

from collections.abc import Iterable

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

    async def query(self, dependencies: Iterable[Dependency]) -> list[VulnerabilityFinding]:
        pinned = [dep for dep in dependencies if dep.version and dep.ecosystem in OSV_ECOSYSTEMS]
        if not pinned:
            return []

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

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            tasks = []
            for i in range(0, len(queries), batch_size):
                batch_queries = queries[i : i + batch_size]
                batch_pinned = pinned[i : i + batch_size]
                tasks.append(fetch_batch(client, batch_queries, batch_pinned))
            
            # Run concurrently in chunks of 5 to avoid overwhelming the OSV API
            concurrency = 5
            for i in range(0, len(tasks), concurrency):
                await asyncio.gather(*tasks[i:i+concurrency])

        return findings


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
    versions: list[str] = []
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
