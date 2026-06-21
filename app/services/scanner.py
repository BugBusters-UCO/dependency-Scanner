from __future__ import annotations

import os
import uuid
from pathlib import Path

import httpx

from app.schemas.scan import (
    CapabilityFinding,
    Dependency,
    ManifestReport,
    NamespaceRiskFinding,
    ScanRequest,
    ScanResponse,
    ScanSummary,
    Severity,
    DependencyRiskFinding,
    RiskChainFinding,
    VulnerabilityFinding,
)
from app.services.blast_radius_analyzer import analyze_blast_radius
from app.services.capability_analyzer import analyze_capabilities
from app.services.exposure_scorer import aggregate_exposure, apply_banking_exposure_scores
from app.services.manifest_discovery import discover_manifests
from app.services.namespace_guard import analyze_namespace_risks
from app.services.osv_client import OSVClient, SEVERITY_ORDER
from app.services.parsers import parse_manifest
from app.services.risk_analyzer import analyze_dependency_risks


class ScanError(Exception):
    """Raised when a scan request cannot be completed."""


class DependencyScanner:
    def __init__(self) -> None:
        self.osv_client = OSVClient()

    async def scan(self, request: ScanRequest) -> ScanResponse:
        project_path = _resolve_project_path(request.project_path)
        manifests = discover_manifests(project_path, request.max_depth)

        manifest_reports: list[ManifestReport] = []
        dependencies: list[Dependency] = []

        for manifest in manifests:
            parsed = parse_manifest(manifest, request.include_dev)
            dependencies.extend(parsed)
            manifest_reports.append(
                ManifestReport(
                    path=str(manifest),
                    type=manifest.name,
                    dependency_count=len(parsed),
                )
            )

        findings: list[VulnerabilityFinding] = []
        if request.use_osv and dependencies:
            try:
                findings = await self.osv_client.query(_dedupe_dependencies(dependencies))
            except httpx.HTTPError as exc:
                raise ScanError(f"OSV vulnerability lookup failed: {exc}") from exc

        dependency_risks = analyze_dependency_risks(project_path, manifest_reports, dependencies)
        capability_findings = analyze_capabilities(project_path)
        namespace_risks = analyze_namespace_risks(project_path, dependencies)
        risk_chains = analyze_blast_radius(project_path, dependencies, findings, dependency_risks)
        apply_banking_exposure_scores(risk_chains, findings, dependency_risks, capability_findings, namespace_risks)
        summary = _summary(
            manifest_reports,
            dependencies,
            findings,
            dependency_risks,
            capability_findings,
            namespace_risks,
            risk_chains,
            request.fail_on,
        )
        return ScanResponse(
            scan_id=str(uuid.uuid4()),
            project_path=str(project_path),
            manifests=manifest_reports,
            dependencies=dependencies,
            findings=sorted(findings, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True),
            dependency_risks=sorted(dependency_risks, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True),
            capability_findings=sorted(capability_findings, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True),
            namespace_risks=sorted(namespace_risks, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True),
            risk_chains=risk_chains,
            summary=summary,
        )


def _resolve_project_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser().resolve()
    if not path.exists():
        raise ScanError(f"Project path does not exist: {path}")
    if not path.is_dir():
        raise ScanError(f"Project path must be a directory: {path}")

    workspace_root = os.getenv("SCANNER_WORKSPACE_ROOT")
    if workspace_root:
        root = Path(workspace_root).expanduser().resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ScanError(f"Project path must be inside SCANNER_WORKSPACE_ROOT: {root}") from exc
    return path


def _dedupe_dependencies(dependencies: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str | None, str]] = set()
    unique: list[Dependency] = []
    for dep in dependencies:
        key = (dep.ecosystem, dep.version, dep.name.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(dep)
    return unique


def _summary(
    manifests: list[ManifestReport],
    dependencies: list[Dependency],
    findings: list[VulnerabilityFinding],
    dependency_risks: list[DependencyRiskFinding],
    capability_findings: list[CapabilityFinding],
    namespace_risks: list[NamespaceRiskFinding],
    risk_chains: list[RiskChainFinding],
    fail_on: Severity,
) -> ScanSummary:
    counts = {severity.value: 0 for severity in Severity}
    vulnerable_packages: set[tuple[str, str]] = set()

    for finding in findings:
        counts[finding.severity.value] += 1
        vulnerable_packages.add((finding.ecosystem, finding.package_name.lower()))

    for risk in dependency_risks:
        counts[risk.severity.value] += 1

    for finding in capability_findings:
        counts[finding.severity.value] += 1

    for risk in namespace_risks:
        counts[risk.severity.value] += 1

    for chain in risk_chains:
        counts[chain.severity.value] += 1

    risk_score = min(
        100,
        counts[Severity.critical.value] * 25
        + counts[Severity.high.value] * 15
        + counts[Severity.medium.value] * 8
        + counts[Severity.low.value] * 3
        + counts[Severity.unknown.value],
    )

    failed = any(SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[fail_on] for finding in findings) or any(
        SEVERITY_ORDER[risk.severity] >= SEVERITY_ORDER[fail_on] for risk in dependency_risks
    ) or any(
        SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[fail_on] for finding in capability_findings
    ) or any(
        SEVERITY_ORDER[risk.severity] >= SEVERITY_ORDER[fail_on] for risk in namespace_risks
    ) or any(
        SEVERITY_ORDER[chain.severity] >= SEVERITY_ORDER[fail_on] for chain in risk_chains
    )
    exposure = aggregate_exposure(risk_chains)
    return ScanSummary(
        total_manifests=len(manifests),
        total_dependencies=len(dependencies),
        vulnerable_dependencies=len(vulnerable_packages),
        dependency_risk_findings=len(dependency_risks),
        capability_findings=len(capability_findings),
        namespace_risks=len(namespace_risks),
        risk_chains=len(risk_chains),
        banking_exposure_score=exposure.score,
        banking_action=exposure.action,
        findings_by_severity=counts,
        risk_score=risk_score,
        ci_status="failed" if failed else "passed",
        fail_on=fail_on,
    )
