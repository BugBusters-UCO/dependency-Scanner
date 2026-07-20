from __future__ import annotations

import os
import uuid
from pathlib import Path

import httpx

from app.schemas.scan import (
    CapabilityFinding,
    BehaviorFinding,
    PackageIntelligenceFinding,
    Dependency,
    ManifestReport,
    NamespaceRiskFinding,
    ScanRequest,
    ScanResponse,
    SinglePackageScanRequest,
    SinglePackageScanResponse,
    ScanSummary,
    Severity,
    DependencyRiskFinding,
    RiskChainFinding,
    StaticMalwareFinding,
    VulnerabilityFinding,
)
from app.services.blast_radius_analyzer import analyze_blast_radius
from app.services.artifact_integrity import build_artifact_metadata
from app.services.capability_analyzer import analyze_capabilities
from app.services.exposure_scorer import aggregate_exposure, apply_banking_exposure_scores
from app.services.manifest_discovery import discover_manifests
from app.services.namespace_guard import analyze_namespace_risks
from app.services.osv_client import OSVClient, SEVERITY_ORDER
from app.services.parsers import parse_manifest
from app.services.risk_analyzer import analyze_dependency_risks
from app.services.static_malware_scanner import scan_static_malware
from app.services.sandbox_service import run_in_sandbox
from app.services.behavior_monitor import analyze_behavior
from app.services.security_policy import validate_startup_policy
from app.services.package_intelligence import analyze_package_intelligence


class ScanError(Exception):
    """Raised when a scan request cannot be completed."""


class DependencyScanner:
    def __init__(self) -> None:
        self.osv_client = OSVClient()

    async def scan_single(self, request: SinglePackageScanRequest) -> SinglePackageScanResponse:
        dep = Dependency(name=request.name, version=request.version, ecosystem=request.ecosystem, manifest_path="proxy")
        try:
            findings = await self.osv_client.query([dep])
        except httpx.HTTPError as exc:
            raise ScanError(f"OSV vulnerability lookup failed: {exc}") from exc
        
        is_malicious = False
        if findings:
            for finding in findings:
                if SEVERITY_ORDER.get(finding.severity, 0) >= SEVERITY_ORDER.get(Severity.high, 0):
                    is_malicious = True
                    break

        return SinglePackageScanResponse(
            isMalicious=is_malicious,
            findings=sorted(findings, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)
        )

    async def scan(self, request: ScanRequest) -> ScanResponse:
        validate_startup_policy()
        project_path = _resolve_project_path(request.project_path)
        manifests = discover_manifests(project_path, request.max_depth)
        artifact = build_artifact_metadata(project_path, manifests)

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
        static_malware_findings, static_malware_status = scan_static_malware(project_path)
        sandbox = run_in_sandbox(project_path, request.sandbox)
        behavior_findings, behavior_status = analyze_behavior(sandbox)
        package_intelligence_findings, package_intelligence_status = await analyze_package_intelligence(dependencies)
        namespace_risks = analyze_namespace_risks(project_path, dependencies)
        risk_chains = analyze_blast_radius(project_path, dependencies, findings, dependency_risks)
        apply_banking_exposure_scores(risk_chains, findings, dependency_risks, capability_findings, namespace_risks)
        summary = _summary(
            manifest_reports,
            dependencies,
            findings,
            dependency_risks,
            capability_findings,
            static_malware_findings,
            behavior_findings,
            package_intelligence_findings,
            namespace_risks,
            risk_chains,
            sandbox,
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
            static_malware_findings=static_malware_findings,
            static_malware_status=static_malware_status,
            behavior_findings=behavior_findings,
            behavior_status=behavior_status,
            package_intelligence_findings=package_intelligence_findings,
            package_intelligence_status=package_intelligence_status,
            namespace_risks=sorted(namespace_risks, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True),
            risk_chains=risk_chains,
            summary=summary,
            artifact=artifact,
            sandbox=sandbox,
            advisory_status=self.osv_client.status(),
            data_isolation={
                "offlineMode": self.osv_client.offline,
                "externalAdvisoryLookup": not self.osv_client.offline,
                "publicRegistryMetadata": not self.osv_client.offline and package_intelligence_status.get("registry") == "queried",
                "sourceUpload": False,
            },
        )


def _resolve_project_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser().resolve()
    if not path.exists():
        raise ScanError(f"Project path does not exist: {path}")
    if not path.is_dir():
        raise ScanError(f"Project path must be a directory: {path}")

    workspace_root = os.getenv("SCANNER_WORKSPACE_ROOT")
    require_root = os.getenv("SCANNER_REQUIRE_WORKSPACE_ROOT", "false").lower() == "true" or os.getenv("NODE_ENV", "").lower() == "production"
    if require_root and not workspace_root:
        raise ScanError("SCANNER_WORKSPACE_ROOT is required in strict mode")
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
    static_malware_findings: list[StaticMalwareFinding],
    behavior_findings: list[BehaviorFinding],
    package_intelligence_findings: list[PackageIntelligenceFinding],
    namespace_risks: list[NamespaceRiskFinding],
    risk_chains: list[RiskChainFinding],
    sandbox: dict,
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

    for finding in static_malware_findings:
        counts[finding.severity.value] += 1

    for finding in behavior_findings:
        counts[finding.severity.value] += 1

    for finding in package_intelligence_findings:
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
        SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[fail_on] for finding in static_malware_findings
    ) or any(
        SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[fail_on] for finding in behavior_findings
    ) or any(
        SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[fail_on] for finding in package_intelligence_findings
    ) or any(
        SEVERITY_ORDER[risk.severity] >= SEVERITY_ORDER[fail_on] for risk in namespace_risks
    ) or any(
        SEVERITY_ORDER[chain.severity] >= SEVERITY_ORDER[fail_on] for chain in risk_chains
    )
    if sandbox.get("status") not in {"not_requested", "completed"}:
        failed = True
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
