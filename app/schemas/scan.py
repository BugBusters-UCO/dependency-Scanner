from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class ScanRequest(BaseModel):
    project_path: str = Field(..., description="Local project directory to scan.")
    include_dev: bool = Field(default=True, description="Include development dependencies.")
    use_osv: bool = Field(default=True, description="Query OSV for known vulnerabilities.")
    fail_on: Severity = Field(default=Severity.high, description="CI fails at or above this severity.")
    max_depth: int = Field(default=8, ge=1, le=20, description="Maximum directory depth for manifest discovery.")
    sandbox: bool = Field(default=False, description="Request execution in the separately managed hardened sandbox.")


class SinglePackageScanRequest(BaseModel):
    name: str = Field(..., description="Package name")
    version: str | None = Field(default=None, description="Package version")
    ecosystem: str = Field(default="npm", description="Package ecosystem (npm, pypi, etc)")


class Dependency(BaseModel):
    name: str
    version: str | None = None
    ecosystem: str
    manifest_path: str
    scope: Literal["runtime", "development", "unknown"] = "unknown"
    package_url: str | None = None


class ManifestReport(BaseModel):
    path: str
    type: str
    dependency_count: int


class FixSuggestion(BaseModel):
    title: str
    description: str
    command: str | None = None
    target_version: str | None = None
    auto_remediable: bool = False


class VulnerabilityFinding(BaseModel):
    id: str
    package_name: str
    installed_version: str | None
    ecosystem: str
    severity: Severity
    summary: str
    details_url: str | None = None
    aliases: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    manifest_path: str
    fix: FixSuggestion


class DependencyRiskFinding(BaseModel):
    id: str
    dependency_name: str | None = None
    manifest_path: str
    severity: Severity
    category: str
    title: str
    description: str
    fix: FixSuggestion


class CapabilityFinding(BaseModel):
    id: str
    capability: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int | None = None
    code: str | None = None
    dependency_name: str | None = None
    banking_impact: str
    fix: FixSuggestion


class StaticMalwareFinding(BaseModel):
    id: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int | None = None
    evidence: str | None = None
    source: str
    confidence: float = Field(ge=0, le=1)
    fix: FixSuggestion


class BehaviorFinding(BaseModel):
    id: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    evidence: dict
    confidence: float = Field(ge=0, le=1)
    fix: FixSuggestion


class PackageIntelligenceFinding(BaseModel):
    id: str
    rule_id: str
    package_name: str
    version: str | None = None
    ecosystem: str
    severity: Severity
    title: str
    description: str
    manifest_path: str
    evidence: dict = Field(default_factory=dict)
    fix: FixSuggestion


class NamespaceRiskFinding(BaseModel):
    id: str
    severity: Severity
    category: str
    title: str
    description: str
    file_path: str
    dependency_name: str | None = None
    evidence: list[str] = Field(default_factory=list)
    banking_impact: str
    fix: FixSuggestion


class ExposureScore(BaseModel):
    score: int
    policy_version: str = "banking-v1"
    action: Literal["block", "expedite", "watch", "track"]
    exploit_likelihood: int
    static_exploitability: int
    business_criticality: int
    trust_deficit: int
    malicious_capability: int
    blast_radius: int
    reasons: list[str] = Field(default_factory=list)


class RiskChainTraceStep(BaseModel):
    step: int
    kind: Literal["route", "manifest", "import", "sensitive-use", "risk", "fix"]
    label: str
    file_path: str | None = None
    line_number: int | None = None
    code: str | None = None
    details: list[str] = Field(default_factory=list)


class RiskChainFinding(BaseModel):
    id: str
    dependency_name: str
    ecosystem: str
    severity: Severity
    title: str
    risk_chain: list[str]
    trace: list[RiskChainTraceStep] = Field(default_factory=list)
    manifest_path: str | None = None
    sensitive_contexts: list[str] = Field(default_factory=list)
    used_in_files: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    exposure: ExposureScore | None = None
    fix: FixSuggestion
    reachability_confidence: float = Field(default=0.5, ge=0, le=1)
    analysis_method: str = "regex-fallback"


class ScanSummary(BaseModel):
    total_manifests: int
    total_dependencies: int
    vulnerable_dependencies: int
    dependency_risk_findings: int = 0
    risk_chains: int = 0
    capability_findings: int = 0
    namespace_risks: int = 0
    banking_exposure_score: int = 0
    banking_action: Literal["block", "expedite", "watch", "track"] = "track"
    findings_by_severity: dict[str, int]
    risk_score: int
    ci_status: Literal["passed", "failed"]
    fail_on: Severity


class ArtifactMetadata(BaseModel):
    artifact_sha256: str
    git_revision: str | None = None
    manifest_count: int
    manifests: list[dict]
    integrity: str


class ScanResponse(BaseModel):
    scan_id: str
    project_path: str
    manifests: list[ManifestReport]
    dependencies: list[Dependency]
    findings: list[VulnerabilityFinding]
    dependency_risks: list[DependencyRiskFinding] = Field(default_factory=list)
    capability_findings: list[CapabilityFinding] = Field(default_factory=list)
    static_malware_findings: list[StaticMalwareFinding] = Field(default_factory=list)
    static_malware_status: dict = Field(default_factory=dict)
    behavior_findings: list[BehaviorFinding] = Field(default_factory=list)
    behavior_status: dict = Field(default_factory=dict)
    package_intelligence_findings: list[PackageIntelligenceFinding] = Field(default_factory=list)
    package_intelligence_status: dict = Field(default_factory=dict)
    namespace_risks: list[NamespaceRiskFinding] = Field(default_factory=list)
    risk_chains: list[RiskChainFinding] = Field(default_factory=list)
    summary: ScanSummary
    artifact: ArtifactMetadata
    sandbox: dict = Field(default_factory=dict)
    advisory_status: str = "offline_no_external_advisory_lookup"
    data_isolation: dict = Field(default_factory=dict)


class SinglePackageScanResponse(BaseModel):
    isMalicious: bool
    findings: list[VulnerabilityFinding]

