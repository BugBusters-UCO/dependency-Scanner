from __future__ import annotations

import json
import os

from app.schemas.scan import (
    CapabilityFinding,
    DependencyRiskFinding,
    ExposureScore,
    NamespaceRiskFinding,
    RiskChainFinding,
    Severity,
    VulnerabilityFinding,
)
from app.services.osv_client import SEVERITY_ORDER


CRITICAL_CONTEXTS = {"authentication", "payments", "kyc", "pii", "crypto", "webhook", "database-write"}


def apply_banking_exposure_scores(
    chains: list[RiskChainFinding],
    findings: list[VulnerabilityFinding],
    dependency_risks: list[DependencyRiskFinding],
    capability_findings: list[CapabilityFinding],
    namespace_risks: list[NamespaceRiskFinding],
) -> None:
    vulnerabilities = {(item.ecosystem, item.package_name.lower()): item for item in findings}
    risks_by_dep: dict[str, list[DependencyRiskFinding]] = {}
    for risk in dependency_risks:
        if risk.dependency_name:
            risks_by_dep.setdefault(risk.dependency_name.lower(), []).append(risk)

    for chain in chains:
        vulnerability = vulnerabilities.get((chain.ecosystem, chain.dependency_name.lower()))
        related_risks = risks_by_dep.get(chain.dependency_name.lower(), [])
        chain.exposure = score_chain(chain, vulnerability, related_risks, capability_findings, namespace_risks)


def score_chain(
    chain: RiskChainFinding,
    vulnerability: VulnerabilityFinding | None,
    dependency_risks: list[DependencyRiskFinding],
    capability_findings: list[CapabilityFinding],
    namespace_risks: list[NamespaceRiskFinding],
) -> ExposureScore:
    policy = _policy()
    route_count = sum(1 for step in chain.trace if step.kind == "route")
    import_count = sum(1 for step in chain.trace if step.kind == "import")
    sensitive_count = sum(1 for step in chain.trace if step.kind == "sensitive-use")
    critical_context_count = len(set(chain.sensitive_contexts) & CRITICAL_CONTEXTS)

    exploit_likelihood = _severity_points(vulnerability.severity if vulnerability else chain.severity)
    if vulnerability and vulnerability.aliases:
        exploit_likelihood = min(100, exploit_likelihood + 10)

    static_exploitability = min(100, round((route_count * 30 + import_count * 20 + sensitive_count * 20) * chain.reachability_confidence))
    business_criticality = min(100, critical_context_count * 18 + len(chain.sensitive_contexts) * 8)
    trust_deficit = min(100, len(dependency_risks) * 25 + len(namespace_risks) * 12)
    malicious_capability = min(100, len(capability_findings) * 18)
    blast_radius = min(100, len(chain.used_in_files) * 15 + len(chain.sensitive_contexts) * 12)

    score = round(sum(value * policy["weights"][name] for name, value in {
        "exploit_likelihood": exploit_likelihood,
        "static_exploitability": static_exploitability,
        "business_criticality": business_criticality,
        "trust_deficit": trust_deficit,
        "malicious_capability": malicious_capability,
        "blast_radius": blast_radius,
    }.items()))
    reasons = _reasons(
        chain,
        vulnerability,
        route_count,
        critical_context_count,
        dependency_risks,
        capability_findings,
        namespace_risks,
        score,
    )
    return ExposureScore(
        score=score,
        policy_version=policy["version"],
        action=_action(score, policy),
        exploit_likelihood=exploit_likelihood,
        static_exploitability=static_exploitability,
        business_criticality=business_criticality,
        trust_deficit=trust_deficit,
        malicious_capability=malicious_capability,
        blast_radius=blast_radius,
        reasons=reasons,
    )


def aggregate_exposure(chains: list[RiskChainFinding]) -> ExposureScore:
    if not chains:
        return ExposureScore(
            score=0,
            policy_version=_policy()["version"],
            action="track",
            exploit_likelihood=0,
            static_exploitability=0,
            business_criticality=0,
            trust_deficit=0,
            malicious_capability=0,
            blast_radius=0,
            reasons=["No route-level dependency exposure detected."],
        )
    scored = [chain.exposure for chain in chains if chain.exposure]
    if not scored:
        return aggregate_exposure([])
    top = max(scored, key=lambda item: item.score)
    return ExposureScore(
        score=top.score,
        policy_version=top.policy_version,
        action=top.action,
        exploit_likelihood=top.exploit_likelihood,
        static_exploitability=top.static_exploitability,
        business_criticality=top.business_criticality,
        trust_deficit=top.trust_deficit,
        malicious_capability=top.malicious_capability,
        blast_radius=top.blast_radius,
        reasons=top.reasons[:5],
    )


def _severity_points(severity: Severity) -> int:
    return {
        Severity.critical: 95,
        Severity.high: 80,
        Severity.medium: 55,
        Severity.low: 25,
        Severity.unknown: 35,
    }[severity]


def _action(score: int, policy: dict | None = None) -> str:
    thresholds = (policy or _policy())["thresholds"]
    if score >= thresholds["block"]:
        return "block"
    if score >= thresholds["expedite"]:
        return "expedite"
    if score >= thresholds["watch"]:
        return "watch"
    return "track"


def _reasons(
    chain: RiskChainFinding,
    vulnerability: VulnerabilityFinding | None,
    route_count: int,
    critical_context_count: int,
    dependency_risks: list[DependencyRiskFinding],
    capability_findings: list[CapabilityFinding],
    namespace_risks: list[NamespaceRiskFinding],
    score: int,
) -> list[str]:
    reasons = []
    if vulnerability:
        reasons.append(f"{vulnerability.id} affects {chain.dependency_name}.")
    if route_count:
        reasons.append(f"Dependency is reachable from {route_count} API route trace step(s) with {chain.reachability_confidence:.0%} confidence via {chain.analysis_method}.")
    if critical_context_count:
        reasons.append(f"Used near bank-critical context(s): {', '.join(sorted(set(chain.sensitive_contexts) & CRITICAL_CONTEXTS))}.")
    if dependency_risks:
        reasons.append(f"Dependency hygiene issue: {dependency_risks[0].title}.")
    if capability_findings:
        reasons.append(f"Repository has suspicious capability fingerprints such as {capability_findings[0].capability}.")
    if namespace_risks:
        reasons.append(f"Registry or namespace trust issue: {namespace_risks[0].title}.")
    policy = _policy()
    reasons.append(f"Banking exposure decision is {_action(score, policy).upper()} at score {score} under policy {policy['version']}.")
    return reasons


def _policy() -> dict:
    default = {
        "version": os.getenv("BANKING_RISK_POLICY_VERSION", "banking-v1"),
        "weights": {
            "exploit_likelihood": 0.25,
            "static_exploitability": 0.20,
            "business_criticality": 0.20,
            "trust_deficit": 0.15,
            "malicious_capability": 0.10,
            "blast_radius": 0.10,
        },
        "thresholds": {"block": 75, "expedite": 55, "watch": 30},
    }
    raw = os.getenv("BANKING_RISK_POLICY_JSON")
    if not raw:
        return default
    try:
        supplied = json.loads(raw)
        weights = {**default["weights"], **(supplied.get("weights") or {})}
        total = sum(float(value) for value in weights.values())
        if total <= 0:
            return default
        weights = {key: float(value) / total for key, value in weights.items()}
        thresholds = {**default["thresholds"], **(supplied.get("thresholds") or {})}
        return {"version": str(supplied.get("version") or default["version"]), "weights": weights, "thresholds": thresholds}
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
