from __future__ import annotations

import ipaddress
import hashlib
import json
import re

from app.schemas.scan import BehaviorFinding, FixSuggestion, Severity


def analyze_behavior(sandbox: dict) -> tuple[list[BehaviorFinding], dict]:
    events = sandbox.get("events") or sandbox.get("telemetry") or []
    if not isinstance(events, list):
        return [], {"eventsInspected": 0, "telemetryAvailable": False, "mode": "behavioral"}
    findings: list[BehaviorFinding] = []
    counts: dict[str, int] = {}
    for raw in events:
        if not isinstance(raw, dict):
            continue
        event = {str(k).lower(): str(v) for k, v in raw.items()}
        blob = " ".join(event.values())
        kind = event.get("type", event.get("kind", "unknown"))
        counts[kind] = counts.get(kind, 0) + 1
        if re.search(r"(\.ssh|id_rsa|\.npmrc|\.pypirc|aws_secret|github_token|private.key|credentials)", blob, re.I):
            findings.append(_finding("credential-access", Severity.critical, "Sandbox accessed credential-like material.", raw))
        if re.search(r"169\.254\.169\.254|metadata\.google|metadata\.azure", blob, re.I):
            findings.append(_finding("cloud-metadata-access", Severity.critical, "Sandbox attempted to access cloud instance metadata.", raw))
        if re.search(r"(bash|sh|cmd|powershell|/bin/(ba)?sh)", blob, re.I) and re.search(r"(exec|spawn|process|command|shell)", blob, re.I):
            findings.append(_finding("shell-spawn", Severity.high, "Sandbox spawned a shell or command interpreter.", raw))
        if re.search(r"(curl|wget|download|http|get|fetch|requests)", blob, re.I) and re.search(r"(\.exe|\.dll|\.so|chmod|exec|spawn|write)", blob, re.I):
            findings.append(_finding("download-execute", Severity.critical, "Sandbox downloaded or wrote content associated with execution.", raw))
        if re.search(r"(crontab|systemctl|launchagents|schtasks|startup|registry\\run)", blob, re.I):
            findings.append(_finding("persistence", Severity.high, "Sandbox attempted an operating-system persistence action.", raw))
        if re.search(r"(stratum\+tcp|xmrig|cryptominer|coinhive|bitcoin|monero)", blob, re.I):
            findings.append(_finding("crypto-mining", Severity.critical, "Sandbox behavior matches cryptocurrency-mining activity.", raw))
        target = event.get("ip") or event.get("remoteip") or event.get("destination")
        if target and _is_private_or_reserved(target):
            findings.append(_finding("protected-network-access", Severity.critical, "Sandbox attempted to reach a private, loopback or reserved network range.", raw))
    return _dedupe(findings), {"eventsInspected": len(events), "eventTypes": counts, "telemetryAvailable": bool(events), "mode": "behavioral"}


def _is_private_or_reserved(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def _finding(rule_id: str, severity: Severity, title: str, event: dict) -> BehaviorFinding:
    evidence = {k: v[:300] for k, v in event.items() if k in {"type", "kind", "path", "command", "process", "domain", "ip", "remoteip", "destination", "syscall"}}
    fingerprint = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()[:20]
    return BehaviorFinding(id=f"behavior:{rule_id}:{fingerprint}", rule_id=rule_id, severity=severity, title=title, description="Behavior was observed during isolated package execution.", evidence=evidence, confidence=0.9 if severity == Severity.critical else 0.75, fix=FixSuggestion(title="Quarantine and investigate artifact", description="Review sandbox evidence, block promotion, and inspect all consumers of the artifact.", auto_remediable=False))


def _dedupe(findings):
    seen=set(); unique=[]
    for finding in findings:
        if finding.id in seen: continue
        seen.add(finding.id); unique.append(finding)
    return unique[:500]
