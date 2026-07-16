from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class SandboxError(Exception):
    pass


def build_sandbox_spec(project_path: Path) -> dict:
    commands = []
    if (project_path / "package-lock.json").is_file():
        commands.extend([["npm", "ci", "--ignore-scripts"], ["npm", "ci"]])
    elif (project_path / "pnpm-lock.yaml").is_file():
        commands.extend([["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"], ["pnpm", "install", "--frozen-lockfile"]])
    elif (project_path / "yarn.lock").is_file():
        commands.extend([["yarn", "install", "--frozen-lockfile", "--ignore-scripts"], ["yarn", "install", "--frozen-lockfile"]])
    if (project_path / "requirements.txt").is_file():
        commands.append(["python", "-m", "pip", "install", "--no-cache-dir", "-r", "requirements.txt"])
    if (project_path / "pyproject.toml").is_file():
        commands.append(["python", "-m", "pip", "install", "--no-cache-dir", "."])
    return {
        "version": "sandbox-v1",
        "inputPath": str(project_path),
        "commands": commands,
        "network": {"mode": "deny_all" if os.getenv("SCANNER_OFFLINE_MODE", "true").lower() == "true" else "deny_by_default", "proxyRequired": not (os.getenv("SCANNER_OFFLINE_MODE", "true").lower() == "true"), "blockedCidrs": ["0.0.0.0/0", "::/0"] if os.getenv("SCANNER_OFFLINE_MODE", "true").lower() == "true" else ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.169.254/32"]},
        "filesystem": {"rootReadOnly": True, "workspaceWritable": True, "hostMounts": False},
        "identity": {"runAsUser": "scanner", "privileged": False, "cloudCredentials": False},
        "limits": {"timeoutSeconds": int(os.getenv("SCANNER_SANDBOX_TIMEOUT_SECONDS", "300")), "memoryMb": int(os.getenv("SCANNER_SANDBOX_MEMORY_MB", "2048")), "cpu": int(os.getenv("SCANNER_SANDBOX_CPU", "2"))},
        "telemetry": {"process": True, "filesystem": True, "network": True, "syscalls": True},
    }


def run_in_sandbox(project_path: Path, requested: bool = False) -> dict:
    enabled = os.getenv("SCANNER_SANDBOX_ENABLED", "false").lower() == "true"
    if not requested and not enabled:
        return {"status": "not_requested", "runner": "none", "commands": []}
    if not enabled:
        return {"status": "disabled", "runner": "none", "commands": [], "reason": "SCANNER_SANDBOX_ENABLED is false"}

    runner = os.getenv("SANDBOX_RUNNER_PATH") or shutil.which("dependency-sandbox-runner")
    if not runner:
        return {"status": "unavailable", "runner": "none", "commands": [], "reason": "No hardened sandbox runner is configured"}

    spec = build_sandbox_spec(project_path)
    try:
        with tempfile.TemporaryDirectory(prefix="dependency-sandbox-") as temp_dir:
            spec_path = Path(temp_dir) / "sandbox-spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            result = subprocess.run([runner, "--spec", str(spec_path)], capture_output=True, text=True, timeout=spec["limits"]["timeoutSeconds"] + 30)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "runner": runner, "commands": spec["commands"]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "error", "runner": runner, "commands": spec["commands"], "reason": str(exc)}

    parsed = {}
    if result.stdout.strip():
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            parsed = {"telemetryAvailable": False}
    return {"status": "completed" if result.returncode == 0 else "failed", "runner": runner, "commands": spec["commands"], **parsed}
