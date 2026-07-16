from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

MAX_HASH_BYTES = int(os.getenv("SCANNER_MAX_HASH_BYTES", str(256 * 1024 * 1024)))


def sha256_file(path: Path) -> str:
    if path.stat().st_size > MAX_HASH_BYTES:
        raise ValueError(f"File exceeds SCANNER_MAX_HASH_BYTES: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision(root: Path) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    revision = result.stdout.strip()
    return revision if len(revision) == 40 else None


def build_artifact_metadata(root: Path, manifests: list[Path]) -> dict:
    files = []
    for manifest in manifests:
        try:
            files.append({"path": manifest.relative_to(root).as_posix(), "sha256": sha256_file(manifest), "sizeBytes": manifest.stat().st_size})
        except (OSError, ValueError) as exc:
            raise ValueError(f"Unable to hash manifest {manifest}: {exc}") from exc
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"artifact_sha256": hashlib.sha256(canonical).hexdigest(), "git_revision": git_revision(root), "manifest_count": len(files), "manifests": files, "integrity": "manifest_hashes_only"}
