from __future__ import annotations

import os


def offline_mode() -> bool:
    return os.getenv("SCANNER_OFFLINE_MODE", "true").lower() == "true"


def validate_startup_policy() -> None:
    strict = os.getenv("SCANNER_STRICT_OFFLINE", "true").lower() == "true"
    production = os.getenv("NODE_ENV", "").lower() == "production"
    if strict and production and not offline_mode():
        raise RuntimeError("SCANNER_OFFLINE_MODE must remain true in strict production mode")
