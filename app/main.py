import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.scans import router as scans_router
from app.services.security_policy import validate_startup_policy

validate_startup_policy()


app = FastAPI(
    title="Dependency Scanner Backend",
    description="Static dependency scanner for vulnerable open-source packages.",
    version="0.1.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv("SCANNER_ALLOWED_ORIGINS", "http://127.0.0.1:3000").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    offline = os.getenv("SCANNER_OFFLINE_MODE", "true").lower() == "true"
    return {
        "status": "ok",
        "service": "dependency-scanner",
        "dataIsolation": {
            "offlineMode": offline,
            "externalAdvisoryLookup": not offline,
            "publicRegistryMetadata": not offline and os.getenv("SCANNER_PACKAGE_INTELLIGENCE_ENABLED", "false").lower() == "true",
            "sourceUpload": False,
            "policy": "strict-offline-v1" if os.getenv("SCANNER_STRICT_OFFLINE", "true").lower() == "true" else "configurable",
        },
    }


app.include_router(scans_router, prefix="/api/v1", tags=["scans"])
