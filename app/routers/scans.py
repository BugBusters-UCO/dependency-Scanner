import os
import secrets

from fastapi import APIRouter, Header, HTTPException

from app.schemas.scan import ScanRequest, ScanResponse, SinglePackageScanRequest, SinglePackageScanResponse
from app.services.scanner import DependencyScanner, ScanError

router = APIRouter()


@router.post("/scans", response_model=ScanResponse)
async def scan_dependencies(payload: ScanRequest, x_scanner_token: str | None = Header(default=None)) -> ScanResponse:
    expected_token = os.getenv("SCANNER_API_TOKEN")
    if expected_token and not secrets.compare_digest(x_scanner_token or "", expected_token):
        raise HTTPException(status_code=401, detail="Invalid scanner service token")
    scanner = DependencyScanner()
    try:
        return await scanner.scan(payload)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/scans/single", response_model=SinglePackageScanResponse)
async def scan_single_package(payload: SinglePackageScanRequest, x_scanner_token: str | None = Header(default=None)) -> SinglePackageScanResponse:
    expected_token = os.getenv("SCANNER_API_TOKEN")
    if expected_token and not secrets.compare_digest(x_scanner_token or "", expected_token):
        raise HTTPException(status_code=401, detail="Invalid scanner service token")
    scanner = DependencyScanner()
    try:
        return await scanner.scan_single(payload)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
