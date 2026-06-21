from fastapi import APIRouter, HTTPException

from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scanner import DependencyScanner, ScanError

router = APIRouter()


@router.post("/scans", response_model=ScanResponse)
async def scan_dependencies(payload: ScanRequest) -> ScanResponse:
    scanner = DependencyScanner()
    try:
        return await scanner.scan(payload)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
