from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.scans import router as scans_router


app = FastAPI(
    title="Dependency Scanner Backend",
    description="Static dependency scanner for vulnerable open-source packages.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "dependency-scanner"}


app.include_router(scans_router, prefix="/api/v1", tags=["scans"])
