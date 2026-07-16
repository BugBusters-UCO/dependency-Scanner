# Dependency Scanner Backend

Phase 1 FastAPI backend for scanning open-source dependency manifests and reporting vulnerable packages with actionable fixes.

## What it scans

- `package.json`
- `package-lock.json`
- `yarn.lock`
- `pnpm-lock.yaml`
- `requirements.txt`
- `pyproject.toml`
- `poetry.lock`
- `Pipfile.lock`
- `pom.xml`
- `build.gradle` / `build.gradle.kts`
- `go.mod` / `go.sum`
- `Cargo.toml` / `Cargo.lock`
- `Gemfile` / `Gemfile.lock`
- `composer.json` / `composer.lock`
- `.csproj`, `.vbproj`, `.fsproj`, `packages.config`, `Directory.Packages.props`
- `Dockerfile` base images

The scanner discovers dependency manifests under a project path, extracts packages, queries the OSV vulnerability database where supported, and returns a CI-friendly risk summary.

It also reports dependency hygiene risks such as unpinned dependencies, floating versions, mutable Docker tags, missing lockfiles, and install-time npm lifecycle scripts.

## Run locally

Fast start on Windows:

```powershell
.\start
```

The default port is `8001`. To use another port:

```powershell
$env:SCANNER_PORT = "8010"
.\start
```

Manual setup:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

Open:

- API docs: `http://127.0.0.1:8001/docs`
- Health: `http://127.0.0.1:8001/health`

## Scan a project

```powershell
curl -X POST "http://127.0.0.1:8001/api/v1/scans" `
  -H "Content-Type: application/json" `
  -d "{\"project_path\":\"C:\\path\\to\\repo\",\"include_dev\":true,\"use_osv\":true,\"fail_on\":\"high\"}"
```

## CI usage

Set `SCANNER_WORKSPACE_ROOT` to restrict scans to a CI workspace:

```powershell
$env:SCANNER_WORKSPACE_ROOT = $pwd.Path
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

`ci_status` in the response is `passed` or `failed` based on the configured `fail_on` severity.

## Internal service authentication

Set `SCANNER_API_TOKEN` on both the scanner and the main backend to require the
`X-Scanner-Token` header for scan requests. Leave it unset only for local
development. Configure `SCANNER_ALLOWED_ORIGINS` with a comma-separated
allowlist rather than exposing the scanner with wildcard CORS.

For the enterprise deployment and Redis worker model, see the repository-level
`ENTERPRISE_DEPLOYMENT.md`.
