# Dependency Scanner — Detailed Flow Documentation

## Overview

The **Dependency Scanner** is a FastAPI-based microservice that identifies vulnerabilities, risky package patterns, capability abuses, namespace confusion attacks, and supply-chain risk chains in a project's open-source dependencies. It integrates with the **OSV (Open Source Vulnerabilities) database** for real CVE data, performs blast radius analysis to trace how vulnerable packages affect application code paths, and computes banking-domain exposure scores.

---

## Architecture Summary

```
frontend (Next.js)
    └── main-backend (FastAPI orchestration layer)
            └── dependency-Scanner (FastAPI microservice)
                    ├── routers/scans.py               — HTTP entry point
                    ├── services/scanner.py             — Core scan orchestrator
                    ├── services/manifest_discovery.py — Manifest file discovery
                    ├── services/parsers.py             — Multi-ecosystem parsers
                    ├── services/osv_client.py          — OSV API client
                    ├── services/risk_analyzer.py       — Dependency risk analysis
                    ├── services/capability_analyzer.py — Package capability analysis
                    ├── services/namespace_guard.py     — Namespace/typosquatting checks
                    ├── services/blast_radius_analyzer.py — Impact tracing
                    ├── services/exposure_scorer.py     — Banking exposure scoring
                    └── schemas/scan.py                — Data models
```

---

## Backend Flow

### 1. HTTP Entry Point — `routers/scans.py`

**Endpoint:** `POST /scans`

```
POST /scans
  |
  |-- Deserializes ScanRequest payload
  |   (project_path, max_depth, include_dev, use_osv, fail_on)
  |-- Instantiates DependencyScanner() [initializes OSVClient]
  |-- Calls await scanner.scan(payload)
  |-- On ScanError -> returns HTTP 400
  └-- On success -> returns ScanResponse (JSON)
```

---

### 2. Core Scanner — `services/scanner.py::DependencyScanner.scan`

#### Step 1 — Path Validation (`_resolve_project_path`)
- Resolves `project_path`, validates it exists and is a directory.
- If `SCANNER_WORKSPACE_ROOT` env var is set, enforces sandbox containment.

#### Step 2 — Manifest Discovery (`services/manifest_discovery.py::discover_manifests`)
- Uses `walk()` to recursively walk up to `max_depth`.
- Looks for known manifest filenames:
  - **Node.js:** `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - **Python:** `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`
  - **Java:** `pom.xml`, `build.gradle`, `build.gradle.kts`
  - **Go:** `go.mod`, `go.sum`
  - **Rust:** `Cargo.toml`, `Cargo.lock`
  - **PHP:** `composer.json`, `composer.lock`
  - **Ruby:** `Gemfile`, `Gemfile.lock`
  - **.NET:** `*.csproj`, `*.fsproj`, `packages.config`
  - **Docker:** `Dockerfile` (for base image dependencies)
- Returns list of `Path` objects pointing to manifests.

#### Step 3 — Manifest Parsing (per-manifest loop)
For each manifest, calls `services/parsers.py::parse_manifest(manifest_path, include_dev)`.

`parse_manifest` dispatches by filename to a specific parser:

| Manifest | Parser Function | Ecosystem |
|---|---|---|
| `package.json` | `parse_package_json()` | npm |
| `package-lock.json` | `parse_package_lock()` | npm |
| `yarn.lock` | `parse_yarn_lock()` | npm |
| `pnpm-lock.yaml` | `parse_pnpm_lock()` | npm |
| `requirements.txt` | `parse_requirements()` | PyPI |
| `Pipfile.lock` | `parse_pipfile_lock()` | PyPI |
| `poetry.lock` | `parse_poetry_lock()` | PyPI |
| `pyproject.toml` | `parse_pyproject()` | PyPI |
| `pom.xml` | `parse_pom()` | Maven |
| `build.gradle` | `parse_gradle()` | Maven |
| `go.mod` | `parse_go()` | Go |
| `Cargo.toml` | `parse_cargo()` | crates.io |
| `Gemfile.lock` | `parse_ruby()` | RubyGems |
| `composer.lock` | `parse_composer()` | Packagist |
| `*.csproj` | `parse_dotnet()` | NuGet |
| `Dockerfile` | `parse_dockerfile()` | Docker |

Each parser produces a `list[Dependency]`:
- `name`, `version`, `ecosystem`, `is_dev` (optional dev dependency)
- `source_manifest` (which manifest file this came from)
- `resolved` (whether it's a resolved/locked version)

Helper functions: `_clean_version()`, `_dependency_from_python_spec()`, `_poetry_dependency()`, `_cargo_dependency()`, `_go_dependency()`, `_ruby_dependency()`, `_composer_dependency()`, `_nuget_dependency()`, `_npm_lock_dependencies()`, `_yarn_key_to_name()`, `_xml_text()`.

Creates `ManifestReport` per manifest: path, type (filename), dependency_count.

#### Step 4 — OSV Vulnerability Lookup (conditional)
If `use_osv=True` and dependencies list is non-empty:
- `_dedupe_dependencies()` — Deduplicates by `(ecosystem, version, name.lower())` tuple.
- Calls `self.osv_client.query(deduplicated_deps)`.

**`services/osv_client.py::OSVClient.query`:**
- Batches dependencies into groups of 1000.
- Makes `POST https://api.osv.dev/v1/querybatch` requests with:
  ```json
  {"queries": [{"package": {"name": "...", "ecosystem": "..."}, "version": "..."}]}
  ```
- Parses OSV responses into `VulnerabilityFinding` objects:
  - `id` (CVE/GHSA/etc.), `package_name`, `ecosystem`, `affected_versions`
  - `severity` (CVSS score mapped to severity enum), `cvss_score`
  - `description`, `aliases[]`, `references[]`, `fix_version`, `published`
- `SEVERITY_ORDER` dict used for sorting: unknown=0, low=1, medium=2, high=3, critical=4.
- On `httpx.HTTPError`: raises `ScanError`.

#### Step 5 — Dependency Risk Analysis (`services/risk_analyzer.py::analyze_dependency_risks`)
Static risk analysis independent of CVE data:

- **`_dependency_hygiene_risks`** — Checks manifest-level health:
  - Missing `package-lock.json` / `poetry.lock` when `package.json` / `Pipfile` exists
  - Overly broad version specs (`*`, `>=`, `^`, `~` without upper bound)
  - Deprecated package indicators in package names
  - Packages pinned to git SHAs instead of versions
  - `_risk()` helper creates `DependencyRiskFinding` with: rule_id, title, description, severity, confidence, category, affected_packages[], fix_suggestion

- **`_lockfile_risks`** — Lockfile integrity checks:
  - Lockfile out of sync with manifest (different package counts)
  - Lockfile missing integrity hashes (`integrity` field in npm lockfiles)
  - Lockfile contains git commit references instead of registry versions

- **`_npm_lifecycle_script_risks`** — Detects dangerous npm scripts:
  - `preinstall` / `postinstall` scripts in `package.json`
  - Scripts calling `curl`, `wget`, `bash`, `sh` — potential supply chain attack vectors
  - Creates `DependencyRiskFinding` per risky script

#### Step 6 — Capability Analysis (`services/capability_analyzer.py::analyze_capabilities`)
Analyzes what capabilities installed packages request:

- **`_package_script_capabilities`** — Reads `package.json` lifecycle scripts:
  - Detects filesystem access (`fs`, `fs-extra`, `mkdirp`, `rimraf`)
  - Detects network access (`axios`, `node-fetch`, `got`, `request`)
  - Detects process execution (`child_process`, `exec`, `spawn`, `execa`)
  - Detects system information access (`os`, `process.env`)
  - `_finding()` creates `CapabilityFinding` with: package, capability_type, evidence, severity, description

- **`_source_capabilities`** — Scans source files for dangerous API usage:
  - `eval()`, `Function()`, `exec()` calls in JavaScript/Python
  - `__import__()`, `importlib`, `ctypes` usage in Python
  - `reflect.Value`, `unsafe.Pointer` in Go
  - Dynamic code loading patterns

- `_dedupe()` — Deduplicates by package + capability_type.

#### Step 7 — Namespace Risk Analysis (`services/namespace_guard.py::analyze_namespace_risks`)
Detects namespace confusion / typosquatting / dependency confusion attacks:

- **`_registry_files`** — Identifies `.npmrc`, `pip.conf`, `Cargo.toml` config sections specifying registry URLs.

- **`_registry_fallback_risks`** — Detects packages configured to fall back to public registry:
  - Internal package names (company-prefixed, `@company/pkg`) configured without `--registry` flag
  - `.npmrc` missing `@scope:registry` for internal scopes
  - `pip.conf` without `--index-url` for internal packages
  - Creates `NamespaceRiskFinding` with: package_name, namespace_type, risk_type, registry_context, severity

- **`_unscoped_internal_name_risks`** — Finds packages that look internal (contain company name patterns) but are unscoped:
  - Pattern: package names containing `internal`, `private`, `corp`, company prefix without `@scope/` prefix
  - Risk: attacker could publish `mycompany-auth` on npm to intercept installs

- **`_git_mutable_reference_risks`** — Finds git-pinned deps without commit SHA:
  - `"pkg": "github:user/repo#main"` — mutable branch reference, can be hijacked
  - `"pkg": "git+https://..."` without commit SHA

- `_risk()` helper creates `NamespaceRiskFinding`. `_rel()` computes relative path.

#### Step 8 — Blast Radius Analysis (`services/blast_radius_analyzer.py::analyze_blast_radius`)
Traces how vulnerable/risky packages propagate through the application:

- **`_source_files`** — Discovers source files in the project (`.py`, `.js`, `.ts`, `.go`, `.java`, etc.).
- **`_dependency_patterns`** — Builds import/require regex patterns per ecosystem.
- **`_find_dependency_usage`** — For each dependency:
  - Searches source files for `import`, `require`, `from X import`, `use X`, etc.
  - Returns `list[(file_path, line_number)]` of usage locations.
  - `_first_matching_line()` — finds first occurrence in a file.
  - `_import_aliases()` — detects import aliases (`import pandas as pd`).

- **`_sensitive_contexts`** — Identifies sensitive code patterns near dependency usage:
  - Payment processing functions (`charge`, `refund`, `process_payment`)
  - Authentication functions (`login`, `authenticate`, `verify_token`)
  - Data storage operations (`save`, `insert`, `write`, `upload`)

- **`_sensitive_lines`** — Finds lines with sensitive context keywords.
- **`_route_lines`** — Finds HTTP route definitions near the dependency.
- **`_route_match_parts`** — Extracts route path patterns for impact assessment.

- **`_risk_chain`** — For each vulnerable/risky package that has usage:
  - Builds a `RiskChainFinding`:
    - `package_name`, `ecosystem`, `vulnerability_id` (if from OSV)
    - `affected_routes[]` — HTTP routes that use this dependency
    - `sensitive_context[]` — sensitive operations near usage
    - `trace_steps[]` — chain of files importing this dependency

- **`_trace_steps`** — Recursively traces transitive import chains:
  - For each file that imports the vulnerable package, finds files that import *that* file
  - Up to depth 5
  - Creates `RiskChainTraceStep` with: file_path, import_line, sensitive_context, distance_from_sink

- **`_chain_severity`** — Computes chain severity based on vulnerability severity AND sensitive context weight.
- `_dedupe_dependencies()` — deduplicates by chain ID.

#### Step 9 — Banking Exposure Scoring (`services/exposure_scorer.py`)

**`apply_banking_exposure_scores(risk_chains, findings, dep_risks, cap_findings, ns_risks)`:**
- Assigns banking-domain weighted scores to all findings:
  - Payment processing packages (stripe, braintree, paypal-sdk) get multiplied score
  - Authentication packages (passport, jwt, bcrypt) get elevated score
  - Cryptography packages (openssl, cryptography, pycryptodome) get elevated score
  - Score formula: `base_severity_score × domain_weight × context_multiplier`

**`score_chain(chain)`:**
- For each `RiskChainFinding`, computes an `ExposureScore`:
  - `score` (0-100): weighted sum of vulnerability severity, route exposure, sensitive context count, chain depth
  - `action` — recommended action (block/warn/monitor/accept)
  - `_severity_points()` — converts severity to point value
  - `_reasons()` — generates list of human-readable scoring reasons
  - `_action()` — determines blocking action based on score threshold

**`aggregate_exposure(risk_chains)`:**
- Aggregates all chain scores into a single `ExposureScore` for the summary.

#### Step 10 — Summary (`_summary`)
Computes `ScanSummary`:
- `total_manifests`, `total_dependencies`, `vulnerable_dependencies`
- `dependency_risk_findings`, `capability_findings`, `namespace_risks`, `risk_chains`
- `findings_by_severity` — aggregated across ALL finding types
- `risk_score` (0-100): critical×25 + high×15 + medium×8 + low×3, capped at 100
- `banking_exposure_score`, `banking_action`
- `ci_status` — "failed" if ANY finding type has severity >= `fail_on`
- `fail_on`

#### Step 11 — Response Assembly
Returns `ScanResponse`:
```json
{
  "scan_id": "<uuid>",
  "project_path": "<path>",
  "manifests": ["ManifestReport..."],
  "dependencies": ["Dependency..."],
  "findings": ["VulnerabilityFinding..."],
  "dependency_risks": ["DependencyRiskFinding..."],
  "capability_findings": ["CapabilityFinding..."],
  "namespace_risks": ["NamespaceRiskFinding..."],
  "risk_chains": ["RiskChainFinding..."],
  "summary": "ScanSummary"
}
```

---

## Backend Data Flow Diagram

```
POST /scans (ScanRequest)
        |
        v
_resolve_project_path()
        |
        v
discover_manifests()  ----------->  [manifest Path list]
        |
        v (per manifest loop)
parse_manifest()  -------------->  [Dependency list] + ManifestReport
        |
        v
_dedupe_dependencies()
        |
        v [if use_osv=True]
osv_client.query()  ------------>  [VulnerabilityFinding list] (from OSV API)
        |
        v
analyze_dependency_risks()  ---->  [DependencyRiskFinding list]
        |
        v
analyze_capabilities()  -------->  [CapabilityFinding list]
        |
        v
analyze_namespace_risks()  ------>  [NamespaceRiskFinding list]
        |
        v
analyze_blast_radius()  -------->  [RiskChainFinding list]
        |
        v
apply_banking_exposure_scores()  -> scores applied to all finding types
        |
        v
aggregate_exposure()
        |
        v
_summary()  -------------------->  ScanSummary
        |
        v
ScanResponse (returned to main-backend --> frontend)
```

---

## Frontend Flow

### Landing Page — `/dependency-scanner/page.tsx`

**Component:** `DependencyScannerLandingPage`

#### On Mount (`useEffect`):
1. Reads `bugbusters_github_session` cookie.
2. If session: calls `fetchScanJobs()` -> `GET /api/scans`.
3. Sorts jobs by `createdAt` descending.
4. On 401: clears cookie.
5. Sets `jobs` and `isLoadingJobs = false`.

#### Render:
- **Page Header** — "Dependency Scanner" title + `inventory_2` icon + description + "Scan New Target" button.
- **`<RecentJobs>`** — Job list.

---

### Dashboard Scan Initiation

Dependency scanner is triggered in parallel with all other scanners.

#### GitHub Flow:
- `startGithubScan()` -> `POST /api/scans/github` with `{repoFullName, repoCloneUrl, githubSession, includeDev, useOsv, failOn}`.

#### ZIP Upload Flow:
- `uploadZipScan()` -> `POST /api/scans/zip` (multipart form data).

**Extra options (unique to dependency scanner):**
- `includeDev` — whether to include dev dependencies in the scan
- `useOsv` — whether to query the OSV vulnerability database

---

### Job Detail Page — `/dependency-scanner/[jobId]/page.tsx`

**Component:** `ScannerJobPage` (shared generic job page)

#### On Mount:
1. `fetchJobStatus(jobId)` -> `GET /api/scans/{jobId}`.
2. SSE stream via `getScanLogsUrl(jobId)` -> `GET /api/scans/{jobId}/logs?authToken=<jwt>`.

#### Result Sections (when completed):
1. **Summary Metrics Row**:
   - Total Dependencies
   - Vulnerabilities (from `summary.findings_by_severity`)
   - Risk Chains (count)
   - Banking Exposure Score
   - CI Status

2. **Vulnerability Findings Table** (`result.findings`):
   - CVE/GHSA ID, Package, Ecosystem, Severity, Version, Fix Available
   - CVSS score display

3. **Dependency Risks Table** (`result.dependency_risks`):
   - Rule ID, Title, Severity, Affected Packages, Fix Suggestion

4. **Capability Findings** (`result.capability_findings`):
   - Package, Capability Type (network/filesystem/exec), Severity, Evidence

5. **Namespace Risks** (`result.namespace_risks`):
   - Package, Risk Type (registry-fallback/typosquatting/mutable-ref), Severity

6. **Blast Radius Map** (`result.risk_chains`) — rendered via `<BlastRadiusMap>` widget:
   - Visual graph of vulnerable package -> usage file -> HTTP route chains
   - Shows affected routes and sensitive contexts
   - Color-coded by chain severity

---

## Frontend API Client Functions (Dependency Scanner)

| Function | HTTP Call | Purpose |
|---|---|---|
| `startGithubScan()` | `POST /api/scans/github` | Start scan from GitHub repo |
| `uploadZipScan()` | `POST /api/scans/zip` | Start scan from ZIP upload |
| `fetchScanJobs()` | `GET /api/scans` | List all dependency scan jobs |
| `fetchJobStatus(jobId)` | `GET /api/scans/{jobId}` | Get job status + result |
| `getScanLogsUrl(jobId)` | URL builder for SSE stream | Real-time log stream URL |

---

## Key Data Models

| Model | Purpose |
|---|---|
| `ScanRequest` | Input params (include_dev, use_osv, fail_on) |
| `Dependency` | A single dependency (name, version, ecosystem) |
| `ManifestReport` | Per-manifest summary |
| `VulnerabilityFinding` | OSV CVE/GHSA finding |
| `DependencyRiskFinding` | Static risk finding (hygiene, lockfile, script) |
| `CapabilityFinding` | Package capability abuse finding |
| `NamespaceRiskFinding` | Namespace confusion / typosquatting risk |
| `RiskChainFinding` | Blast radius chain (package -> usage -> route) |
| `RiskChainTraceStep` | One step in a blast radius trace |
| `ExposureScore` | Banking exposure score + action |
| `ScanSummary` | High-level statistics |
| `ScanResponse` | Full scan output |

---

## Supported Ecosystems

| Ecosystem | Package Registry | Manifest Files |
|---|---|---|
| npm | npmjs.com | package.json, lock files |
| PyPI | pypi.org | requirements.txt, poetry.lock, Pipfile.lock, pyproject.toml |
| Maven | maven.org | pom.xml, build.gradle |
| Go | pkg.go.dev | go.mod, go.sum |
| crates.io | crates.io | Cargo.toml, Cargo.lock |
| RubyGems | rubygems.org | Gemfile, Gemfile.lock |
| Packagist | packagist.org | composer.json, composer.lock |
| NuGet | nuget.org | *.csproj, packages.config |
| Docker | Docker Hub | Dockerfile |

---

## Severity Weight Table (OSV + All Finding Types)

| Severity | Score Weight |
|---|---|
| critical | x25 |
| high | x15 |
| medium | x8 |
| low | x3 |
| unknown | x1 |

Risk score is the weighted sum of ALL finding types (vulnerabilities + dependency risks + capability findings + namespace risks + risk chains), capped at 100.
