from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.schemas.scan import Dependency


VERSION_PREFIX_RE = re.compile(r"^[~^<>=! ]+")
REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:\[.*?\])?\s*([<>=!~]=?|===)?\s*([^;#\s]+)?")
GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*\(?\s*["']([^:"']+):([^:"']+):([^"']+)["']"""
)
GO_REQUIRE_RE = re.compile(r"^\s*([A-Za-z0-9_.~/-]+)\s+v?([^\s]+)")
CARGO_LOCK_PACKAGE_RE = re.compile(r"\[\[package\]\]\s+name = \"([^\"]+)\"\s+version = \"([^\"]+)\"", re.MULTILINE)
GEM_LOCK_RE = re.compile(r"^\s{2,}([A-Za-z0-9_.-]+) \(([^)]+)\)", re.MULTILINE)
COMPOSER_LOCK_PACKAGE_TYPES = {"packages": "runtime", "packages-dev": "development"}
NUGET_PACKAGE_RE = re.compile(r"""<package\s+[^>]*id=["']([^"']+)["'][^>]*version=["']([^"']+)["']""", re.IGNORECASE)
NUGET_REFERENCE_RE = re.compile(r"""<PackageReference\s+[^>]*Include=["']([^"']+)["'][^>]*(?:Version=["']([^"']+)["'])?""", re.IGNORECASE)
NUGET_VERSION_CHILD_RE = re.compile(r"""<PackageReference\s+[^>]*Include=["']([^"']+)["'][^>]*>.*?<Version>([^<]+)</Version>.*?</PackageReference>""", re.IGNORECASE | re.DOTALL)
DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s:@]+(?:/[^\s:@]+)*)(?::([^\s@]+))?", re.IGNORECASE | re.MULTILINE)


def parse_manifest(path: Path, include_dev: bool) -> list[Dependency]:
    if path.name == "package.json":
        return parse_package_json(path, include_dev)
    if path.name == "package-lock.json":
        return parse_package_lock(path, include_dev)
    if path.name == "yarn.lock":
        return parse_yarn_lock(path)
    if path.name == "pnpm-lock.yaml":
        return parse_pnpm_lock(path, include_dev)
    if path.name == "requirements.txt":
        return parse_requirements(path)
    if path.name == "pyproject.toml":
        return parse_pyproject(path, include_dev)
    if path.name == "poetry.lock":
        return parse_poetry_lock(path, include_dev)
    if path.name == "Pipfile.lock":
        return parse_pipfile_lock(path, include_dev)
    if path.name == "pom.xml":
        return parse_pom(path)
    if path.name in {"build.gradle", "build.gradle.kts"}:
        return parse_gradle(path, include_dev)
    if path.name in {"go.mod", "go.sum"}:
        return parse_go(path)
    if path.name in {"Cargo.toml", "Cargo.lock"}:
        return parse_cargo(path, include_dev)
    if path.name in {"Gemfile", "Gemfile.lock"}:
        return parse_ruby(path, include_dev)
    if path.name in {"composer.json", "composer.lock"}:
        return parse_composer(path, include_dev)
    if path.name == "packages.config" or path.suffix.lower() in {".csproj", ".vbproj", ".fsproj"} or path.name == "Directory.Packages.props":
        return parse_dotnet(path)
    if path.name == "Dockerfile":
        return parse_dockerfile(path)
    return []


def parse_package_json(path: Path, include_dev: bool) -> list[Dependency]:
    data = _load_json(path)
    deps: list[Dependency] = []
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "development")):
        if section == "devDependencies" and not include_dev:
            continue
        for name, raw_version in data.get(section, {}).items():
            deps.append(
                Dependency(
                    name=name,
                    version=_clean_version(str(raw_version)),
                    ecosystem="npm",
                    manifest_path=str(path),
                    scope=scope,
                    package_url=f"pkg:npm/{name}",
                )
            )
    return deps


def parse_package_lock(path: Path, include_dev: bool) -> list[Dependency]:
    data = _load_json(path)
    deps: list[Dependency] = []
    packages = data.get("packages", {})
    if packages:
        for package_path, package_data in packages.items():
            if not package_path or not isinstance(package_data, dict):
                continue
            if package_data.get("dev") and not include_dev:
                continue
            name = package_data.get("name") or package_path.removeprefix("node_modules/")
            deps.append(
                Dependency(
                    name=name,
                    version=package_data.get("version"),
                    ecosystem="npm",
                    manifest_path=str(path),
                    scope="development" if package_data.get("dev") else "runtime",
                    package_url=f"pkg:npm/{name}",
                )
            )
        return deps

    for name, package_data in data.get("dependencies", {}).items():
        if package_data.get("dev") and not include_dev:
            continue
        deps.append(
            Dependency(
                name=name,
                version=package_data.get("version"),
                ecosystem="npm",
                manifest_path=str(path),
                scope="development" if package_data.get("dev") else "runtime",
                package_url=f"pkg:npm/{name}",
            )
        )
    return deps


def parse_requirements(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(("-", "git+")):
            continue
        match = REQUIREMENT_RE.match(stripped)
        if not match:
            continue
        name, operator, version = match.groups()
        deps.append(
            Dependency(
                name=name,
                version=version if operator in {"==", "==="} else None,
                ecosystem="PyPI",
                manifest_path=str(path),
                scope="runtime",
                package_url=f"pkg:pypi/{name.lower()}",
            )
        )
    return deps


def parse_yarn_lock(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    current_names: list[str] = []
    current_version: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.rstrip()
        if line and not line.startswith(" ") and line.endswith(":"):
            if current_names and current_version:
                deps.extend(_npm_lock_dependencies(current_names, current_version, path))
            current_names = [_yarn_key_to_name(item) for item in line[:-1].split(",")]
            current_version = None
        elif line.strip().startswith("version "):
            current_version = line.split("version ", 1)[1].strip().strip('"')
    if current_names and current_version:
        deps.extend(_npm_lock_dependencies(current_names, current_version, path))
    return deps


def parse_pnpm_lock(path: Path, include_dev: bool) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = raw_line.strip().strip("'\"")
        if not stripped.startswith("/"):
            continue
        key = stripped.split(":", 1)[0].strip("'\"")
        parts = key.strip("/").split("/")
        if len(parts) < 2:
            continue
        if parts[0].startswith("@") and len(parts) >= 3:
            name = f"{parts[0]}/{parts[1]}"
            version = parts[2].split("_", 1)[0]
        else:
            name = parts[0]
            version = parts[1].split("_", 1)[0]
        deps.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="npm",
                manifest_path=str(path),
                scope="runtime" if include_dev else "unknown",
                package_url=f"pkg:npm/{name}",
            )
        )
    return deps


def parse_pyproject(path: Path, include_dev: bool) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
    deps: list[Dependency] = []

    for raw in data.get("project", {}).get("dependencies", []):
        dep = _dependency_from_python_spec(raw, path, "runtime")
        if dep:
            deps.append(dep)

    optional = data.get("project", {}).get("optional-dependencies", {})
    if include_dev:
        for specs in optional.values():
            for raw in specs:
                dep = _dependency_from_python_spec(raw, path, "development")
                if dep:
                    deps.append(dep)

    poetry = data.get("tool", {}).get("poetry", {})
    for name, raw_version in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        deps.append(_poetry_dependency(name, raw_version, path, "runtime"))

    if include_dev:
        groups = poetry.get("group", {})
        for group_data in groups.values():
            for name, raw_version in group_data.get("dependencies", {}).items():
                deps.append(_poetry_dependency(name, raw_version, path, "development"))

        for name, raw_version in poetry.get("dev-dependencies", {}).items():
            deps.append(_poetry_dependency(name, raw_version, path, "development"))

    return deps


def parse_poetry_lock(path: Path, include_dev: bool) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
    deps: list[Dependency] = []
    for package in data.get("package", []):
        category = package.get("category") or "main"
        groups = package.get("groups") or [category]
        is_dev = category == "dev" or "dev" in groups
        if is_dev and not include_dev:
            continue
        name = package.get("name")
        version = package.get("version")
        if name:
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="PyPI",
                    manifest_path=str(path),
                    scope="development" if is_dev else "runtime",
                    package_url=f"pkg:pypi/{name.lower()}",
                )
            )
    return deps


def parse_pipfile_lock(path: Path, include_dev: bool) -> list[Dependency]:
    data = _load_json(path)
    deps: list[Dependency] = []
    for section, scope in (("default", "runtime"), ("develop", "development")):
        if scope == "development" and not include_dev:
            continue
        for name, package_data in data.get(section, {}).items():
            raw_version = package_data.get("version") if isinstance(package_data, dict) else str(package_data)
            deps.append(
                Dependency(
                    name=name,
                    version=_clean_version(str(raw_version or "")),
                    ecosystem="PyPI",
                    manifest_path=str(path),
                    scope=scope,
                    package_url=f"pkg:pypi/{name.lower()}",
                )
            )
    return deps


def parse_pom(path: Path) -> list[Dependency]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    root = ET.fromstring(text)
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag.split("}")[0] + "}"

    properties: dict[str, str] = {}
    props = root.find(f"{namespace}properties")
    if props is not None:
        for child in props:
            key = child.tag.replace(namespace, "")
            if child.text:
                properties[key] = child.text.strip()

    deps: list[Dependency] = []
    for dep_node in root.findall(f".//{namespace}dependency"):
        group_id = _xml_text(dep_node, namespace, "groupId")
        artifact_id = _xml_text(dep_node, namespace, "artifactId")
        version = _xml_text(dep_node, namespace, "version")
        scope = _xml_text(dep_node, namespace, "scope") or "runtime"
        if not group_id or not artifact_id:
            continue
        if version and version.startswith("${") and version.endswith("}"):
            version = properties.get(version[2:-1], version)
        name = f"{group_id}:{artifact_id}"
        deps.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="Maven",
                manifest_path=str(path),
                scope="development" if scope == "test" else "runtime",
                package_url=f"pkg:maven/{group_id}/{artifact_id}",
            )
        )
    return deps


def parse_gradle(path: Path, include_dev: bool) -> list[Dependency]:
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    for match in GRADLE_DEP_RE.finditer(text):
        group_id, artifact_id, version = match.groups()
        line_start = text.rfind("\n", 0, match.start()) + 1
        line = text[line_start : text.find("\n", match.start())]
        is_dev = "test" in line.lower()
        if is_dev and not include_dev:
            continue
        name = f"{group_id}:{artifact_id}"
        deps.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="Maven",
                manifest_path=str(path),
                scope="development" if is_dev else "runtime",
                package_url=f"pkg:maven/{group_id}/{artifact_id}",
            )
        )
    return deps


def parse_go(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.name == "go.mod":
        in_require_block = False
        for raw_line in text.splitlines():
            stripped = raw_line.split("//", 1)[0].strip()
            if stripped == "require (":
                in_require_block = True
                continue
            if in_require_block and stripped == ")":
                in_require_block = False
                continue
            candidate = stripped.removeprefix("require ").strip()
            if not candidate or candidate.startswith(("module ", "go ", "toolchain ")):
                continue
            match = GO_REQUIRE_RE.match(candidate)
            if match:
                name, version = match.groups()
                deps.append(_go_dependency(name, version, path))
    else:
        for raw_line in text.splitlines():
            parts = raw_line.strip().split()
            if len(parts) >= 2 and parts[1].startswith("v") and not parts[0].endswith("/go.mod"):
                deps.append(_go_dependency(parts[0], parts[1], path))
    return deps


def parse_cargo(path: Path, include_dev: bool) -> list[Dependency]:
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.name == "Cargo.lock":
        for name, version in CARGO_LOCK_PACKAGE_RE.findall(text):
            deps.append(_cargo_dependency(name, version, path, "runtime"))
        return deps

    data = tomllib.loads(text)
    for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "development"), ("build-dependencies", "development")):
        if scope == "development" and not include_dev:
            continue
        for name, raw_version in data.get(section, {}).items():
            version = raw_version.get("version") if isinstance(raw_version, dict) else str(raw_version)
            deps.append(_cargo_dependency(name, _clean_version(version), path, scope))
    return deps


def parse_ruby(path: Path, include_dev: bool) -> list[Dependency]:
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.name == "Gemfile.lock":
        for name, version in GEM_LOCK_RE.findall(text):
            deps.append(_ruby_dependency(name, version.split(",")[0], path, "runtime"))
        return deps

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("gem "):
            continue
        parts = [part.strip().strip("\"'") for part in stripped.removeprefix("gem ").split(",")]
        if parts:
            version = _clean_version(parts[1]) if len(parts) > 1 else None
            deps.append(_ruby_dependency(parts[0], version, path, "runtime"))
    return deps


def parse_composer(path: Path, include_dev: bool) -> list[Dependency]:
    data = _load_json(path)
    deps: list[Dependency] = []
    if path.name == "composer.lock":
        for section, scope in COMPOSER_LOCK_PACKAGE_TYPES.items():
            if scope == "development" and not include_dev:
                continue
            for package in data.get(section, []):
                deps.append(_composer_dependency(package.get("name"), package.get("version"), path, scope))
        return [dep for dep in deps if dep.name]

    for section, scope in (("require", "runtime"), ("require-dev", "development")):
        if scope == "development" and not include_dev:
            continue
        for name, version in data.get(section, {}).items():
            if name.lower() == "php" or name.startswith("ext-"):
                continue
            deps.append(_composer_dependency(name, _clean_version(str(version)), path, scope))
    return deps


def parse_dotnet(path: Path) -> list[Dependency]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    deps: list[Dependency] = []
    for name, version in NUGET_PACKAGE_RE.findall(text):
        deps.append(_nuget_dependency(name, version, path))
    try:
        root = ET.fromstring(text)
        for node in root.iter():
            tag = node.tag.split("}", 1)[-1]
            if tag not in {"PackageReference", "PackageVersion"}:
                continue
            name = node.attrib.get("Include") or node.attrib.get("Update")
            version = node.attrib.get("Version")
            if not version:
                for child in node:
                    if child.tag.split("}", 1)[-1] == "Version" and child.text:
                        version = child.text.strip()
                        break
            if name:
                deps.append(_nuget_dependency(name, version, path))
    except ET.ParseError:
        for name, version in NUGET_REFERENCE_RE.findall(text):
            deps.append(_nuget_dependency(name, version or None, path))
        for name, version in NUGET_VERSION_CHILD_RE.findall(text):
            deps.append(_nuget_dependency(name, version, path))
    return deps


def parse_dockerfile(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for image, tag in DOCKER_FROM_RE.findall(path.read_text(encoding="utf-8", errors="ignore")):
        if image.lower() == "scratch":
            continue
        deps.append(
            Dependency(
                name=image,
                version=tag or None,
                ecosystem="Docker",
                manifest_path=str(path),
                scope="runtime",
                package_url=f"pkg:docker/{image}" + (f"@{tag}" if tag else ""),
            )
        )
    return deps


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def _npm_lock_dependencies(names: list[str], version: str, path: Path) -> list[Dependency]:
    return [
        Dependency(
            name=name,
            version=version,
            ecosystem="npm",
            manifest_path=str(path),
            scope="runtime",
            package_url=f"pkg:npm/{name}",
        )
        for name in names
        if name
    ]


def _yarn_key_to_name(key: str) -> str:
    cleaned = key.strip().strip('"').strip("'")
    if cleaned.startswith("@"):
        parts = cleaned.split("@")
        return f"@{parts[1]}" if len(parts) > 1 else cleaned
    return cleaned.split("@", 1)[0]


def _clean_version(raw: str) -> str | None:
    raw = raw.strip()
    if raw in {"*", "latest"} or raw.startswith(("file:", "git:", "workspace:")):
        return None
    if raw.startswith(("~", "^", "<", ">", "=", "!")) or " " in raw or "||" in raw:
        return None
    return VERSION_PREFIX_RE.sub("", raw).strip() or None


def _dependency_from_python_spec(raw: str, path: Path, scope: str) -> Dependency | None:
    match = REQUIREMENT_RE.match(raw)
    if not match:
        return None
    name, operator, version = match.groups()
    return Dependency(
        name=name,
        version=version if operator in {"==", "==="} else None,
        ecosystem="PyPI",
        manifest_path=str(path),
        scope=scope,
        package_url=f"pkg:pypi/{name.lower()}",
    )


def _poetry_dependency(name: str, raw_version: Any, path: Path, scope: str) -> Dependency:
    version: str | None
    if isinstance(raw_version, str):
        version = _clean_version(raw_version)
    elif isinstance(raw_version, dict):
        version = _clean_version(str(raw_version.get("version", "")))
    else:
        version = None
    return Dependency(
        name=name,
        version=version,
        ecosystem="PyPI",
        manifest_path=str(path),
        scope=scope,
        package_url=f"pkg:pypi/{name.lower()}",
    )


def _xml_text(node: ET.Element, namespace: str, name: str) -> str | None:
    child = node.find(f"{namespace}{name}")
    if child is None or child.text is None:
        return None
    return child.text.strip()


def _go_dependency(name: str, version: str, path: Path) -> Dependency:
    return Dependency(name=name, version=version.removeprefix("v"), ecosystem="Go", manifest_path=str(path), scope="runtime", package_url=f"pkg:golang/{name}")


def _cargo_dependency(name: str, version: str | None, path: Path, scope: str) -> Dependency:
    return Dependency(name=name, version=version, ecosystem="crates.io", manifest_path=str(path), scope=scope, package_url=f"pkg:cargo/{name}")


def _ruby_dependency(name: str, version: str | None, path: Path, scope: str) -> Dependency:
    return Dependency(name=name, version=version, ecosystem="RubyGems", manifest_path=str(path), scope=scope, package_url=f"pkg:gem/{name}")


def _composer_dependency(name: str | None, version: str | None, path: Path, scope: str) -> Dependency:
    return Dependency(name=name or "", version=version, ecosystem="Packagist", manifest_path=str(path), scope=scope, package_url=f"pkg:composer/{name}")


def _nuget_dependency(name: str, version: str | None, path: Path) -> Dependency:
    return Dependency(name=name, version=version, ecosystem="NuGet", manifest_path=str(path), scope="runtime", package_url=f"pkg:nuget/{name}")
