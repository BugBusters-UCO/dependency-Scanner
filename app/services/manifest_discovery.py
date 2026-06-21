from pathlib import Path


MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "packages.config",
    "Directory.Packages.props",
    "Dockerfile",
}

MANIFEST_SUFFIXES = {
    ".csproj",
    ".vbproj",
    ".fsproj",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
}


def discover_manifests(root: Path, max_depth: int) -> list[Path]:
    manifests: list[Path] = []
    root = root.resolve()

    def walk(current: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            return

        for entry in entries:
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    walk(entry, depth + 1)
            elif entry.name in MANIFEST_NAMES or entry.suffix.lower() in MANIFEST_SUFFIXES:
                manifests.append(entry)

    walk(root, 0)
    return sorted(manifests)
