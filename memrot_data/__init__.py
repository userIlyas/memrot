"""Paths to bundled schemas and profiles, shared by the two CLI packages."""
from pathlib import Path


def data_path(directory: str, name: str) -> Path:
    """Resolve package data in a wheel or the original editable checkout.

    Hatch copies the canonical top-level data directories into this namespace
    when building a wheel. Editable installs read those same source files.
    Resolution never depends on the caller's working directory.
    """
    package = Path(__file__).resolve().parent
    bundled = package / directory / name
    if bundled.is_file():
        return bundled
    source = package.parent / directory / name
    if (package.parent / "pyproject.toml").is_file() and source.is_file():
        return source
    raise FileNotFoundError(f"bundled resource not found: {directory}/{name}")
