#!/usr/bin/env python3
"""Remove volatile Syft fields and normalize the committed CycloneDX SBOM."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def component_key(component: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return a stable sort key for a CycloneDX component."""
    return (
        str(component.get("type", "")),
        str(component.get("name", "")),
        str(component.get("version", "")),
        str(component.get("purl", "")),
    )


def normalize(document: dict[str, Any], source_root: Path) -> dict[str, Any]:
    """Normalize known volatile and unordered CycloneDX fields in place."""
    document.pop("serialNumber", None)
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)

    components = document.get("components")
    if isinstance(components, list):
        for component in components:
            if not isinstance(component, dict) or component.get("type") != "file":
                continue
            name = component.get("name")
            if not isinstance(name, str):
                continue
            component_path = Path(name)
            if component_path.is_absolute() and component_path.is_relative_to(source_root):
                component["name"] = component_path.relative_to(source_root).as_posix()
        components.sort(key=component_key)

    dependencies = document.get("dependencies")
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if isinstance(dependency, dict) and isinstance(dependency.get("dependsOn"), list):
                dependency["dependsOn"].sort()
        dependencies.sort(key=lambda dependency: str(dependency.get("ref", "")))
    return document


def main() -> int:
    """Normalize a CycloneDX JSON file."""
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    document = json.loads(arguments.path.read_text(encoding="utf-8"))
    normalized = normalize(document, arguments.source_root.resolve())
    arguments.path.write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
