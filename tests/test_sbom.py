"""Tests for deterministic SBOM normalization."""

from pathlib import Path

from tools.normalize_sbom import normalize


def test_root_component_reference_is_environment_independent() -> None:
    """Syft's path-derived root reference is replaced with a stable identity."""
    document = {
        "metadata": {
            "timestamp": "volatile",
            "component": {
                "bom-ref": "path-derived-value",
                "type": "file",
                "name": "watchtower-grc",
                "version": "development",
            },
        }
    }

    normalized = normalize(document, Path("/workspace"))

    assert normalized["metadata"] == {
        "component": {
            "bom-ref": "file:watchtower-grc@development",
            "type": "file",
            "name": "watchtower-grc",
            "version": "development",
        }
    }
