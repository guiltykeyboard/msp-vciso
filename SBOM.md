# Software bill of materials

The repository currently contains documentation, JSON framework content, and a Python standard-library validation script. It has no third-party runtime dependencies.

When application dependencies are introduced, CI must generate a machine-readable CycloneDX SBOM for every release and publish it with the container/image attestations. This file will remain the human-readable summary and should not be treated as the authoritative generated SBOM.
