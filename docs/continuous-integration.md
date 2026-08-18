# Continuous integration trust model

Watchtower treats a green check as evidence about the exact commit, not merely the last commit that happened to match a path filter. The normal validation workflows run for every pull request and every push to `main`.

Required checks:

- `lint`: Pylint, actionlint, and repository workflow security policy;
- `api-tests`: API behavior, PostgreSQL row-level tenant isolation, and generated API contract freshness;
- `framework-packs`: framework schema and content validation;
- `repository-metadata`: deterministic badge and CycloneDX SBOM freshness;
- `api-docs`: generated OpenAPI/Postman freshness and publishable documentation artifact.

## Generated metadata

`tools/update_badges.py` counts nonblank lines in recognized source files returned by Git, including non-ignored files being prepared for a commit. It excludes generated `api/` documentation, Markdown, JSON framework content, generated badges, SBOM data, dependencies, and build output. It writes the language and line-count SVG files and content-addresses their README URLs to avoid stale GitHub/browser image caches.

The metadata workflow regenerates badges and the SBOM and then runs `git diff --exit-code`. It does not push to `main`. A source change that makes generated metadata stale must include the regenerated files in the same reviewed commit.

Useful local checks:

```bash
python tools/update_badges.py
python tools/update_badges.py --check
python tools/validate_workflows.py
python tools/validate_frameworks.py
```

The SBOM must be regenerated with the Syft version pinned in `.github/workflows/repository-metadata.yml`, then normalized with `tools/normalize_sbom.py`.

## Workflow supply chain

Third-party actions use full commit SHAs. `tools/validate_workflows.py` rejects tag-only action references, `[skip ci]`, `pull_request_target`, `write-all` permissions, mutable `ubuntu-latest` runner labels, and path filters on required validation workflows. Workflow jobs use explicit permissions and timeouts.

The repository should allow only GitHub-owned actions plus the explicitly approved Anchore SBOM and OpenSSF SLSA actions, and should require full-SHA pinning in repository settings.

## Release provenance

The release-provenance workflow runs only for semantic version tags. A normal branch check does not claim to have generated SLSA provenance. Tagged builds create the release source archive, generate SLSA provenance for its digest, and upload the archive to the corresponding release.
