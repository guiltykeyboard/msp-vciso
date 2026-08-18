# Watchtower GRC

[![Lint](https://github.com/guiltykeyboard/msp-vciso/actions/workflows/lint.yml/badge.svg)](https://github.com/guiltykeyboard/msp-vciso/actions/workflows/lint.yml)
[![Framework packs](https://github.com/guiltykeyboard/msp-vciso/actions/workflows/frameworks.yml/badge.svg)](https://github.com/guiltykeyboard/msp-vciso/actions/workflows/frameworks.yml)
[![Repository metadata](https://github.com/guiltykeyboard/msp-vciso/actions/workflows/repository-metadata.yml/badge.svg)](https://github.com/guiltykeyboard/msp-vciso/actions/workflows/repository-metadata.yml)
[![SLSA provenance](https://github.com/guiltykeyboard/msp-vciso/actions/workflows/slsa-provenance.yml/badge.svg)](https://github.com/guiltykeyboard/msp-vciso/actions/workflows/slsa-provenance.yml)
![Languages](badges/languages.svg)
![Lines of code](badges/lines-of-code.svg)

Watchtower is an open-source, self-hosted compliance and evidence platform for managed service providers and the customers they support across commercial, nonprofit, and public-sector environments. It is MSP-first and framework-neutral. CJIS Security Policy 6.1 and Ohio Revised Code 9.64 are initial reference packs that prove the platform can accommodate law enforcement and other uncommon requirements without making them the product boundary.

> Project status: product and data-model foundation. This repository is not yet an audit-ready product and does not provide legal advice or certify compliance.

## Why this exists

Most compliance automation products are priced and designed for venture-backed SaaS companies. A township, village, dispatch center, or police department often cannot justify a five-figure annual platform before paying for the actual remediation work.

Watchtower is designed around a different operating model:

- One MSP workspace can serve many legally separate customer tenants.
- Frameworks are versioned data packs, so common baselines and uncommon sector, contractual, state, or local requirements use the same product model.
- Evidence includes provenance, collection time, collector version, scope, hash, reviewer decision, and expiration—not merely an uploaded file.
- Automated checks are deterministic. AI can draft, map, explain, and summarize, but cannot silently declare a control compliant.
- Self-hosting is a first-class deployment mode; a managed hosting service can use the same open-source code.

## Product direction

The recommended path is not a wholesale rewrite of Vanta or Comp AI. It is an MSP compliance control plane that can integrate with existing sources such as Microsoft 365, Entra ID, endpoint management, backup platforms, vulnerability scanners, Prowler, and a small cross-platform device collector. Sector-specific workflows are installable capabilities on top of that general foundation.

The first useful release should support:

1. MSP and customer organizations with explicit tenant-scoped roles.
2. Versioned framework packs and cross-framework control mapping.
3. Assessments, applicability decisions, implementation narratives, findings, and remediation work.
4. Manual and automated evidence with immutable provenance and reviewer approval.
5. Configurable obligations, deadlines, and sensitive-evidence handling, initially demonstrated by Ohio incident reporting and CJIS.
6. Auditor/customer read-only access and a redacted evidence export.

See [the product decision](docs/product-decision.md), [the architecture](docs/design.md), and [framework authoring](docs/framework-authoring.md).

The current machine-readable [CycloneDX SBOM](sbom/watchtower.cdx.json) and its [human-readable guide](SBOM.md) are maintained in the repository. CI regenerates the SBOM and the repository-local language/line-count badges whenever `main` changes.

## Framework packs

Framework content lives in `frameworks/` and is validated independently of the future application runtime.

```text
frameworks/
├── schema/framework-pack.schema.json
└── ohio-hb96/2025.09.30.json
```

Validate all packs with only Python's standard library:

```bash
python3 tools/validate_frameworks.py
```

The initial Ohio pack distinguishes statutory requirements, conditional duties, record classifications, and non-mandatory implementation guidance. That distinction is essential: the platform must not turn a suggested safeguard into a false statement of law.

## Architecture principles

- PostgreSQL row-level security plus application authorization for tenant isolation.
- Tenant identity derived from the authenticated session or enrollment credential, never trusted from an arbitrary request body.
- S3-compatible object storage with per-tenant keys and content hashes for evidence.
- Append-only audit events for security-sensitive actions.
- A queue-backed collector runtime with short-lived, least-privilege credentials.
- A small signed endpoint agent that sends posture facts, not user documents or CJI.
- OSCAL-compatible import/export at the boundary while keeping the authoring format approachable.

## Licensing

The project license is GNU AGPLv3 so self-hosting remains free and hosted modifications remain available to their users. Complete a dependency/license review before the first software release. Comp AI was evaluated as a reference project; no Comp AI source code is included in this repository.

## Authoritative references

- [FBI CJIS Security Policy v6.1 (June 25, 2026)](https://le.fbi.gov/file-repository/cjis_security_policy_v6-1_20260625.pdf)
- [Ohio Revised Code 9.64](https://codes.ohio.gov/ohio-revised-code/section-9.64)
- [Ohio Auditor of State Bulletin 2025-007](https://www.ohioauditor.gov/publications/bulletins/2025/2025-007.pdf)
