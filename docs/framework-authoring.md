# Framework pack authoring

Framework packs represent external obligations faithfully and separately from customer implementation. A pack is immutable after publication and must cite an authoritative source.

## Requirement modality

Use the narrowest accurate type:

- `mandatory`: the authority imposes the requirement.
- `conditional`: the authority imposes it only when the recorded condition is true.
- `guidance`: suggested implementation material that must not be reported as a legal mandate.
- `record_classification`: a confidentiality, disclosure, or handling classification.

Do not convert `may`, examples, commentary, or vendor advice into `shall`. Preserve distinct reporting deadlines as distinct requirements.

## Evidence requests

Evidence requests describe what would support a reviewer decision, not what conclusively proves compliance. Prefer a small set of high-signal evidence. Each request includes a sensitivity classification and optional freshness period.

Automated checks must name a typed collector and versioned deterministic result expression. An AI summary can accompany the result, but it cannot be the result expression.

## Versioning

- `framework_version` identifies the authority's version or effective date.
- `pack_version` uses semantic versioning for this project's representation.
- Correcting a typo without changing meaning is a patch.
- Changing requirement interpretation, evidence expectations, or mappings is a minor version.
- Moving to a new authority version is a new framework version and normally a new directory/file.

Published assessments pin an exact pack digest. Updating the catalog never silently changes a customer assessment.

## Validation

Run:

```bash
python3 tools/validate_frameworks.py
```

The validator checks the structural subset needed by the current repository, identifiers, citations, unique evidence IDs, conditional expressions, and deterministic automation rules. The JSON Schema is the contract for future application importers.

