# Upstream projects and reuse policy

Watchtower is built upstream-first. Before implementing a substantial generic GRC, evidence, integration, or endpoint capability, contributors should inspect relevant open-source implementations and decide whether to integrate, depend on, adapt, or independently implement. “Built from source” must mean traceable reuse—not unattributed copying.

This register is an engineering aid, not legal advice. The license and repository boundary for an exact upstream revision must be verified again when code or content is imported.

## Source register

| Project | Current published boundary | What should inform Watchtower | Preferred relationship |
|---|---|---|---|
| [Comp AI](https://github.com/trycompai/comp) | AGPL-3.0 core with a separately licensed `/ee` boundary | Organization-scoped compliance data, evidence tasks, integrations, device agent, automation, AI-assisted workflows | Study and selectively adapt eligible core code; never import `/ee` code without a separate grant |
| [CISO Assistant](https://github.com/intuitem/ciso-assistant-community) | AGPL-3.0 outside the commercially licensed `enterprise` directory | Framework libraries, audit/risk models, mappings, assessment workflow, self-hosted deployment | Study and selectively adapt eligible community code; keep the enterprise boundary out of scope |
| [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | Cloud/M365 discovery, typed checks, provider adapters, finding formats, compliance mappings | Prefer integration and normalized ingestion; reuse small components when integration is insufficient |
| [Fleet](https://github.com/fleetdm/fleet) and [Orbit](https://github.com/fleetdm/fleet/tree/main/orbit) | Fleet is open core; most/free code is MIT and paid features are separately licensed. Orbit is MIT | Enrollment, agent lifecycle, update channels, query scheduling, device transparency, MSP-scale endpoint operations | Prefer Fleet/osquery integration; reuse only files whose exact license boundary is confirmed |
| [osquery](https://github.com/osquery/osquery) | Source files identify an Apache-2.0 or GPL-2.0-only choice; bundled components can differ | Cross-platform posture observations and a mature query/table ecosystem | Use as an external collector/runtime where practical; preserve query and extension provenance |
| [SimpleRisk](https://github.com/simplerisk/code) | Open-source core published as a release mirror; related repositories identify MPL-2.0 licensing | Risk, governance, test, and remediation workflows that work for small teams | Product/workflow reference first; review exact file and distribution terms before adaptation |
| [Eramba](https://github.com/eramba) | Community product is distributed publicly, but the public GitHub organization primarily exposes helpers/templates rather than a clearly licensed core repository | Practical GRC vocabulary, workflows, reporting, and low-cost self-hosted operations | Inspiration and interoperability until the exact core artifact/license is recorded and approved |
| [GovReady-Q](https://github.com/GovReady/govready-q) | GPL-3.0 | OSCAL/OpenControl interoperability, reusable compliance content, assessment-as-data | Study its content/import model and prefer standards interoperability over direct legacy coupling |

## Intake rules

Before copying or adapting upstream source, the change must record:

1. Project and canonical repository URL.
2. Exact tag or commit SHA.
3. Source file paths and the license that applies to those paths.
4. Whether the material is copied, modified, linked, invoked, or used only as design reference.
5. Required copyright, SPDX, attribution, source-offer, and notice handling.
6. The Watchtower files containing the resulting work.
7. Any trademark, content-license, patent, CLA, or commercial-edition boundary reviewed.

Record imported material in `THIRD_PARTY_NOTICES.md` in the same change. Add the component to the generated SBOM when tooling cannot discover it automatically.

## Implementation preference

Use this order unless a documented constraint justifies another choice:

1. Integrate through a stable API, file format, command, or event stream.
2. Depend on a maintained, independently versioned open-source component.
3. Adapt a focused upstream module with full provenance and license compliance.
4. Implement independently after recording why the upstream options do not fit.

Large source imports require an architecture decision. Do not create an unmaintainable hybrid by copying an upstream application's entire persistence or UI layer for one feature.

## Boundaries

- Watchtower's AGPL license does not make commercially licensed upstream code reusable.
- A repository described as “open core” must be reviewed by file path, not by its marketing-level license label.
- Framework catalogs, policy templates, check text, logos, screenshots, and documentation can have licenses different from application code.
- Preserve behavior and interoperability where useful, but do not copy upstream trademarks or present Watchtower as an official edition of another project.
- AI-assisted adaptation follows the same provenance and license rules as manual adaptation.
- Prefer contributing generally useful fixes upstream instead of carrying private patches indefinitely.
