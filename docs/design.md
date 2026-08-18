# Architecture and security design

## Scope

Watchtower is a multi-tenant compliance system for an MSP and its customer organizations across industries. The core tenancy, assessment, evidence, automation, and review models are sector-neutral. Optional framework packs and workflow profiles accommodate specialized environments, including law enforcement. The platform stores sensitive security records, but it should not ingest regulated production data merely to prove that a system protecting that data is configured correctly; in particular, it should not ingest Criminal Justice Information (CJI) for that purpose.

The primary design constraint is defensibility: every reported status must be traceable to a requirement version, applicability decision, implementation statement, evidence observation, deterministic test, and human review.

## Trust boundaries

```text
MSP operator / customer / auditor
              |
        identity provider
              |
       web app and API
       |      |       |
 Postgres   queue   object storage
       |      |       |
       |   collectors  |
       |      |        |
       +-- append-only evidence ledger
              |
     endpoint and integration sources
```

The web/API tier, workers, database, and object store are separate trust boundaries. Collectors receive a single tenant and integration scope per job. Endpoint enrollment credentials are tenant-bound, rotatable, and distinct from user credentials.

## Tenancy model

Core entities:

- `service_provider`: the MSP boundary.
- `organization`: a customer/legal entity. Every protected business record belongs to exactly one organization.
- `user`: a human identity.
- `membership`: user-to-service-provider or user-to-organization role assignment.
- `engagement`: an MSP service relationship and its permitted support scope.

Initial roles:

- Platform operator: deployment maintenance only; no default customer evidence access.
- MSP administrator: tenant provisioning and delegated access administration.
- MSP analyst: explicitly assigned customer assessment work.
- Customer administrator: customer users, systems, and program approvals.
- Control owner: implementation and evidence submission.
- Reviewer: accepts/rejects evidence and findings.
- Auditor: time-limited read-only access to an approved assessment/data room.

Tenant isolation is enforced twice:

1. The application authorizes the membership and engagement for every request.
2. PostgreSQL row-level security limits rows to a transaction-local organization context.

An `organization_id` supplied in a URL or body never establishes authority. Background jobs carry a signed job envelope with one organization, purpose, and expiration. Object keys begin with a non-guessable tenant identifier and are authorized before a short-lived download URL is created.

## Compliance domain

```text
FrameworkPackVersion -> Requirement -> ControlObjective
                              |              |
                              v              v
                         Applicability -> Implementation
                                               |
                                  EvidenceRequirement
                                               |
                                EvidenceObservation
                                  |          |
                              TestResult   ReviewDecision
                                  |          |
                                  +-> AssessmentStatus
```

- A framework pack is immutable after publication. Corrections create a new version.
- A requirement preserves its authority, citation, modality, and effective dates.
- A reusable control objective can map to multiple framework requirements.
- Applicability is an explicit, reviewed decision with a rationale.
- Evidence observations are facts. They do not themselves equal compliance.
- Test results are produced by versioned deterministic logic.
- Assessment status is computed and may be overridden only with a recorded reviewer rationale.

Never collapse `not applicable`, `not implemented`, `not tested`, `failed`, and `stale evidence` into the same state.

## Evidence model

Each observation records:

- tenant, system/resource scope, and collection purpose;
- originating requirement/evidence request;
- source type and source account/device identifier;
- collection method (`manual`, `api`, `endpoint`, `browser`, or `import`);
- collector name, version, test definition version, and execution identifier;
- observed-at, received-at, valid-from, and expires-at timestamps;
- normalized facts used by deterministic evaluation;
- raw artifact location, media type, byte size, and SHA-256 hash;
- sensitivity (`internal`, `confidential`, `security_record`, or `cji`);
- submitter/collector identity and reviewer decision;
- supersession and retention metadata.

Raw artifacts are immutable. Redaction produces a new derivative linked to its source. Deletion is a controlled tombstone/retention workflow with an audit event; it must not rewrite assessment history.

The default endpoint collector must not enumerate user files, capture screen contents, collect browser history, or search for CJI. It should collect narrowly defined posture facts such as OS/build, disk encryption state, firewall state, screen-lock policy, supported security product health, patch age, and agent heartbeat.

## Automation and AI

Automated checks consist of:

1. A collector that returns typed observations.
2. A normalizer that removes unstable/provider-specific representation.
3. Versioned deterministic result logic.
4. A human-readable explanation showing the observed fact and expected condition.

AI may:

- suggest mappings between requirements and reusable controls;
- draft implementation narratives and evidence requests;
- summarize evidence and highlight conflicts or missing coverage;
- assist with policy drafting using cited customer facts;
- answer questions using approved tenant data with source links.

AI may not be the unrecorded source of a pass/fail result, approve its own output, invent evidence, or receive cross-tenant retrieval context. Model requests and responses must be tenant-scoped, logged, redactable, and disabled per tenant. A self-hosted/local model option is desirable for customers that prohibit external processing.

## Sector and jurisdiction accommodations

Specialized requirements use the same versioned framework, applicability, evidence, workflow, and review primitives as common security baselines. A sector profile may add content, default evidence requests, sensitivity classifications, deadlines, approval steps, and export templates. It must not create a separate tenant model or fork the core application.

Ohio 9.64 and CJIS are the first demanding examples because they exercise statutory deadlines, formal legislative approvals, non-public/security-record classifications, contractor responsibilities, and endpoint posture. Future commercial, nonprofit, insurance, healthcare, education, or other public-sector packs should be installable through the same mechanism.

## Ohio Revised Code 9.64 workflow

Ohio compliance needs capabilities beyond control checklists:

- Program adoption tracks the approving legislative authority, resolution/policy, adoption date, entity type, and applicable implementation milestone.
- Incident intake classifies the event without exposing the record broadly.
- Discovery time starts two separately visible deadlines: Ohio Homeland Security within seven days and the Auditor of State within thirty days.
- Submission evidence records when, how, by whom, and to whom each notice was sent.
- A ransomware-payment decision requires a resolution or ordinance and an explicit best-interest rationale when payment/compliance is approved.
- Program/framework records and incident reports are marked non-public; cybersecurity procurement records are marked security records.

As of this design, the Auditor bulletin's stated milestones (January 1, 2026 for counties/cities and July 1, 2026 for other entity types) have passed. The product should present overdue adoption accurately without implying that software alone establishes legal compliance.

## CJIS-specific requirements

CJIS Security Policy 6.1 is the current FBI version as of this design. The first CJIS pack must preserve the official requirement hierarchy and state/local overlays rather than use the obsolete shorthand in the previous repository README. Because the policy is a living document, published assessments must pin a version and offer an explicit upgrade/diff workflow.

Important product implications include:

- provider/contractor personnel agreements, screening, training, and access evidence;
- auditability by the CSA and FBI;
- event/content logging and retention evidence;
- encryption, key custody, media protection, and destruction evidence;
- physical location and cloud provider responsibility evidence;
- mobile/MDM configuration and device posture;
- evidence of Security Addendum acknowledgements.

The platform itself should be deployable in a way that can meet CJIS requirements, but using the platform must never be marketed as automatic “CJIS certification.” The responsible CSA and applicable state policy remain authoritative.

## Proposed runtime

Keep infrastructure boring and self-hostable:

- React/Next.js web application for operator, customer, and auditor workflows.
- Python API/workers for compliance content, integrations, exports, and AI-assisted workflows.
- PostgreSQL for transactional data and row-level security.
- Redis-compatible queue for asynchronous collection and document jobs.
- S3-compatible storage (MinIO locally; supported cloud/object store in hosted deployments).
- Go endpoint service for Windows first, followed by macOS/Linux if customer scope requires them.
- OpenTelemetry-compatible logs/metrics/traces, with security events also written to the application audit ledger.

Exact frameworks should be selected in an architecture decision record before scaffolding the production runtime. The first vertical slice should prove tenant isolation, framework import, one assessment, one manual evidence upload, one automated endpoint observation, review, and export.

## Deployment modes

- Single-customer self-host: one organization, all multi-tenant controls still active.
- MSP self-host: one service provider with many customer organizations.
- Managed service: shared control plane with strong logical isolation; optionally dedicated database/object storage for higher-risk tenants.
- Disconnected/high-security: no external AI or SaaS connectors; signed offline collector bundles and controlled imports.

## Security gates before real customer data

- Threat model and data classification approved.
- Automated negative tests for cross-tenant reads, writes, jobs, search, exports, and signed URLs.
- MFA/SSO, session management, privileged access, and break-glass logging implemented.
- Encryption/key management and backup restore tested.
- Dependency and container scanning in CI; signed releases and endpoint binaries.
- Evidence retention, legal hold, export, redaction, and deletion behavior tested.
- Independent application security review and a customer-facing security architecture document.
