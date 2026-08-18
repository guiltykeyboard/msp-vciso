# Product decision: build an MSP-first compliance platform

Date: 2026-08-18  
Status: proposed

## Decision

Build an open-source, self-hostable MSP compliance control plane, but do not begin by rebuilding every generic GRC feature. The core product must serve customers across industries. Deliver a differentiated vertical slice first and integrate proven open-source collectors and security tools; treat law-enforcement support as an important accommodation and content specialization, not an exclusive product category.

The project should remain capable of importing or interoperating with Comp AI, CISO Assistant, Prowler, FleetDM/osquery, and OSCAL rather than making one of those projects a permanent architectural dependency. These projects are also approved implementation sources when the exact upstream revision, file-level license boundary, attribution, and maintenance approach are documented under the upstream reuse policy.

## Why

The target operating model has an unusual combination:

- a mix of common, contractual, sector-specific, and jurisdiction-specific requirements;
- limited budgets and small teams;
- MSP-managed shared operations but legally separate customer records;
- endpoint, Microsoft 365, identity, backup, and network evidence needs;
- customer-specific deadlines, approvals, and records classifications;
- customers with different sensitivity levels, including environments subject to CJI requirements.

Generic compliance SaaS products can automate common startup frameworks, but their pricing, tenant model, and content model are often a poor fit for an MSP serving many smaller customers. Traditional open-source GRC tools can lower license cost but usually require separate discovery/evidence plumbing.

## Options considered

### Buy a commercial automation platform

Fastest for common integrations, but five-figure minimums are incompatible with the intended customer base. MSP/referral arrangements do not solve the end-customer affordability or uncommon-framework problem.

### Deploy a traditional open-source GRC product

Eramba Community and SimpleRisk Core are credible low-cost options for moving away from spreadsheets. CISO Assistant is the strongest current open-source product to pilot for multi-framework GRC and custom framework content. These are worthwhile short-term pilots, but discovery, endpoint evidence, MSP-wide operations, and specialized obligations such as Ohio statutory workflows would still need integration or custom development.

### Fork Comp AI wholesale

Comp AI is technically attractive: active AGPL code, organization-scoped data, integrations, evidence automation, AI features, and an Electron device agent. It is the closest product reference to the desired experience.

However, the current upstream repository describes local development more clearly than production self-hosting, says Docker deployment instructions are forthcoming, and relies on services such as Vercel, Trigger.dev, Upstash, and Browserbase in important paths. A wholesale fork would create a large upstream merge and operations burden before proving the MSP operating model and specialized workflows. Its open-core boundary must also be reviewed feature by feature.

Decision: inspect and reuse eligible upstream source deliberately rather than recreating proven components by default. Preserve exact provenance and notices, satisfy AGPL network-source obligations for derivative work, and exclude commercially licensed directories such as Comp AI's `/ee` unless a separate grant is obtained.

### Focused greenfield control plane

This costs more engineering than configuring an existing GRC, but gives direct control over MSP tenancy, framework packs, evidence provenance, deployment, configurable obligations, and specialized records handling. Scope control is the key: integrations and generic features must be added only when they serve real pilot customers.

## Recommended delivery sequence

### Phase 0 — two-week validation

- Deploy CISO Assistant and Comp AI in test environments.
- Import one broadly applicable baseline plus a small Ohio 9.64 pack and representative CJIS subset.
- Test MSP organization switching, customer-scoped roles, evidence export, and backup/restore.
- Test the Comp AI endpoint agent against representative Windows workstations without CJI.
- Interview administrators from at least two different customer sectors, an MSP technical operator, and a CJIS/security contact about the evidence packets they actually need.

### Phase 1 — usable vertical slice

- Tenant provisioning and roles.
- Framework-pack import/versioning.
- Assessment and applicability workflow.
- Evidence upload/provenance/review.
- Configurable obligation and deadline workflow, demonstrated by Ohio program adoption and incident reporting.
- Windows posture collector for a narrowly approved fact set.
- Reviewer-ready export with redaction.

### Phase 2 — MSP efficiency

- Cross-tenant exception dashboard that exposes status but not evidence contents by default.
- Microsoft 365/Entra, RMM/PSA, vulnerability, backup, and identity evidence connectors chosen from pilot demand.
- Shared control library and evidence reuse within, never across, a tenant.
- Recurring collection, evidence freshness, remediation tickets, and notifications.

### Phase 3 — managed hosting

- Automated tenant provisioning, metering, support tooling, disaster recovery, upgrade channels, and public security documentation.
- Pricing based on managed organizations/endpoints and service level, with a genuinely useful free self-hosted edition.

## Affordability target

License cost should not be the barrier. A reasonable initial hypothesis is:

- community/self-hosted: free AGPL;
- MSP managed hosting: low platform base plus modest per-organization or endpoint bands;
- implementation/content services: transparent one-time or hourly work;
- no auditor seat charge and no five-figure entry tier.

Validate willingness to pay before treating these as published prices. Hosting, support, content maintenance, and liability—not an artificial feature wall—should fund the project.

## Non-goals for the first release

- issuing a certification or legal opinion;
- storing operational CJI;
- replacing a customer's SIEM, RMM, MDM, PSA, or incident-response platform;
- supporting every compliance framework;
- autonomous AI remediation or compliance approval;
- building a public trust center before the evidence system is trustworthy.

## Success criteria

A successful pilot lets one MSP prepare and maintain evidence for customers with materially different compliance profiles—for example, a commercial customer using a common security baseline and a public-sector customer with Ohio 9.64/CJIS obligations—without cross-tenant leakage. It identifies stale or missing evidence automatically, tracks specialized deadlines where applicable, and exports reviewer-ready packets for materially less than a commercial platform minimum.
