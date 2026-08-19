# Client tenant access

Watchtower uses named access profiles for client personnel. Administrators select a profile when creating an invitation; they cannot assemble ad hoc permissions or grant an MSP role through the client invitation flow. This keeps authorization reviews and audit exports understandable.

| Access profile | Intended use | Current capabilities |
| --- | --- | --- |
| Customer administrator | Client program lead | Client access, assessments, evidence submission/review, integrations, and endpoints |
| Control owner | Person responsible for implementing controls | Assessment work, evidence submission, and evidence reading |
| Evidence reviewer | Independent client reviewer | Evidence review and reading |
| Read-only auditor | Auditor or approved observer | Read-only assessments, evidence, and audit activity |

Only `customer_admin` and `msp_admin` memberships may create, list, or revoke client invitations. The API rejects MSP roles in invitation payloads.

## Invitation lifecycle

1. An administrator chooses an email address, optional display name, access profile, and expiration of 1–30 days.
2. Watchtower returns a cryptographically random bearer token exactly once and stores only its SHA-256 hash.
3. The web application places that token in a URL fragment (`#invite=...`), which is not transmitted in HTTP requests, and applies a `no-referrer` policy.
4. Acceptance atomically consumes the token, creates or resolves the user, activates exactly one tenant membership, and appends an `invitation.accepted` audit event.
5. Expired, revoked, replayed, malformed, and cross-tenant invitation operations fail without exposing neighboring tenant state.

Creation, acceptance, and revocation are recorded in the append-only tenant audit ledger. Invitation listings never return the bearer token or its hash.

## Delivery and production identity

The current vertical slice shows the acceptance link once for manual delivery through an MSP-approved channel. Automatic email delivery requires a future transactional email provider, tenant-specific templates, rate limits, bounce handling, and delivery audit events.

The current acceptance exchange provisions the development identity used by the local header adapter. Production deployments already reject that adapter; invitation acceptance will remain unavailable there until the production OIDC identity adapter can bind the invitation email to a verified identity-provider claim. The bearer token must not become the user's long-term authentication credential.

## API

- `GET /v1/access/roles`
- `GET /v1/invitations`
- `POST /v1/invitations`
- `DELETE /v1/invitations/{invitation_id}`
- `POST /v1/invitations:accept`

The generated [OpenAPI specification](../api/openapi.json) and [Postman collection](../api/postman/watchtower.postman_collection.json) contain the complete request and response contracts.
