# End-user policy acknowledgements

Watchtower can send a recipient-specific link for an approved policy or procedure and retain a defensible electronic acknowledgement of the exact version presented. This workflow is intended for internal policy attestations such as acceptable-use, security-awareness, and process agreements. It is not a qualified digital-signature service, a substitute for legal advice, or a guarantee that a particular jurisdiction will accept the record.

## Recipient and identity model

An acknowledgement recipient is an end user, not automatically a tenant member. The link authorizes access to one document version only and does not expose the dashboard, controls, evidence, other recipients, or any other tenant resource. A recipient can therefore acknowledge an internal policy without receiving customer-administrator, control-owner, reviewer, or auditor permissions.

For development, the existing insecure identity adapter permits a recipient-specific bearer link so the complete workflow can be tested. Production startup rejects that adapter. A production identity adapter must require OIDC sign-in and match a verified email claim to the request recipient before inspection or signing. The URL-fragment token is then only a request locator and bootstrap secret; it is not the authenticated session. The receipt's identity-assurance field distinguishes the development `email_link` path from future verified `oidc` acknowledgement.

End-user login should use the same global user identity model as tenant access, while keeping acknowledgement entitlement separate from tenant membership. This allows one work account to receive several policies or later gain an explicit tenant role without conflating those grants.

## Record integrity

Only MSP and customer administrators can issue or revoke acknowledgement requests. Watchtower:

- permits requests only for the current approved document version;
- pins the request to that immutable version and its SHA-256 fingerprint;
- returns the recipient secret once and stores only its SHA-256 hash;
- expires the link and prevents a second pending request for the same recipient and version;
- requires a typed legal name and affirmative consent to the displayed attestation;
- atomically consumes the pending request when the recipient signs; and
- stops accepting the bearer link for inspection immediately after signing; and
- retains signer name and email, exact attestation, document fingerprint, version, timestamp, identity-assurance level, direct peer IP when valid, and user-agent in an immutable receipt.

Creating a later revision never changes an existing request or receipt. Administrators must approve the new version and issue a new acknowledgement. Request, acknowledgement, and revocation transitions are also appended to the tenant audit ledger. Forced PostgreSQL row-level security and composite tenant foreign keys prevent cross-customer associations.

## Scheduled review and re-agreement

An administrator can make a request one-time or recurring, choose a 30–1095 day cadence, and select how many days before the next due date Watchtower should surface the review prompt. The first completed acknowledgement establishes the next review date. When the prompt window opens, an administrator can create exactly one successor link. The successor uses the document's current approved version—not the version used in the prior cycle—and links back to its predecessor without modifying either receipt.

The current application surfaces due prompts and creates the one-time renewal link. Automatic email delivery belongs behind a notification adapter so a deployment can use its approved Microsoft 365, SMTP, or transactional-email service without storing plaintext link secrets in an outbox. A future worker must create and deliver the secret in one operation; it must not persist a recoverable bearer token.

Cadence suggestions are advisory and source-labeled:

- For a tenant assessed against CJIS, Watchtower suggests an annual cycle to align with annual security and privacy literacy training in [FBI CJIS Security Policy 6.1, AT-2](https://le.fbi.gov/file-repository/cjis_security_policy_v6-1_20260625.pdf/view). That training requirement does not make every internal policy signature annual, and the applicable CSA or local overlay may add requirements.
- For an Ohio political subdivision, Watchtower suggests an annual cycle aligned to the role-appropriate cybersecurity training program in [Ohio Revised Code 9.64(C)(6)](https://codes.ohio.gov/ohio-revised-code/section-9.64). The statute recognizes annual state training but does not expressly require annual policy signatures.
- For other frameworks, the annual option is an organization-defined governance baseline. NIST SP 800-53 PS-6 requires re-signing after an agreement update or at an organization-defined frequency; customer counsel, contracts, policy type, and sector overlays remain authoritative.

Material policy changes should normally trigger a new review immediately rather than waiting for the calendar schedule. Watchtower never presents a framework-derived suggestion as a legal requirement.

## API

Administrative operations require a tenant-scoped MSP or customer administrator:

- `GET /v1/policies/{document_id}/agreements`
- `POST /v1/policies/{document_id}/agreements`
- `DELETE /v1/policy-agreements/{agreement_id}`
- `POST /v1/policy-agreements/{agreement_id}/renew`
- `GET /v1/policies/agreement-cadence-suggestions`

Recipient operations accept the opaque request token and are disabled in production until the verified identity adapter is installed:

- `POST /v1/policy-agreements:inspect`
- `POST /v1/policy-agreements:acknowledge`

The generated [OpenAPI document](../api/openapi.json) and [Postman collection](../api/postman/watchtower.postman_collection.json) describe the request and response schemas.
