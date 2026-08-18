# Integration architecture and roadmap

## Objective

Watchtower integrations turn vendor facts into tenant-scoped evidence observations. They are not arbitrary ETL jobs and they do not let a vendor's account hierarchy establish Watchtower authorization. Every connection, synchronization, mapping change, credential change, and collected artifact is attributable in the audit ledger.

The first connector releases should favor high-value, read-only evidence that an MSP can deploy across many customers. Write actions, remediation, ticket creation, billing sync, and destructive vendor operations are separate capabilities and remain disabled until they have explicit permissions, idempotency, approval, and audit behavior.

## Connector runtime

```text
MSP connection                         Watchtower organization
      |                                           |
      +-- vendor account discovery ---------------+
      |        explicit account/site mapping      |
      v                                           v
credential vault -> scheduled job -> connector -> normalized observations
                                      |              |
                                      |              +-> deterministic checks
                                      +-> immutable raw response + SHA-256
```

Each connector implements the same boundaries:

- `authorize`: validate a secret or delegated OAuth grant without logging it;
- `discover_scopes`: enumerate partner, customer, site, subscription, or account scopes;
- `map_scopes`: require an operator to map each vendor scope to one Watchtower organization;
- `collect`: retrieve one evidence family through a cursor/checkpoint-aware read operation;
- `normalize`: emit typed, versioned facts without discarding the raw source artifact;
- `health`: report last success, last complete success, partial/stale state, throttling, and credential expiry;
- `revoke`: disable collection and revoke/delete the local secret without deleting evidence history.

Credentials are encrypted with an envelope key, never returned after creation, and scoped to one service provider plus one vendor connection. A collection job receives a short-lived secret handle and exactly one mapped organization. Shared MSP credentials are supported, but their discovered vendor accounts must be mapped individually and unmapped accounts are quarantined from evidence ingestion.

## Delivery tiers

### Tier 1: prove the evidence pipeline

1. Microsoft 365, Entra ID, and Azure
2. Hudu
3. ConnectWise PSA
4. WatchGuard Cloud
5. SentinelOne
6. Cove Data Protection

These cover delegated cloud identity, documentation, PSA inventory, network security, endpoint security, and backup evidence. Together they exercise the connector abstractions more effectively than implementing several similar security products first.

### Tier 2: MSP security operations

- Microsoft 365 Lighthouse
- CyberDrain CIPP
- Huntress Security
- Avanan / Check Point Harmony Email & Collaboration
- Keeper Security
- ConnectWise RMM (Asio)

### Tier 3: narrower or documentation-gated sources

- BrightGauge
- Phin Security (`phinsec.io` / Phin)
- Namecheap
- Atakama
- Actifile

Tier 3 does not mean unimportant. It means the public API surface, partner access, or evidence value needs validation before committing to a production adapter.

## Requested connector catalog

| Connector | Initial evidence | Interface and tenancy notes | Implementation gate |
|---|---|---|---|
| Microsoft 365 / Entra ID | users, privileged roles, MFA registration, conditional access, secure-score facts, domains, licenses, audit configuration | Microsoft Graph with OAuth application/delegated grants; keep customer Entra tenant ID as an external scope identifier | Permission matrix, national-cloud handling, pagination/delta tests |
| Azure | subscriptions/resources, policy assignments/compliance, Defender configuration, logging and diagnostic settings | Azure Resource Manager APIs; map every subscription to a Watchtower organization and record management-tenant context | Read-only app permissions and sovereign-cloud test fixtures |
| Microsoft 365 Lighthouse | managed tenants, device compliance, malware/protection state, risk and baseline facts | Microsoft Graph `managedTenants`; many endpoints are beta and some are delegated-only. Store API version per observation and never silently substitute portal behavior | GDAP role matrix, CSP eligibility, beta-change contract tests |
| CyberDrain CIPP | tenant inventory, standards results, users, policies and CIPP-managed configuration | CIPP publishes an OpenAPI document and supports OAuth client credentials. Treat a CIPP instance as an MSP connection and each CIPP tenant as a mapped scope | Pin a tested CIPP release/spec hash and impose Watchtower-side concurrency limits |
| Hudu | companies, assets, procedures, networks, expirations, activity records and documentation freshness | `x-api-key`, instance URL, company mapping; API pagination is small and rate limited | Supplied Swagger 2.0 reference reviewed; use scoped read-only key and sanitize instance URLs |
| ConnectWise PSA | companies/sites, configurations, contacts, agreements, service tickets, projects and audit-relevant activity | Instance/region URL, company mapping, API member credentials and client ID; HTTPS only | Supplied OpenAPI reference is large and versioned; implement an allow-list rather than generating a client for all endpoints |
| ConnectWise RMM (Asio) | sites/endpoints, OS/patch state, AV/EDR state, alerts, policy and agent health | Partner/site hierarchy; the current API is gated in the ConnectWise developer network | Obtain current Asio spec and sandbox credentials; do not target the retired legacy surface |
| WatchGuard Cloud | accounts, Fireboxes, endpoint inventory/health, alerts, ThreatSync and NDR findings | Regional base URLs; service-provider and subscriber scopes; API key plus access token | Confirm licensed API families and least-privilege read scopes |
| SentinelOne | sites/groups, agents, policy, threats, exclusions and agent health | Per-console URL; partner/site hierarchy; console API Hub supplies the version-matched OpenAPI spec | User-provided console spec and read-only service-account scopes |
| Cove Backup by N-able | partners/customers, protected devices, last backup status, job/session statistics, retention and storage facts | Custom JSON-RPC endpoint, case-sensitive methods, `visa` session value, nested result envelopes, Unix timestamps and column-vector responses | Golden fixtures from a real partner tenant, redaction review, and bounded polling before production |
| Huntress Security | accounts/organizations, agents, incident reports, escalations, signals, subscriptions and audit-relevant status | REST API; user keys inherit user permissions. Account keys are deprecated. SAT uses a separate OAuth2 API | Import the official Swagger document and separate core-platform, EDR, SIEM, and SAT capabilities |
| Avanan / Check Point Harmony Email | protected entities, security events, exceptions, audit logs and service health | Regional REST endpoints; bearer token and request ID; MSP parent/child accounts use separate regional credentials | Confirm the currently licensed API generation and child-account scope behavior |
| Keeper Security | managed companies, users, teams/roles, enforcement policies, 2FA posture, audit events and license status | Keeper MSP hierarchy; Commander provides CLI/SDK automation and managed-company context switching | Approve a non-interactive service identity and distinguish metadata evidence from vault secrets; never ingest vault contents |
| Namecheap | domains, DNS/host records, expiration/renewal and security-lock facts | Query-string API, XML responses, API key plus whitelisted client IP; sandbox available | Egress-IP configuration and a strict secret/query-string logging filter |
| BrightGauge | dataset/gauge freshness and reporting coverage, where exposed | Public developer detail is insufficient for a production design; it may be more useful as an output/reporting sink than an authoritative evidence source | Vendor API documentation, auth model, rate limits, and MSP account hierarchy |
| Phin Security | customer/user enrollment, training/campaign completion, phishing results and reported-email metrics | Public material advertises open APIs but does not define a stable contract | Vendor OpenAPI/API guide and partner sandbox |
| Atakama | protected users/devices, policy/encryption posture, agent health and audit events | Public API contract not established during planning | Vendor API guide, authentication, tenancy, and export constraints |
| Actifile | devices/users, policy, sensitive-data posture, alerts and agent health | Public administration material exists, but no stable public API contract was established | Vendor API guide, tenant hierarchy, rate limits, and data-handling review |

## Cove defensive adapter

Cove's connector must isolate its protocol quirks instead of leaking them into the evidence model:

- A handwritten JSON-RPC transport sends one method per typed adapter call and preserves the exact raw response.
- Authentication/session refresh is centralized; `visa` values and device passwords/tokens are secret fields and are redacted before logs or evidence previews.
- Envelope parsing accepts only explicitly tested shapes such as `result.result`; an unexpected shape creates a visible `contract_changed` health result rather than an empty successful sync.
- Enumerations are checkpointed by partner/customer and resumable. Parallelism is bounded globally and per connection.
- Column codes/vectors are normalized only through a versioned lookup table. Unknown columns remain in raw evidence and produce a warning.
- Backup freshness records both the vendor timestamp and Watchtower receipt time in UTC. Zero, sentinel, and missing timestamps are distinct states.
- A sync can be `complete`, `partial`, `throttled`, `contract_changed`, or `failed`. Only a complete sync advances `last_complete_at`.
- Read-only methods ship first. A future write operation must re-read the resource and verify the result, matching N-able's own guidance.

Initial Cove methods should be limited to authentication, partner/customer discovery, `EnumerateAccounts`, `GetAccountInfoById`, `EnumerateAccountStatistics`, and the minimum reporting calls needed to establish the last successful backup. Test fixtures must cover nested errors, expired sessions, missing columns, oversized tenants, duplicate names, and partial storage-node failure.

## Supplied specifications

The locally supplied Hudu and ConnectWise PSA files were used as documentation references only; their contents were not treated as project instructions and are not copied into this repository.

| Reference | Format/version | SHA-256 | Planning decision |
|---|---|---|---|
| `hudu-api-docs.json` | Swagger 2.0 / Hudu API 1.0 | `2bfd4cfed88231bcdb7784db18e99ffaebf0c4182da87375757b99a15d78527f` | Configure the Hudu instance URL; never commit a customer hostname. Start with companies and read-only documentation/assets. |
| `PSA-API-ALL.json` | OpenAPI 3.0.1 / ConnectWise 2026.11 | `40fda69246eaa97acac42b0de959517c294a542ae45e2940022cc197adbbc671` | Generate no all-endpoint client. Select and test the small company/configuration/service surface needed for evidence and require HTTPS. |

## Connector acceptance criteria

A connector is production-ready only when it has:

1. tenant mapping and negative cross-tenant tests;
2. least-privilege setup instructions and secret redaction tests;
3. pagination, rate-limit, retry, expiry, and partial-result fixtures;
4. immutable raw evidence plus a deterministic normalizer version;
5. visible freshness and failure health without converting “no data” into “pass”;
6. disconnect/revocation behavior that retains the audit and evidence history;
7. a vendor contract/spec version and change-detection test;
8. documented data classes, retention, and whether regulated or customer content can be returned.

## Primary references

- [WatchGuard Cloud APIs](https://www.watchguard.com/help/docs/API/)
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0)
- [Microsoft 365 Lighthouse API](https://learn.microsoft.com/en-us/graph/managedtenants-concept-overview)
- [CyberDrain CIPP API authentication](https://docs.cipp.app/api-documentation/setup-and-authentication)
- [Hudu REST API](https://support.hudu.com/hc/en-us/articles/11422780787735-REST-API)
- [ConnectWise developer network](https://developer.connectwise.com/Best_Practices/Getting_Started)
- [Cove JSON-RPC API](https://documentation.n-able.com/covedataprotection/USERGUIDE/documentation/Content/service-management/json-api/home.htm)
- [Huntress API integrations](https://support.huntress.io/hc/en-us/categories/22524094248979-Integrations)
- [Check Point Harmony Email API overview](https://sc1.checkpoint.com/documents/Avanan_API_Reference/Topics-HEC-Avanan-API-Reference-Guide/Overview/API-Overview.htm)
- [Namecheap API](https://www.namecheap.com/support/api/intro/)
- [Keeper MSP](https://docs.keeper.io/enterprise-guide/keeper-msp)
