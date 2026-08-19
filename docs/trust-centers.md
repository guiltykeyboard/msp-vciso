# Tenant trust centers and custom domains

Each organization can publish a deliberately narrow Trust Center at the platform preview path `/trust/{organization-slug}` and, after DNS verification, at a customer-owned hostname such as `trust.customer.example`. The public surface is separate from the authenticated tenant dashboard.

## Disclosure model

A trust profile begins as a private draft. Customer and MSP administrators can publish its organization name, headline, overview, security contact, accent color, and selected resource metadata. A public resource is pinned to the exact currently approved policy version and contains only a public title, summary, document type, version number, category, and publication timestamp.

The policy body, control mappings, evidence, personnel, assessment state, internal responsibilities, and tenant identifiers are never returned by the public API. Publishing a summary is an explicit action and unpublishing it is audited. Editing the underlying policy does not silently update the public resource because the resource stays pinned to the reviewed version.

## Domain onboarding

For `trust.customer.example`, Watchtower returns two DNS requirements:

1. A TXT ownership challenge at `_watchtower-trust.trust.customer.example`.
2. A direct CNAME from `trust.customer.example` to the configured `WATCHTOWER_TRUST_CNAME_TARGET`.

Watchtower normalizes IDNA hostnames, rejects IP addresses, wildcards, apex names, malformed labels, and duplicate hostnames, and limits each tenant to five enabled domains. The platform verifies the unique TXT value before it checks the direct CNAME. Only a published profile with an active, verified hostname can resolve publicly or receive a positive TLS-issuance authorization.

Disabling a domain immediately removes it from trust-page routing and certificate authorization. The record is retained for auditability and to reduce accidental hostname reassignment.

## Azure managed hosting

For the multi-tenant hosted product, use Azure Front Door Standard or Premium in front of the application origin. Front Door is designed to associate multiple custom domains with an endpoint, supports managed TLS certificates, and places WAF and edge routing outside the application. Microsoft recommends considering stamp-based domain grouping because custom domains per Front Door profile are quota-limited. [Azure multitenant Front Door guidance](https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/service/front-door) and [Front Door domain/certificate behavior](https://learn.microsoft.com/en-ca/azure/frontdoor/domain) are the operational references.

The future Azure domain provisioner should consume only `verified` domain records, create the Front Door custom-domain resource, attach it to the trust route, request an Azure-managed certificate, and update `certificate_status` only after Azure reports deployment success. Azure credentials and subscription/resource identifiers belong in deployment configuration or managed identity—not tenant-facing records.

Azure Container Apps free managed certificates are a simpler option for a smaller self-hosted installation. Subdomains must CNAME directly to the generated Container Apps hostname; intermediate services such as Cloudflare can block issuance or renewal, and a root CAA policy must allow DigiCert. [Container Apps custom domains and managed certificates](https://learn.microsoft.com/en-us/azure/container-apps/custom-domains-managed-certificates) documents the current requirements.

## Self-hosted ACME / Let's Encrypt

[Caddy On-Demand TLS](https://caddyserver.com/docs/automatic-https#on-demand-tls) fits customer-controlled domains because certificates are obtained and renewed only for authorized hostnames. Use [the example Caddyfile](../deploy/caddy/Caddyfile.example) and keep `/v1/internal/trust-domains:authorize` reachable from Caddy on the private container network but blocked at the public edge. Caddy calls this constant-time indexed lookup with its `?domain=...` value plus a deployment secret; Watchtower returns success only for a valid secret, published tenant profile, and active domain.

Production requirements:

- Persist and back up Caddy's `/data` storage, protect the ACME account key, and configure an operational contact email.
- Expose ports 80 and 443 so ACME challenges and HTTPS redirects can complete.
- Point `WATCHTOWER_TRUST_CNAME_TARGET` at the public load balancer or Caddy hostname.
- Generate a unique high-entropy `WATCHTOWER_TRUST_TLS_AUTHORIZATION_SECRET`, provide it only to the API and Caddy, and rotate it through the deployment secret store.
- Run at least two edge instances only with supported shared certificate storage or route initial issuance consistently.
- Monitor issuance failures, renewals, CAA changes, DNS drift, certificate expiry, and disabled-domain traffic.
- Apply CA rate-limit planning before bulk onboarding. Let's Encrypt's [integration guide](https://letsencrypt.org/docs/integration-guide/) recommends guarding the ACME account key and planning certificate grouping and issuance volume.

The internal authorization endpoint does no DNS lookup by design; DNS is checked during the administrator-controlled verification workflow. This keeps the TLS handshake authorization path fast and prevents arbitrary certificate requests from turning into outbound DNS work.

## Current implementation boundary

The repository now implements publishing, public hostname resolution, TXT and CNAME verification, certificate authorization, disablement, RLS isolation, and audit logging. Caddy can use the authorization endpoint immediately. Azure resource creation and certificate-state callbacks remain deployment-plane work; the UI's `provisioning` state is authorization to begin issuance, not proof that a certificate has been deployed.
