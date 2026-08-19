# Policy and procedure library

Watchtower treats a customer's policies, procedures, standards, and guidelines as controlled compliance records. Each record belongs to one customer tenant and can be cross-referenced to the exact controls it addresses and the evidence that supports it.

## Record contents

A document records:

- its type, title, responsible owner, review date, and lifecycle state;
- an immutable sequence of numbered document versions and revision summaries;
- controls pinned to both a framework-pack version and control reference;
- evidence observations classified as supporting, implementing, or demonstrating the document; and
- append-only audit events for creation, revision, approval, and retirement.

Controls offered in the editor come only from framework packs used by the selected tenant's assessments. Evidence options come only from the selected tenant. Composite tenant foreign keys and forced PostgreSQL row-level security provide a database-level backstop against cross-customer relationships.

## Lifecycle and permissions

New records begin in `draft`. Creating a revision increments the immutable version number and returns an approved or retired document to draft for review. An MSP or customer administrator can then mark the current version `approved` or `retired`; the audit event records the exact version affected.

| Tenant role | Read | Create and revise | Approve or retire |
| --- | --- | --- | --- |
| MSP administrator | Yes | Yes | Yes |
| Customer administrator | Yes | Yes | Yes |
| MSP analyst | Yes | Yes | No |
| Control owner | Yes | Yes | No |
| Reviewer | Yes | No | No |
| External auditor | Yes | No | No |

The current release sets control and evidence relationships when the record is created. A future relationship-management workflow can add or end links without mutating the immutable document-version history.

## API

The tenant-scoped API exposes:

- `GET /v1/policies/reference-options` for eligible controls and evidence;
- `GET /v1/policies` and `GET /v1/policies/{document_id}` for discovery and audit review;
- `POST /v1/policies` to create a record and its first immutable version;
- `POST /v1/policies/{document_id}/versions` to create a revision; and
- `PUT /v1/policies/{document_id}/status` for administrator approval or retirement.

The generated [OpenAPI document](../api/openapi.json) and [Postman collection](../api/postman/watchtower.postman_collection.json) include request and response schemas for these operations.
