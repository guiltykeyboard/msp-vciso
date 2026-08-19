# Organizational roles and shared responsibility

Watchtower keeps operational responsibility separate from application authorization. A tenant can document that a person is its Information Security Officer, that an MSP team performs a control, or that a vendor supplies a service without granting any of those people dashboard access. Access remains governed by tenant memberships and invitations.

## Model

Each tenant maintains reusable organizational roles with a customer, MSP, or vendor party. A role can have named holders, including effective dates and one current primary holder. Role-holder email addresses are descriptive contact data only; they are not login credentials and do not create or change a tenant membership.

Roles map to controlled policies/procedures or controls in the tenant's active assessments using RACI:

- **Responsible** performs the work. Several roles may be responsible.
- **Accountable** owns the outcome and approves the result. A target has at most one accountable role.
- **Consulted** supplies input before a decision or action.
- **Informed** receives status or outcome updates.

Every mapping also records the delivery boundary: customer-owned, MSP-owned, shared, or vendor-owned. Notes should identify handoffs, escalation conditions, exclusions, and any dependency that could otherwise make “shared” ambiguous.

## Authorization and audit behavior

Customer and MSP administrators can create roles, assign holders, add mappings, and remove mappings. Tenant auditors and other members can read the matrix but cannot alter it. All mutations produce tenant-scoped audit events. PostgreSQL row-level security and composite tenant foreign keys prevent cross-customer role, policy, and mapping relationships.

Controls offered for mapping come only from framework packs used by that tenant's active assessments. Policies offered for mapping are the tenant's non-retired controlled documents.

## Current boundary and next steps

This first slice documents the current operating model. A later lifecycle slice should add role-holder end dates and replacement workflows, role retirement, responsibility review reminders, CSV/PDF export, reusable MSP templates, and gap reporting for targets without an accountable or responsible role. Those additions should preserve the distinction between responsibility records and security permissions.
