"""API request and response models."""

from datetime import date, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class OrganizationResponse(BaseModel):
    """Tenant organization visible in the active request context."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str


class AssessmentCreate(BaseModel):
    """Fields accepted when opening an assessment."""

    framework_pack_version_id: int = Field(gt=0)
    name: str = Field(min_length=1, max_length=200)


class AssessmentResponse(BaseModel):
    """Tenant-scoped assessment representation."""

    id: UUID
    name: str
    status: str
    framework_pack_version_id: int
    created_at: datetime


PolicyDocumentType = Literal["policy", "procedure", "standard", "guideline"]
PolicyDocumentStatus = Literal["draft", "approved", "retired"]
PolicyEvidenceRelationship = Literal["supports", "implements", "demonstrates"]


class PolicyControlLinkCreate(BaseModel):
    """Framework control selected for a tenant document."""

    framework_pack_version_id: int = Field(gt=0)
    control_reference: str = Field(min_length=1, max_length=200)


class PolicyEvidenceLinkCreate(BaseModel):
    """Evidence selected to substantiate a tenant document."""

    evidence_id: UUID
    relationship: PolicyEvidenceRelationship = "supports"
    notes: str | None = Field(default=None, max_length=2000)


class PolicyDocumentCreate(BaseModel):
    """Initial immutable revision and relationships for a tenant document."""

    title: str = Field(min_length=1, max_length=240)
    document_type: PolicyDocumentType
    owner_display_name: str | None = Field(default=None, max_length=200)
    review_due_at: date | None = None
    content: str = Field(min_length=1, max_length=200_000)
    change_summary: str = Field(default="Initial version", min_length=1, max_length=1000)
    controls: list[PolicyControlLinkCreate] = Field(default_factory=list, max_length=200)
    evidence: list[PolicyEvidenceLinkCreate] = Field(default_factory=list, max_length=200)


class PolicyDocumentVersionCreate(BaseModel):
    """A new immutable revision for an existing tenant document."""

    content: str = Field(min_length=1, max_length=200_000)
    change_summary: str = Field(min_length=1, max_length=1000)


class PolicyDocumentStatusUpdate(BaseModel):
    """An explicit policy lifecycle decision."""

    status: PolicyDocumentStatus
    review_due_at: date | None = None


class PolicyControlReferenceResponse(BaseModel):
    """Framework requirement available for document cross-referencing."""

    framework_pack_version_id: int
    framework: str
    reference: str
    title: str


class PolicyEvidenceReferenceResponse(BaseModel):
    """Tenant evidence available for document linking."""

    id: UUID
    title: str
    assessment_name: str
    sensitivity: str
    observed_at: datetime


class PolicyReferenceOptionsResponse(BaseModel):
    """Tenant-valid controls and evidence selectable by a document editor."""

    controls: list[PolicyControlReferenceResponse]
    evidence: list[PolicyEvidenceReferenceResponse]


class PolicyDocumentSummaryResponse(BaseModel):
    """Policy library row with relationship coverage counts."""

    id: UUID
    title: str
    document_type: PolicyDocumentType
    status: PolicyDocumentStatus
    owner_display_name: str | None
    review_due_at: date | None
    current_version: int
    control_count: int
    evidence_count: int
    updated_at: datetime


class PolicyDocumentVersionResponse(BaseModel):
    """One immutable policy or procedure revision."""

    id: UUID
    version_number: int
    content: str
    change_summary: str
    authored_by: UUID
    created_at: datetime


class PolicyControlLinkResponse(BaseModel):
    """Control cross-reference retained with a tenant document."""

    framework_pack_version_id: int
    framework: str
    control_reference: str
    control_title: str
    linked_at: datetime


class PolicyEvidenceLinkResponse(BaseModel):
    """Evidence relationship retained with a tenant document."""

    evidence_id: UUID
    evidence_title: str
    relationship: PolicyEvidenceRelationship
    notes: str | None
    linked_at: datetime


class PolicyDocumentResponse(PolicyDocumentSummaryResponse):
    """Complete tenant document with revisions and compliance relationships."""

    versions: list[PolicyDocumentVersionResponse]
    controls: list[PolicyControlLinkResponse]
    evidence: list[PolicyEvidenceLinkResponse]


class PolicyAgreementCreate(BaseModel):
    """Recipient and validity selected for an approved document version."""

    recipient_email: str = Field(
        min_length=3,
        max_length=320,
        pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$",
    )
    recipient_display_name: str | None = Field(default=None, max_length=200)
    expires_in_days: int = Field(default=7, ge=1, le=30)
    recurrence_days: int | None = Field(default=None, ge=30, le=1095)
    prompt_before_days: int = Field(default=14, ge=0, le=90)
    schedule_basis: str | None = Field(default=None, max_length=120)


class PolicyAgreementResponse(BaseModel):
    """Redacted administrator view of one acknowledgement request."""

    id: UUID
    policy_document_id: UUID
    policy_version: int
    recipient_email: str
    recipient_display_name: str | None
    document_sha256: str
    status: Literal["pending", "acknowledged", "revoked", "expired"]
    expires_at: datetime
    created_at: datetime
    acknowledged_at: datetime | None
    revoked_at: datetime | None
    signer_display_name: str | None
    identity_assurance: Literal["email_link", "oidc"] | None
    recurrence_days: int | None
    prompt_before_days: int
    next_review_at: datetime | None
    schedule_basis: str | None
    renewal_available: bool


class PolicyAgreementCreatedResponse(PolicyAgreementResponse):
    """New acknowledgement request including its one-time-delivered bearer token."""

    token: str


class PolicyAgreementCadenceSuggestion(BaseModel):
    """Advisory recurrence derived from a tenant's assessed frameworks."""

    key: str
    label: str
    recurrence_days: int
    prompt_before_days: int
    rationale: str
    source_label: str
    source_url: str
    qualification: str


class PolicyAgreementTokenRequest(BaseModel):
    """Recipient-specific acknowledgement link credential."""

    token: str = Field(min_length=40, max_length=500)


class PolicyAgreementInspectionResponse(BaseModel):
    """Exact document and attestation visible to the intended recipient."""

    request_id: UUID
    organization_name: str
    document_title: str
    document_type: PolicyDocumentType
    version_number: int
    document_content: str
    document_sha256: str
    recipient_email: str
    recipient_display_name: str | None
    attestation_text: str
    agreement_status: Literal["pending"]
    expires_at: datetime
    acknowledged_at: datetime | None


class PolicyAgreementAcknowledge(PolicyAgreementTokenRequest):
    """Typed electronic signature and explicit affirmative consent."""

    signer_display_name: str = Field(min_length=2, max_length=200)
    agreed: Literal[True]


class PolicyAcknowledgementReceiptResponse(BaseModel):
    """Immutable receipt returned after successful acknowledgement."""

    acknowledgement_id: UUID
    signed_at: datetime
    signed_document_sha256: str
    signed_version: int


ResponsibilityParty = Literal["customer", "msp", "vendor"]
ResponsibilityRaci = Literal["responsible", "accountable", "consulted", "informed"]
ResponsibilityDeliveryModel = Literal["customer", "msp", "shared", "vendor"]
ResponsibilityTargetType = Literal["policy", "control"]


class ResponsibilityRoleCreate(BaseModel):
    """Tenant-defined operational role, distinct from application authorization."""

    name: str = Field(min_length=2, max_length=160, pattern=r".*\S.*")
    description: str | None = Field(default=None, max_length=1000)
    party: ResponsibilityParty


class ResponsibilityHolderCreate(BaseModel):
    """Named person currently filling an operational role."""

    display_name: str = Field(min_length=2, max_length=200, pattern=r".*\S.*")
    email: str | None = Field(default=None, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    is_primary: bool = False
    starts_on: date | None = None
    ends_on: date | None = None


class ResponsibilityHolderResponse(ResponsibilityHolderCreate):
    """Named role holder visible in a tenant responsibility matrix."""

    id: UUID
    app_user_id: UUID | None
    created_at: datetime


class ResponsibilityRoleResponse(BaseModel):
    """Organizational role and the people currently filling it."""

    id: UUID
    name: str
    description: str | None
    party: ResponsibilityParty
    status: Literal["active", "inactive"]
    created_at: datetime
    holders: list[ResponsibilityHolderResponse]


class ResponsibilityAssignmentCreate(BaseModel):
    """RACI responsibility for one tenant policy or assessed control."""

    role_id: UUID
    target_type: ResponsibilityTargetType
    policy_document_id: UUID | None = None
    framework_pack_version_id: int | None = Field(default=None, gt=0)
    control_reference: str | None = Field(default=None, max_length=240)
    raci: ResponsibilityRaci
    delivery_model: ResponsibilityDeliveryModel
    notes: str | None = Field(default=None, max_length=1000)


class ResponsibilityAssignmentResponse(BaseModel):
    """Resolved responsibility row for display and audit review."""

    id: UUID
    role_id: UUID
    role_name: str
    role_party: ResponsibilityParty
    target_type: ResponsibilityTargetType
    target_key: str
    target_title: str
    framework: str | None
    raci: ResponsibilityRaci
    delivery_model: ResponsibilityDeliveryModel
    notes: str | None
    assigned_at: datetime


class ResponsibilityOptionsResponse(BaseModel):
    """Tenant policies and assessed controls eligible for responsibility mapping."""

    policies: list[dict[str, Any]]
    controls: list[dict[str, Any]]


class ResponsibilityMatrixResponse(BaseModel):
    """Complete tenant role catalog, mapping rows, and eligible targets."""

    roles: list[ResponsibilityRoleResponse]
    assignments: list[ResponsibilityAssignmentResponse]
    options: ResponsibilityOptionsResponse


CollectionMethod = Literal["manual", "api", "endpoint", "browser", "import"]
EvidenceSensitivity = Literal["internal", "confidential", "security_record", "cji"]
ReviewDecision = Literal["accepted", "rejected"]
StorageProvider = Literal["azure", "s3"]
ThemePreference = Literal["light", "dark"]
ClientAccessRole = Literal["customer_admin", "control_owner", "reviewer", "auditor"]
ScanStatus = Literal["pending", "clean", "quarantined", "error"]
ObjectLockMode = Literal["none", "governance", "compliance"]
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024


class ClientAccessRoleResponse(BaseModel):
    """Documented tenant access profile available for a client invitation."""

    id: ClientAccessRole
    name: str
    description: str
    permissions: list[str]


class OrganizationInvitationCreate(BaseModel):
    """Client personnel and access profile selected by a tenant administrator."""

    email: str = Field(
        min_length=3,
        max_length=320,
        pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$",
    )
    display_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r".*\S.*",
    )
    role: ClientAccessRole
    expires_in_days: int = Field(default=7, ge=1, le=30)


class ExternalAuditorInvitationCreate(BaseModel):
    """External auditor invited with a fixed read-only tenant role."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(
        min_length=3,
        max_length=320,
        pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$",
    )
    display_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        pattern=r".*\S.*",
    )
    expires_in_days: int = Field(default=7, ge=1, le=30)


class OrganizationInvitationResponse(BaseModel):
    """Redacted tenant invitation lifecycle state."""

    id: UUID
    email: str
    display_name: str | None
    role: ClientAccessRole
    status: Literal["pending", "accepted", "revoked", "expired"]
    expires_at: datetime
    created_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None


class OrganizationInvitationCreatedResponse(OrganizationInvitationResponse):
    """Invitation response that returns its bearer token exactly once."""

    token: str


class OrganizationInvitationAccept(BaseModel):
    """One-time bearer invitation accepted by client personnel."""

    token: str = Field(min_length=40, max_length=500)
    display_name: str = Field(min_length=1, max_length=200, pattern=r".*\S.*")


class OrganizationInvitationAcceptedResponse(BaseModel):
    """Development identity established after consuming an invitation."""

    organization_id: UUID
    organization_name: str
    actor_id: UUID
    role: ClientAccessRole


class AuthorizedOrganizationResponse(BaseModel):
    """One active tenant membership available to the current identity."""

    id: UUID
    name: str
    slug: str
    role: str


class UserPreferencesUpdate(BaseModel):
    """Mutable preferences stored with the authenticated user profile."""

    theme: ThemePreference


class UserPreferencesResponse(UserPreferencesUpdate):
    """Current server-backed preferences for the authenticated user."""

    updated_at: datetime | None


class EvidenceObservationCreate(BaseModel):
    """Provenance and integrity metadata for a newly received artifact."""

    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    collection_method: CollectionMethod = "manual"
    source_type: str = Field(min_length=1, max_length=100)
    source_identifier: str | None = Field(default=None, max_length=500)
    observed_at: AwareDatetime
    artifact_name: str = Field(min_length=1, max_length=255)
    media_type: str = Field(min_length=1, max_length=255)
    byte_size: int = Field(ge=0, le=MAX_ARTIFACT_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sensitivity: EvidenceSensitivity = "confidential"
    normalized_facts: dict[str, Any] = Field(default_factory=dict)


class EvidenceReviewCreate(BaseModel):
    """A human review decision appended to an evidence observation."""

    decision: ReviewDecision
    rationale: str = Field(min_length=1, max_length=4000)


class EvidenceReviewResponse(BaseModel):
    """An immutable evidence review ledger entry."""

    id: UUID
    decision: ReviewDecision
    rationale: str
    reviewed_by: UUID
    reviewed_at: datetime


class EvidenceObservationResponse(BaseModel):
    """Tenant-scoped evidence metadata and its latest review decision."""

    id: UUID
    assessment_id: UUID
    title: str
    description: str | None
    collection_method: CollectionMethod
    source_type: str
    source_identifier: str | None
    observed_at: datetime
    received_at: datetime
    artifact_name: str
    media_type: str
    byte_size: int
    sha256: str
    sensitivity: EvidenceSensitivity
    normalized_facts: dict[str, Any]
    submitted_by: UUID
    storage_provider: StorageProvider | None = None
    latest_review: EvidenceReviewResponse | None = None
    lifecycle: "EvidenceLifecycleResponse | None" = None


class EvidenceUploadResponse(BaseModel):
    """Short-lived instructions for uploading an artifact directly to storage."""

    id: UUID
    provider: StorageProvider
    method: Literal["PUT"]
    url: str
    headers: dict[str, str]
    expires_at: datetime


class EvidenceDownloadResponse(BaseModel):
    """Short-lived read authorization for a clean evidence artifact."""

    url: str
    expires_at: datetime


class EvidenceLifecycleResponse(BaseModel):
    """Operational scan, retention, and legal-hold state."""

    scan_status: ScanStatus
    scan_engine: str | None
    scan_detail: str | None
    scanned_at: datetime | None
    retention_until: datetime
    object_lock_mode: ObjectLockMode
    legal_hold: bool
    legal_hold_reason: str | None
    updated_at: datetime


class EvidenceScanResult(BaseModel):
    """Result submitted by an authorized malware-scanning worker."""

    status: Literal["clean", "quarantined", "error"]
    engine: str = Field(min_length=1, max_length=128)
    detail: str | None = Field(default=None, max_length=2000)


class EvidenceLegalHoldUpdate(BaseModel):
    """Explicit legal-hold transition and its required justification."""

    enabled: bool
    reason: str | None = Field(default=None, min_length=1, max_length=2000)


class EvidenceRetentionPolicyUpdate(BaseModel):
    """Tenant-wide defaults for newly committed evidence artifacts."""

    retention_days: int = Field(ge=1, le=36500)
    object_lock_mode: ObjectLockMode = "none"


class EvidenceRetentionPolicyResponse(EvidenceRetentionPolicyUpdate):
    """Current tenant retention defaults."""

    updated_at: datetime


class MicrosoftConnectionCreate(BaseModel):
    """Microsoft Graph application connection for one mapped customer tenant."""

    display_name: str = Field(min_length=1, max_length=255)
    external_tenant_id: UUID
    cloud: Literal["commercial", "gcc_high", "dod"] = "commercial"
    client_id: UUID
    client_secret: str = Field(min_length=16, max_length=4096, repr=False)


class MicrosoftConnectionResponse(BaseModel):
    """Redacted Microsoft Graph connection metadata."""

    id: UUID
    display_name: str
    external_tenant_id: str
    cloud: str
    client_id: str
    status: str
    last_success_at: datetime | None
    last_error: str | None
    created_at: datetime


class SiteCreate(BaseModel):
    """Tenant site used to scope endpoint enrollment."""

    name: str = Field(min_length=1, max_length=255)


class SiteResponse(BaseModel):
    """Endpoint collector site."""

    id: UUID
    name: str
    created_at: datetime


class AgentEnrollmentTokenCreate(BaseModel):
    """Bounded one-time or deployment enrollment authorization."""

    site_id: UUID
    allowed_platforms: list[Literal["windows", "macos", "linux"]] = Field(min_length=1)
    expires_at: AwareDatetime
    max_uses: int = Field(default=1, ge=1, le=10000)


class AgentEnrollmentTokenResponse(BaseModel):
    """Enrollment secret returned exactly once."""

    id: UUID
    token: str
    expires_at: datetime


class AgentEnrollmentExchange(BaseModel):
    """Initial machine enrollment request."""

    token: str
    platform: Literal["windows", "macos", "linux"]
    hostname: str = Field(min_length=1, max_length=255)
    public_key: str = Field(min_length=32, max_length=8192)
    agent_version: str = Field(min_length=1, max_length=64)


class AgentEnrollmentResponse(BaseModel):
    """New device identity and secret credential returned once."""

    device_id: UUID
    credential: str


class AgentObservationCreate(BaseModel):
    """Versioned allow-listed posture facts from an enrolled endpoint."""

    idempotency_key: UUID
    schema_version: str = Field(pattern=r"^v[0-9]+$")
    observed_at: AwareDatetime
    facts: dict[str, Any]


class AgentObservationResponse(BaseModel):
    """Accepted endpoint observation."""

    device_id: UUID
    idempotency_key: UUID
    received_at: datetime
