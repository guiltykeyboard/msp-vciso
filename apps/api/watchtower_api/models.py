"""API request and response models."""

from datetime import datetime
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


CollectionMethod = Literal["manual", "api", "endpoint", "browser", "import"]
EvidenceSensitivity = Literal["internal", "confidential", "security_record", "cji"]
ReviewDecision = Literal["accepted", "rejected"]
StorageProvider = Literal["azure", "s3"]
ThemePreference = Literal["light", "dark"]
ScanStatus = Literal["pending", "clean", "quarantined", "error"]
ObjectLockMode = Literal["none", "governance", "compliance"]
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024


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
