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
    byte_size: int = Field(ge=0)
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
    latest_review: EvidenceReviewResponse | None = None
