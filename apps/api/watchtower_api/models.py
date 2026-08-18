"""API request and response models."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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
