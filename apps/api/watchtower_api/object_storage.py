"""Direct-upload adapters for Azure Blob, S3, and S3-compatible storage."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any, Protocol

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobSasPermissions, BlobServiceClient, generate_blob_sas
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from watchtower_api.config import ObjectStorageSettings


class ObjectNotFoundError(Exception):
    """The expected object does not exist in the configured store."""


class ObjectStorageError(Exception):
    """The object provider could not complete a storage operation."""


class ObjectIntegrityError(ObjectStorageError):
    """Staged bytes or properties differ from the authorized evidence."""


@dataclass(frozen=True, slots=True)
class UploadGrant:
    """A short-lived direct-upload request returned to an authorized client."""

    method: str
    url: str
    headers: dict[str, str]
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class StoredObject:
    """Provider-normalized properties used to verify a completed upload."""

    byte_size: int
    media_type: str | None
    sha256: str | None
    expected_size: str | None


class ObjectStore(Protocol):
    """Provider-neutral operations required by the evidence upload workflow."""

    provider: str

    async def create_upload(
        self,
        object_key: str,
        media_type: str,
        byte_size: int,
        sha256: str,
        expires_at: datetime,
    ) -> UploadGrant:
        """Create a constrained direct-upload request."""

    async def finalize_upload(
        self,
        staging_key: str,
        final_key: str,
        media_type: str,
        byte_size: int,
        sha256: str,
    ) -> StoredObject:
        """Hash staged bytes and copy the verified object to an unexposed key."""


class S3ObjectStore:
    """Amazon S3 adapter that also supports explicit S3-compatible endpoints."""

    provider = "s3"

    def __init__(
        self,
        settings: ObjectStorageSettings,
        client: Any | None = None,
    ) -> None:
        self.bucket = settings.s3.bucket or ""
        self.server_side_encryption = settings.s3.server_side_encryption
        self.kms_key_id = settings.s3.kms_key_id
        client_config = Config(
            signature_version="s3v4",
            s3={"addressing_style": settings.s3.addressing_style},
        )
        self.client = client or boto3.client(
            "s3",
            region_name=settings.s3.region,
            endpoint_url=settings.s3.endpoint_url,
            config=client_config,
        )
        self.signing_client = self.client
        if client is None and settings.s3.public_endpoint_url:
            self.signing_client = boto3.client(
                "s3",
                region_name=settings.s3.region,
                endpoint_url=settings.s3.public_endpoint_url,
                config=client_config,
            )

    async def create_upload(
        self,
        object_key: str,
        media_type: str,
        byte_size: int,
        sha256: str,
        expires_at: datetime,
    ) -> UploadGrant:
        """Presign one S3 PUT with required metadata and optional encryption."""
        parameters: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": object_key,
            "ContentType": media_type,
            "Metadata": {"sha256": sha256, "expected-size": str(byte_size)},
        }
        headers = {
            "Content-Type": media_type,
            "x-amz-meta-sha256": sha256,
            "x-amz-meta-expected-size": str(byte_size),
        }
        if self.server_side_encryption:
            parameters["ServerSideEncryption"] = self.server_side_encryption
            headers["x-amz-server-side-encryption"] = self.server_side_encryption
        if self.kms_key_id:
            parameters["SSEKMSKeyId"] = self.kms_key_id
            headers["x-amz-server-side-encryption-aws-kms-key-id"] = self.kms_key_id
        seconds = max(1, int((expires_at - datetime.now(UTC)).total_seconds()))
        try:
            url = await asyncio.to_thread(
                self.signing_client.generate_presigned_url,
                "put_object",
                Params=parameters,
                ExpiresIn=seconds,
                HttpMethod="PUT",
            )
        except (ClientError, ValueError) as error:
            raise ObjectStorageError("S3 could not create an upload URL") from error
        return UploadGrant(method="PUT", url=url, headers=headers, expires_at=expires_at)

    def _finalize_upload_sync(
        self,
        staging_key: str,
        final_key: str,
        media_type: str,
        byte_size: int,
        sha256: str,
    ) -> StoredObject:
        """Verify staged S3 bytes and conditionally copy the inspected version."""
        try:
            properties = self.client.head_object(
                Bucket=self.bucket,
                Key=staging_key,
            )
            response = self.client.get_object(
                Bucket=self.bucket,
                Key=staging_key,
                IfMatch=properties["ETag"],
            )
        except ClientError as error:
            status_code = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status_code == 404 or error.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                raise ObjectNotFoundError from error
            raise ObjectStorageError("S3 could not inspect the uploaded object") from error
        digest = hashlib.sha256()
        actual_size = 0
        body = response["Body"]
        try:
            while chunk := body.read(1024 * 1024):
                actual_size += len(chunk)
                digest.update(chunk)
        except (ClientError, OSError) as error:
            raise ObjectStorageError("S3 could not read the uploaded object") from error
        metadata = properties.get("Metadata", {})
        actual = StoredObject(
            byte_size=properties.get("ContentLength"),
            media_type=properties.get("ContentType"),
            sha256=digest.hexdigest(),
            expected_size=metadata.get("expected-size"),
        )
        expected = StoredObject(
            byte_size=byte_size,
            media_type=media_type,
            sha256=sha256,
            expected_size=str(byte_size),
        )
        if actual_size != actual.byte_size or metadata.get("sha256") != sha256 or actual != expected:
            raise ObjectIntegrityError("S3 object properties or content hash do not match")
        try:
            copy_parameters: dict[str, Any] = {
                "Bucket": self.bucket,
                "Key": final_key,
                "CopySource": {"Bucket": self.bucket, "Key": staging_key},
                "CopySourceIfMatch": properties["ETag"],
                "MetadataDirective": "COPY",
            }
            if self.server_side_encryption:
                copy_parameters["ServerSideEncryption"] = self.server_side_encryption
            if self.kms_key_id:
                copy_parameters["SSEKMSKeyId"] = self.kms_key_id
            self.client.copy_object(
                **copy_parameters,
            )
        except ClientError as error:
            raise ObjectStorageError("S3 could not preserve the verified object") from error
        return actual

    async def finalize_upload(
        self,
        staging_key: str,
        final_key: str,
        media_type: str,
        byte_size: int,
        sha256: str,
    ) -> StoredObject:
        """Verify and preserve one S3 or S3-compatible staged object."""
        return await asyncio.to_thread(
            self._finalize_upload_sync,
            staging_key,
            final_key,
            media_type,
            byte_size,
            sha256,
        )


class AzureBlobObjectStore:
    """Azure Blob adapter using managed identity and user-delegation SAS tokens."""

    provider = "azure"

    def __init__(
        self,
        settings: ObjectStorageSettings,
        service_client: Any | None = None,
    ) -> None:
        self.container = settings.azure.container or ""
        self.service_client = service_client or BlobServiceClient(
            account_url=settings.azure.account_url,
            credential=DefaultAzureCredential(),
        )

    async def create_upload(
        self,
        object_key: str,
        media_type: str,
        byte_size: int,
        sha256: str,
        expires_at: datetime,
    ) -> UploadGrant:
        """Create a write-only Azure user-delegation SAS for one blob."""
        start = datetime.now(UTC) - timedelta(minutes=5)
        try:
            delegation_key = await asyncio.to_thread(
                self.service_client.get_user_delegation_key,
                key_start_time=start,
                key_expiry_time=expires_at,
            )
            token = generate_blob_sas(
                account_name=self.service_client.account_name,
                container_name=self.container,
                blob_name=object_key,
                user_delegation_key=delegation_key,
                permission=BlobSasPermissions(create=True, write=True),
                start=start,
                expiry=expires_at,
            )
            blob_client = self.service_client.get_blob_client(
                container=self.container,
                blob=object_key,
            )
        except (AzureError, ValueError, TypeError) as error:
            raise ObjectStorageError("Azure Blob could not create an upload URL") from error
        return UploadGrant(
            method="PUT",
            url=f"{blob_client.url}?{token}",
            headers={
                "Content-Type": media_type,
                "x-ms-blob-type": "BlockBlob",
                "x-ms-meta-sha256": sha256,
                "x-ms-meta-expected-size": str(byte_size),
            },
            expires_at=expires_at,
        )

    def _finalize_upload_sync(
        self,
        staging_key: str,
        final_key: str,
        media_type: str,
        byte_size: int,
        sha256: str,
    ) -> StoredObject:
        """Verify staged Azure bytes and copy them to an unexposed blob key."""
        source = self.service_client.get_blob_client(
            container=self.container,
            blob=staging_key,
        )
        try:
            properties = source.get_blob_properties()
            digest = hashlib.sha256()
            actual_size = 0
            for chunk in source.download_blob(if_match=properties.etag).chunks():
                actual_size += len(chunk)
                digest.update(chunk)
        except ResourceNotFoundError as error:
            raise ObjectNotFoundError from error
        except AzureError as error:
            raise ObjectStorageError("Azure Blob could not inspect the uploaded object") from error
        metadata = properties.metadata or {}
        actual = StoredObject(
            byte_size=properties.size,
            media_type=properties.content_settings.content_type,
            sha256=digest.hexdigest(),
            expected_size=metadata.get("expected-size"),
        )
        expected = StoredObject(
            byte_size=byte_size,
            media_type=media_type,
            sha256=sha256,
            expected_size=str(byte_size),
        )
        if actual_size != actual.byte_size or metadata.get("sha256") != sha256 or actual != expected:
            raise ObjectIntegrityError("Azure Blob properties or content hash do not match")
        start = datetime.now(UTC) - timedelta(minutes=5)
        expiry = datetime.now(UTC) + timedelta(minutes=10)
        try:
            delegation_key = self.service_client.get_user_delegation_key(
                key_start_time=start,
                key_expiry_time=expiry,
            )
            read_token = generate_blob_sas(
                account_name=self.service_client.account_name,
                container_name=self.container,
                blob_name=staging_key,
                user_delegation_key=delegation_key,
                permission=BlobSasPermissions(read=True),
                start=start,
                expiry=expiry,
            )
            destination = self.service_client.get_blob_client(
                container=self.container,
                blob=final_key,
            )
            copy_result = destination.start_copy_from_url(
                f"{source.url}?{read_token}",
                source_if_match=properties.etag,
                requires_sync=True,
            )
            if copy_result.get("copy_status") != "success":
                raise ObjectStorageError("Azure Blob did not complete the verified copy")
        except AzureError as error:
            raise ObjectStorageError("Azure Blob could not preserve the verified object") from error
        return actual

    async def finalize_upload(
        self,
        staging_key: str,
        final_key: str,
        media_type: str,
        byte_size: int,
        sha256: str,
    ) -> StoredObject:
        """Verify and preserve one staged Azure Blob object."""
        return await asyncio.to_thread(
            self._finalize_upload_sync,
            staging_key,
            final_key,
            media_type,
            byte_size,
            sha256,
        )


def create_object_store(settings: ObjectStorageSettings) -> ObjectStore | None:
    """Create the configured provider adapter, or disable upload endpoints."""
    if settings.provider == "disabled":
        return None
    if settings.provider == "s3":
        return S3ObjectStore(settings)
    if settings.provider == "azure":
        return AzureBlobObjectStore(settings)
    raise ValueError(f"Unsupported object storage provider: {settings.provider}")
