# Evidence object storage

Watchtower keeps artifact bytes out of the API request path. An authorized user first requests a short-lived upload, sends the artifact directly to a private object store, and then asks Watchtower to complete the upload.

Completion does not trust client-supplied metadata as proof of integrity. The active storage adapter reads and hashes the staged bytes, verifies the authorized size, media type, and SHA-256 value, and copies the verified object to a new evidence key that was never included in the client's upload authorization. Evidence is committed only after that process succeeds.

Committed artifacts begin in `pending` scan state and cannot receive a download URL until an authorized malware-scanning worker records a `clean` result. Quarantined and failed artifacts remain unavailable. Every scan transition, legal-hold change, retention-policy change, and download authorization is written to the append-only tenant audit ledger.

The initial atomic-copy workflow limits individual artifacts to 5 GiB. Larger evidence packages should be split or represented by a signed manifest until multipart preservation is implemented.

Configure a lifecycle rule to delete incomplete objects under the `staging/` prefix after an operationally appropriate period. Keep the `evidence/` prefix private, encrypted, versioned where supported, and subject to the retention or immutability policy applicable to the tenant. Watchtower never returns an unrestricted bucket or container credential.

## Amazon S3 and AWS GovCloud

Set:

```text
WATCHTOWER_STORAGE_PROVIDER=s3
WATCHTOWER_S3_BUCKET=watchtower-evidence
WATCHTOWER_S3_REGION=us-east-1
```

The AWS SDK default credential chain is used, so workload roles and short-lived credentials are preferred. For AWS GovCloud, use `us-gov-west-1` or `us-gov-east-1` and credentials issued inside the GovCloud partition. A FIPS endpoint can be supplied with `WATCHTOWER_S3_ENDPOINT_URL` when required.

Optional encryption settings are:

```text
WATCHTOWER_S3_SERVER_SIDE_ENCRYPTION=aws:kms
WATCHTOWER_S3_KMS_KEY_ID=<customer-managed-key-id>
```

Bucket policy should deny plaintext transport, public access, and requests that do not meet the deployment's encryption requirements.

When a tenant selects `governance` or `compliance` retention mode, Watchtower applies S3 Object Lock to each newly committed artifact. The bucket must have Object Lock and versioning enabled and the workload identity needs `s3:PutObjectRetention`. Retention is disabled by default so an unsupported provider configuration cannot be mistaken for protected storage.

## S3-compatible storage

The same provider supports MinIO and other compatible services:

```text
WATCHTOWER_STORAGE_PROVIDER=s3
WATCHTOWER_S3_BUCKET=watchtower-evidence
WATCHTOWER_S3_REGION=us-east-1
WATCHTOWER_S3_ENDPOINT_URL=https://minio.example.internal
WATCHTOWER_S3_ADDRESSING_STYLE=path
```

If the API reaches storage through a different address than user devices, set `WATCHTOWER_S3_PUBLIC_ENDPOINT_URL` to the externally reachable signing endpoint. Production internal and public endpoints must use HTTPS. Server-side copy, conditional source reads, metadata preservation, and ordinary S3 GET/HEAD/PUT behavior are required. These capabilities should be tested against a specific vendor and version before storing customer evidence.

For local development, the repository includes an optional MinIO profile:

```bash
WATCHTOWER_STORAGE_PROVIDER=s3 docker compose --profile storage up --build --wait
```

The MinIO API listens on `http://localhost:59000` and its development console on `http://localhost:59001`. The bundled credentials are development-only.

## Azure Blob Storage

Set:

```text
WATCHTOWER_STORAGE_PROVIDER=azure
WATCHTOWER_AZURE_STORAGE_ACCOUNT_URL=https://<account>.blob.core.windows.net
WATCHTOWER_AZURE_STORAGE_CONTAINER=evidence
```

Azure Government deployments can use the corresponding `blob.core.usgovcloudapi.net` account URL. Watchtower uses `DefaultAzureCredential`; a managed identity is recommended. The identity needs blob data access and permission to request a user-delegation key. Upload access is granted with a short-lived, write-only user-delegation SAS rather than an account key.

Azure retention uses version-level blob immutability. The account and container must have the required versioning and immutable-storage features enabled, and the managed identity needs permission to set the policy. `governance` maps to an unlocked Azure policy and `compliance` maps to a locked policy.

## Common settings

`WATCHTOWER_UPLOAD_TTL_SECONDS` controls upload authorization lifetime and must be between 60 and 3,600 seconds. The default is 900 seconds. `WATCHTOWER_STORAGE_PROVIDER=disabled` leaves direct-upload endpoints unavailable with an HTTP 503 response.
