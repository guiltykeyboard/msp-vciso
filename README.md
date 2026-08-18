# MSP Multi-Tenant Audit Platform

Quick start: `docker-compose --profile with-web up --build`
DB: `postgres:5432` · API: `localhost:8000` · Agent: 300s

## Framework Mappings
| Framework | Key Controls |
|---|---|
| **CJIS** (v5.9+) | 5.10 Encryption · 5.11 Access/MFA · 5.12 Audit · 5.13 Physical · 5.14 Screening |
| **Ohio HB 96** | Data retention · Encryption · Access controls · Audit trails |

## Storage Options
| Mode | Config | Use Case |
|---|---|---|
| Internal (default) | `USE_INTERNAL_STORAGE=true` | Small clients |
| External S3 | `USE_EXTERNAL_S3=true` + `minio` profile | External custody |

AGPLv3 applies to CompAI-derived code; starter agent independently authored.
