# Endpoint collector

The endpoint collector is not implemented yet. Its approved product boundary and proposed cross-platform architecture are documented in [the collector design](../docs/endpoint-collector.md).

The plan is a signed Go system service with an optional thin UI for Windows, macOS, and Linux. It uses a one-time, tenant/site-bound enrollment token that is exchanged for a per-device credential, supports both interactive and silent deployment, gathers only allow-listed posture facts, and has an audited revocation/uninstall lifecycle. Fleet/Orbit, osquery, and the compatible portions of CompAI's AGPL device agent remain upstream references or integration options.
