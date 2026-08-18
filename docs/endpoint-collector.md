# Cross-platform endpoint collector design

## Product boundary

The Watchtower endpoint collector gathers narrowly allow-listed security posture facts from Windows, macOS, and Linux. It is an evidence sensor, not a remote shell, file scanner, employee surveillance tool, EDR replacement, or general RMM agent. It does not enumerate documents, capture screens, collect browser history, or search for CJI.

The initial implementation should be a small signed Go service with a thin optional GUI. Go keeps the privileged background component compact and supports native packages for all three operating systems. A local web/IPC API lets a separately packaged tray or settings UI display status without placing enrollment secrets in the user session.

## Components

```text
installer / RMM / MDM
        |
        | one-time site token
        v
privileged service ---- local authenticated IPC ---- optional tray/settings UI
        |
        | exchange token once; receive device credential
        v
Watchtower enrollment API -> organization + site -> device identity
        |
        +-> signed collection policy
        +<- versioned posture observations
        +-> signed update manifest
```

- **Service:** collection scheduler, enrollment, local secure storage, upload queue, updater, and uninstall handoff.
- **Check library:** small OS-specific probes behind typed interfaces, each with a version and declared privilege/data needs.
- **UI:** enrollment for interactive installs, current tenant/site, last check-in, check results, privacy disclosure, logs, and uninstall request.
- **Control plane:** token issuance, device identity, policy, check-in, evidence normalization, revocation, update channels, and audit events.

CompAI's AGPL device agent at revision `2b255847891988a7fd890cd3db3b50358ac85a0f` is a design and possible source reference for its OS check modules, scheduler, reporter, secure storage, tray UI, update packaging, and API tests. Watchtower needs a different MSP enrollment and service architecture: CompAI's employee/session-oriented flow does not by itself meet silent site deployment, machine identity, or privileged-service requirements. No CompAI source has been copied at this stage.

## Tenant and site enrollment

An MSP or customer administrator creates an enrollment package for exactly one Watchtower organization and site. The displayed token is:

- random, at least 256 bits, stored only as a server-side hash;
- bound to service provider, organization, site, allowed platforms, enrollment policy, and creator;
- short-lived and revocable, with optional maximum uses;
- marked for interactive use, automated deployment, or offline package import;
- never accepted as an ongoing device credential.

On first start, the agent generates a device key pair, gathers a stable-but-minimal hardware/OS identity, and exchanges the one-time token plus public key. The server atomically consumes a token use and returns a device ID, tenant/site binding, short-lived client certificate or refreshable device credential, signed policy, and trust bundle. Future requests derive tenant identity only from that credential. Reinstall and clone detection create a reviewable event instead of silently moving a device between tenants.

Tokens can be supplied through:

- interactive GUI entry or an enrollment link;
- `watchtower-agent enroll --token <token> --non-interactive`;
- MSI properties or a Windows installer response file;
- a signed macOS configuration profile/MDM script;
- DEB/RPM environment file or deployment-management secret.

Command-line secrets must also support reading from a protected file or standard input to avoid process-list and RMM-log exposure. Install logs show the token fingerprint, not the token.

## Device credentials and local security

- Windows: machine certificate/private key protected by CNG/DPAPI in the LocalMachine context; service runs under a constrained service identity.
- macOS: system Keychain item accessible only to the signed daemon; launch daemon and UI helper are separate processes.
- Linux: root-owned credential under `/var/lib/watchtower-agent` with mode `0600`, preferably backed by TPM/systemd credentials where available.
- All platforms: TLS 1.2+ with server validation; mTLS is preferred after enrollment. Device refresh credentials rotate, and old credentials have a short overlap window.
- The local IPC endpoint authenticates the calling UI and exposes status/actions only. It never returns the private key or enrollment token.

## Evidence collection v1

Each result reports `check_id`, check version, observed time, duration, status (`observed`, `not_supported`, `permission_denied`, `error`), typed facts, and diagnostic codes. A failed or unsupported probe is never converted into a compliance failure or pass until deterministic control logic interprets it.

Initial facts:

- OS family, edition, build/kernel, architecture, boot time, and update support state;
- device identifier/serial hash, hostname, and tenant/site binding;
- full-disk encryption state and recovery-key escrow presence (never the recovery key);
- host firewall state by profile/zone;
- screen-lock and idle-timeout policy;
- password/local authentication policy where reliably queryable;
- automatic update configuration and last successful patch/install time;
- supported anti-malware/EDR product name, service state, engine/signature age, and tamper-protection state;
- secure boot and TPM/security hardware presence;
- agent version, policy version, last successful check-in, and clock skew.

Network addresses, logged-in username, installed software, local administrators, USB/media state, certificates, and listening ports are opt-in evidence families because they can materially expand privacy and data volume. Process lists, user documents, clipboard, browser data, keystrokes, screenshots, and content inspection are prohibited by the base agent.

## Scheduling and offline behavior

The server sends a signed allow-list policy with check IDs, cadence, jitter, expiry, maximum payload size, and collection purpose. The agent rejects unknown/expired signatures and does not accept arbitrary commands or shell text. Checks run with bounded time and output. Results enter an encrypted, size-limited local queue and are uploaded with an idempotency key. Backoff uses jitter and a server-provided retry time.

If the agent is offline, Watchtower shows the last observed and last received times separately. Queue eviction retains the newest full posture set and emits a dropped-observation count. Server-side evidence stores raw signed payloads and normalized facts with hashes and collector/policy versions.

## Installation and removal

| Platform | Interactive package | Silent install/uninstall | Service model |
|---|---|---|---|
| Windows | signed MSI/bootstrap UI | `msiexec /i ... /qn` and `msiexec /x ... /qn`; Intune/RMM deployment | Windows service plus optional per-user tray UI |
| macOS | signed/notarized PKG with settings UI | `installer -pkg ... -target /`; MDM script/profile; signed uninstaller | launch daemon plus optional launch agent UI |
| Linux | signed DEB and RPM; optional GTK/system settings helper later | `apt`, `dnf`/`rpm`, config-management scripts, and package removal | hardened systemd service |

The installer verifies package signatures and refuses a tenant mismatch during repair/upgrade. Release manifests and binaries are signed through the release pipeline with provenance. Rollback protection prevents a compromised control plane from silently installing an older vulnerable agent unless a separately audited recovery policy permits it.

Removal paths are explicit:

1. **Uninstall locally:** stop collection, attempt an authenticated `device.uninstall_started` event, remove service/UI/binaries and local credential, and leave a minimal non-secret installer log. If offline, the device eventually becomes stale; it is not falsely marked successfully removed.
2. **Remove/revoke in Watchtower:** require reason and authorized actor; record `device.revocation_requested`, revoke the device credential immediately, send a removal directive if reachable, and record acknowledgement. Evidence history remains.
3. **Delete inventory record:** a separate retention/tombstone workflow available only after revocation. It cannot erase audit events or evidence referenced by an assessment.
4. **Re-enroll:** always issues a new device identity and links the old identity as predecessor; it never resurrects a revoked credential.

The UI and API distinguish `active`, `stale`, `revocation_pending`, `revoked`, `uninstall_acknowledged`, and `tombstoned`. The platform logs actor, tenant, site, device, reason, timestamps, request ID, agent version, IP/security context, and outcome for every lifecycle action.

## Control-plane API sequence

1. `POST /v1/agent-enrollment-tokens` — authorized human creates a site-bound token.
2. `POST /v1/agent-enrollments:exchange` — unauthenticated one-time token exchange with device public key.
3. `POST /v1/agents/{device_id}/check-ins` — authenticated policy/results exchange with idempotency key.
4. `GET /v1/agents/{device_id}/policy` — authenticated conditional retrieval by policy digest.
5. `POST /v1/agents/{device_id}/credential-rotations` — proof-of-possession rotation.
6. `POST /v1/agents/{device_id}/revocations` — human/API revocation with reason.
7. `POST /v1/agents/{device_id}/removal-acknowledgements` — agent confirms local removal.

Enrollment and check-in endpoints must rate-limit by token fingerprint, device, organization, and network source without using IP address as identity. Payload schemas are versioned independently from the agent binary.

## Delivery sequence

1. Threat model and protocol schema, including replay, cloning, downgrade, tenant-confusion, and malicious-local-user cases.
2. Go service skeleton, enrollment exchange, secure local credential, heartbeat, signed policy, and a fake control plane.
3. OS/build, encryption, firewall, screen lock, and update checks with golden fixtures on all three operating systems.
4. Windows MSI/service and silent RMM deployment; then notarized macOS PKG and Linux DEB/RPM.
5. Optional GUI/tray and user-visible privacy/status experience.
6. Signed update channels, staged rollout, rollback controls, and release provenance.
7. Revocation/removal state machine and destructive-path integration tests.

No remote remediation or arbitrary command capability belongs in the first agent release.
