# Watchtower endpoint collector

The initial collector is a dependency-free Go service/CLI for Windows, macOS, and Linux. It implements enrollment and evidence check-in without remote shell or remediation capability.

```text
watchtower-agent enroll --server https://watchtower.example --token-file /run/secrets/watchtower-token
watchtower-agent collect
watchtower-agent check-in
watchtower-agent ui --listen 127.0.0.1:17654
watchtower-agent uninstall --notify
```

Enrollment accepts a protected token file or standard input and exchanges it once for a device credential stored with owner-only permissions. Production packages should use Windows CNG/DPAPI and the macOS system Keychain as described in [the collector design](../docs/endpoint-collector.md).

The v1 allow-list includes OS family, architecture, hostname, and collector version. OS-specific encryption, firewall, screen-lock, update, EDR, Secure Boot, and TPM probes are the next check-library increment; unsupported checks remain explicit and are never interpreted as compliance failures.

`ui` binds loopback only and provides the optional GUI/status surface. Silent deployment can run `enroll` and `check-in` through an RMM, MDM, launchd, systemd, or Windows Service wrapper. `uninstall --notify` attempts an authenticated lifecycle check-in before removing the credential; the platform retains its audit/evidence history.
