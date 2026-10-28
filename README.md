# HTM UC PBX agent

A small read-only program that runs on a VitalPBX/Asterisk host and pushes the live state the HTM UC needs
(BLF/hint state, DND/forward, Class of Service) to the UC over outbound HTTPS. It lets one UC serve a PBX on another server.
The PBX opens no inbound port.

## What it can and cannot do
- Runs only these Asterisk commands: `core show hints`, `database show`, `database show CustomDevstate`, `database show <family>`.
- Runs one SQL SELECT against the PBX database (read-only session, local socket).
- Sends only what the UC's scope lists (active UC users with an extension), optionally narrowed further by `allowed_tenants` in its own config.
- Cannot change any PBX setting in this version. There is no inbound listener and no remote shell.
- Every request is HMAC-SHA256 signed with a per-agent secret; replies are signed back; timestamps and nonces stop replays. TLS is required (plain HTTP only to 127.0.0.1 for tests).

## Install (as root on the PBX)
1. In the UC: Settings > PBX Agent > Add an agent. Pick the tenants it may report on. Copy the ID and the secret (shown once).
2. On the PBX:
```sh
curl -fsSLO https://github.com/raziffmohamed/htmuc-pbx-agent/releases/download/vVERSION/get.sh
sh get.sh --version VERSION --sha256 <hash from the release notes> --uc-url https://uc.example.com/uc/ --agent-id ag_...
```
The script verifies the SHA-256 before running anything, asks for the secret with a hidden prompt, detects the tenant Asterisk families, writes
`/etc/htmuc-agent/agent.json` (mode 600), checks it can reach the UC, and only then starts the `htmuc-agent` service.

From a checkout: `python3 install_agent.py --uc-url ... --agent-id ...`.

Useful commands (`/opt/htmuc-agent/htmuc-agent --config /etc/htmuc-agent/agent.json <cmd>`): `check`, `dry-run`, `once`, `discover`, `sample`, `version`.
`sample` works before configuration and prints redacted excerpts of what the agent parses.

Uninstall: `python3 install_agent.py --uninstall [--purge]`, then delete the agent in the UC.

## Config (`/etc/htmuc-agent/agent.json`)
| key | meaning |
|---|---|
| `uc_url`, `agent_id`, `secret` | from Settings > PBX Agent |
| `tenant_families` | `{"<PBX tenant id>": "<Asterisk family>"}`, detected at install |
| `allowed_tenants` | optional list of PBX tenant ids; the agent ignores everything else |
| `intervals`, `max_age` | per kind (`blf`, `routing`, `cos`) polling period and heartbeat, seconds |
| `ca_file` | PEM bundle for a private CA |

## Tests
```sh
python3 tests/test_agent.py
UC_PKG=/path/to/VitalPBX-UC-package python3 tests/diff_legacy.py   # must produce the same snapshots as the UC's own collectors
```
