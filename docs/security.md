# Security model

MAP is intended for administrators connecting trusted MCP clients to panels they control. Do not expose it as an unauthenticated public HTTP service.

## Trust boundaries

- **MAP host:** no arbitrary shell, SSH, or OS-root tool is provided. Run the service as an unprivileged account.
- **Panel API:** configured keys determine capabilities. Generic write requests and dedicated tools can be destructive.
- **MCP client:** any client holding the bearer token can invoke all tools on that service; the token is not per-tool authorization.
- **Wings transfers:** binary tools follow panel-generated signed URLs only after HTTPS and exact-host checks.

## Controls

- Loopback binding by default; non-loopback HTTP binds require a bearer token of at least 32 characters.
- Constant-time bearer comparison.
- HTTPS-only panel URLs, no embedded user-info/query/fragment, and no arbitrary external request target.
- Redirects disabled for authenticated API calls.
- Common credential fields, known configured key strings, and sensitive signed-URL query parameters are redacted.
- Configurable response/file size limits.
- Exact Wings hostname allowlist; redirects disabled.
- Included systemd service uses a dedicated account and OS sandboxing.

These are defense-in-depth controls, not a guarantee that every deployment or panel fork is secure.

## Recommended deployment

1. Use the narrowest API keys and permissions available; avoid reusing root-admin tokens across panels.
2. For remote access, use HTTPS, a firewall/source restriction, and MAP's bearer token. Consider an additional access layer.
3. Keep environment files, API keys, signed URLs, and production logs out of Git and issues.
4. Never run MAP as root.
5. Back up before destructive actions. Treat kill, file deletion, backup deletion, and generic mutating requests as potentially irreversible.
6. Rotate secrets promptly after accidental exposure.

Report vulnerabilities privately through the process in [SECURITY.md](../SECURITY.md).
