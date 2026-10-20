# Deployment

Supported modes are HTTP for hosted services and stdio for local MCP clients. Docker Compose publishes HTTP only on host loopback and requires a bearer token. The systemd example uses an unprivileged service account and root-owned environment file.

Remote use requires HTTPS ingress and access controls. Never expose unauthenticated plaintext HTTP.

See the [deployment guide](https://github.com/RealmsNetwork/MAP/blob/main/docs/deployment.md).
