# Security policy

Security fixes are developed against the latest version on the default branch. Until a stable release is declared, no long-term support window is promised for older versions.

## Private vulnerability reports

Do not publish exploit details, API keys, signed transfer URLs, or proof-of-concept requests in public issues. Use [GitHub private vulnerability reporting](https://github.com/RealmsNetwork/MAP/security/advisories/new). Private vulnerability reporting is enabled for this repository. Include the affected commit/version, impact, configuration requirements, and a minimal reproduction using dummy credentials.

Maintainers aim to acknowledge credible reports promptly and coordinate a fix before publication.

MAP is privileged administrative software. Use least-privilege keys, HTTPS for remote access, and an unprivileged service account. See [docs/security.md](docs/security.md).
