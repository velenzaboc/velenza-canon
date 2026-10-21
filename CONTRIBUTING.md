# Contributing & Open-Source Hygiene Policy

Velenza Canon (`velenza-canon`) is a strictly vendor-neutral, clean-room open-source project licensed under Apache-2.0.

## Strict Zero-Proprietary-IP & Config-Only Policy

To keep Velenza Canon 100% portable and safe for public distribution, the repository enforces three non-negotiable rules through automated CI tests (`arbor_canon_traceability_test.go` `TestOpenSourceHygiene`):

1. **Zero Proprietary IP or Organization Identifiers**
   - No organization names, internal codenames, internal project identifiers, or proprietary domain names may appear anywhere in source code, comments, tests, commit messages, or documentation.
   - Use generic domains (`@example.com`) and generic project identifiers (`example-gcp-project`, `example-spanner-instance`, `example-org`) in unit and integration tests.

2. **Zero Hardcoded Environment Coordinates**
   - Never hardcode workstation paths (`/Users/...`, `/Volumes/...`, `/home/...`, `C:\Users\...`), internal hostnames, cloud project IDs, database instance IDs, or private/Tailscale IP addresses (`100.x.x.x`, `10.x.x.x`, `192.168.x.x`).

3. **Everything Goes Through Configuration (`SpecGraphConfig`)**
   - All deployment-specific coordinates—GCP project IDs, Spanner instance and database IDs, Vertex AI endpoints, authentication credentials, and local corpus roots—must be supplied at runtime via `VELENZA_CANON_CONFIG`, `SPEC_GRAPH_CONFIG`, `spec-graph.config.json`, or `ARBOR_*` environment variables.
   - See [`velenza-canon.config.example.json`](./velenza-canon.config.example.json) for the full configuration schema.
   - Local configuration files (`spec-graph.config.json`) are listed in `.gitignore`.

## License, Code of Conduct & Contact

- **License**: By contributing to Velenza Canon, you agree that your contributions will be licensed under the [Apache License, Version 2.0](./LICENSE) and subject to the attribution requirements in [`NOTICE`](./NOTICE).
- **Code of Conduct**: Participation is governed by our [Code of Conduct](./CODE_OF_CONDUCT.md).
- **Security Vulnerabilities**: Please follow [`SECURITY.md`](./SECURITY.md) and report security issues privately via GitHub Private Vulnerability Reporting or email to **open-source@velenzaboc.com**.
- **General Open-Source Contact**: **open-source@velenzaboc.com**
