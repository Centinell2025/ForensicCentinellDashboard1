# Centinell Forensics Enterprise

Copyright © 2026 Beacon of the Eagle LLC. All Rights Reserved. This is proprietary software; see [`LICENSE`](LICENSE) and [`COPYRIGHT.md`](COPYRIGHT.md).

Production-oriented, multi-tenant DFIR and cybersecurity case-management SaaS by Beacon of the Eagle. The monorepo separates the customer frontend, secure Node.js API, PostgreSQL persistence, infrastructure, observability, and deployment automation.

## Enterprise architecture

- repository root — GitHub Pages SPA and customer interface
- `backend/src` — REST API, authentication, authorization, tenancy, audit, and AI gateway
- `api` — OpenAPI contract
- `monitoring` — Prometheus scrape and alert rules
- `kubernetes` — deployment, service, ingress, autoscaling, and disruption controls
- `terraform` — reproducible Kubernetes namespace and configuration
- `.github/workflows` — continuous integration and security scanning
- `docs` — architecture, launch, operations, and security guidance

## Working capabilities

- Self-service organization and administrator registration
- Secure login, lockout protection, and HTTP-only sessions
- Tenant-isolated case creation and retrieval
- Role enforcement for administrators, analysts, auditors, and viewers
- Immutable-style audit event trail for material actions
- Centinell AI forensic copilot with browser-side BYOK; the user's Anthropic key is sent only to Anthropic
- Health checks, validation, rate limits, container build, and Railway configuration

## Deploy on Railway

1. Add a PostgreSQL service.
2. Set `DATABASE_URL`, `JWT_SECRET` (32+ random characters), and optionally `ANTHROPIC_API_KEY`.
3. Deploy this repository. Railway uses the included Dockerfile and `/api/v1/health` health check.
4. Register the first organization through **Create account**.

The schema is created safely at startup. Never commit `.env` or customer evidence.

## Local verification

```bash
cp .env.example .env
npm install
npm run check
npm test
npm start
```

PostgreSQL must be reachable before startup. For a market launch, complete the checklist in `docs/LAUNCH-CHECKLIST.md`.


## DFIR readiness and operational boundary

**Last updated:** 2026-08-30

The dashboard provides the client-side DFIR workspace and does not claim to be a forensic evidence repository by itself.

### Implemented in the repository

- Hash-based SPA navigation with direct module links.
- Accessible cards, buttons, keyboard activation, and technical-analysis views.
- Evidence provenance fields, UTC normalization indicators, analyst notes, peer-review fields, and TXT export.
- Browser-side SHA-256 verification for a selected file, clearly marked as a local fingerprint.
- Chain-of-custody integrity verification and investigative panel routing.
- Persistent Vulnerabilities and Asset Intelligence filters.
- Offline-safe local state for continuity and user preferences.
- Enterprise CI and CodeQL checks; SonarCloud is not required.

### Production requirements before accepting tenant evidence

The following must run on an authenticated backend (for example Railway), never in GitHub Pages:

1. Derive organization_id from the authenticated session and enforce PostgreSQL RLS.
2. Upload evidence to encrypted object storage with server-side SHA-256 and immutable audit records.
3. Keep JWT secrets, encryption keys, VirusTotal/TAXII credentials, and database credentials in server-side secrets.
4. Record UTC timestamps, actor, command, evidence reference, access reason, and peer approval.
5. Enable backups, retention/legal hold, malware scanning, rate limits, monitoring, and recovery tests.

Until those controls are connected, the public Pages deployment is an interface and controlled local workspace, not a substitute for a production evidence vault.
