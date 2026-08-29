# Centinell Forensics Enterprise

Copyright © 2026 Beacon of the Eagle LLC. All Rights Reserved. This is proprietary software; see `COPYRIGHT.md`.

Production-oriented, multi-tenant DFIR and cybersecurity case-management SaaS by Beacon of the Eagle. The existing dashboard design is preserved and backed by a secure Node.js API and PostgreSQL.

## Working capabilities

- Self-service organization and administrator registration
- Secure login, lockout protection, and HTTP-only sessions
- Tenant-isolated case creation and retrieval
- Role enforcement for administrators, analysts, auditors, and viewers
- Immutable-style audit event trail for material actions
- Server-side Centinell AI gateway (no customer API keys in the browser)
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
