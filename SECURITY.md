# Security policy

Report suspected vulnerabilities privately to the support/security contact configured for Beacon of the Eagle. Do not include credentials, client evidence, personal data, or exploit details in a public GitHub issue.

## Production controls

- Secrets are supplied only through the hosting environment.
- Passwords are hashed with bcrypt cost 12.
- Sessions use signed, short-lived, HTTP-only cookies.
- Every business query is scoped by organization ID.
- Case creation and AI use produce tenant-scoped audit events.
- Authentication and API routes are rate limited.
- AI provider credentials stay on the server.

Before handling regulated or evidentiary data, complete an independent security review, backup/restore exercise, incident-response test, and applicable legal/compliance assessment.
