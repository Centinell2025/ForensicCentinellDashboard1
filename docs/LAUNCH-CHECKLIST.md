# Market launch checklist

## Required before accepting customers

- [ ] Provision production PostgreSQL with encrypted backups and test restoration.
- [ ] Set a unique 32+ character `JWT_SECRET`; keep all secrets in Railway variables.
- [ ] Configure the production domain, TLS, `ALLOWED_ORIGINS`, support email, and privacy/terms links.
- [ ] Configure the server-side AI key or disable AI until configured.
- [ ] Run registration, login, lockout, logout, tenant-isolation, case creation, audit, and AI failure-path tests.
- [ ] Create two test organizations and prove neither can access the other's records.
- [ ] Perform dependency, SAST, DAST, and independent penetration testing.
- [ ] Establish monitoring, alerting, retention, incident response, and customer-support procedures.
- [ ] Review claims, contracts, privacy policy, data processing terms, and compliance language with qualified counsel.
- [ ] Do not describe the product as certified or fully compliant until that certification has been independently completed.

## Safe first release

Use a controlled pilot with synthetic data. Promote to general availability only after the database backup/restore and cross-tenant authorization tests pass.

## Verification record

Record the date, operator, environment, commit SHA, database backup identifier, restore-test evidence, test results, security-review reference, and deployment URL for every production release. A checkbox without supporting evidence is not a completed control.
