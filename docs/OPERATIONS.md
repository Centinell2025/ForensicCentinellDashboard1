# Operations Runbook

## Availability

- `/api/v1/ready` confirms the process is responsive.
- `/api/v1/health` verifies PostgreSQL connectivity.
- Alert when health checks fail twice or the 5xx ratio exceeds 5% for five minutes.

## Incident procedure

1. Restrict affected access and preserve logs.
2. Record timestamps, tenant, trace IDs, and responders.
3. Rotate affected credentials without committing them.
4. Restore from a tested encrypted backup when integrity is uncertain.
5. Document customer notification and legal decisions outside public issues.

## Backup minimum

Use daily encrypted backups, point-in-time recovery, separate backup credentials, and a quarterly restore exercise. Retention must follow the customer agreement and applicable law.
