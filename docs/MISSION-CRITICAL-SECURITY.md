# Mission-Critical Security Controls

## Implemented foundations

- PostgreSQL RLS is forced on cases and audit events using a transaction-local organization context.
- Audit events use a per-organization SHA-256 chain with a transaction advisory lock for ordering.
- Evidence envelope encryption uses one-time AES-256-GCM data keys and a provider-neutral KMS/HSM adapter.
- A HashiCorp Vault Transit adapter can wrap and unwrap evidence data keys without exposing the master key to the application.
- WebAuthn credential and ABAC policy stores are present for the mandatory-MFA authorization layer.
- CI starts PostgreSQL and runs automated cross-tenant RLS read/write isolation tests.
- The audit chain head can be periodically signed and sent to an external anchor, with its receipt stored in PostgreSQL.
- SIEM events are structured, signed with HMAC-SHA256, carry idempotency identifiers, and retry transient delivery failures.
- Terraform provisions an explicit DigitalOcean VPC, a three-node autoscaling DOKS worker pool, and a two-node managed PostgreSQL cluster.

## Required before claiming production activation

1. Use a least-privileged, non-owner database application role and inspect every sensitive query plan before launch.
2. Implement WebAuthn registration/assertion ceremonies, recovery, attestation policy, and mandatory step-up checks. Database tables alone are not MFA.
3. Deploy and harden Vault with an HSM-backed seal, or add an approved cloud KMS adapter. Supplying Vault credentials alone does not make the deployment HSM-backed.
4. Store ciphertext only in a private object store; restrict it with short-lived service identities and retention locks where available.
5. Configure the audit anchor URL to target independently administered immutable/WORM storage and verify its receipts. The included client does not make an ordinary webhook immutable.
6. Add a durable delivery queue and dead-letter handling, then configure receiver-side replay protection, allowlists, and secret rotation for SIEM delivery.
7. Run restore, failover, region-loss, service-mesh policy, and evidence-decryption exercises with recorded evidence.

## DigitalOcean production topology

- DOKS application cluster with multiple replicas, PodDisruptionBudget, network policy, TLS, and tested Istio policies.
- Managed PostgreSQL Standard with at least one standby for HA, private VPC access, SSL, PITR, firewall rules, and a geographically separate read-only node only when the latency/consistency model permits it.
- External customer-managed HSM/KMS for evidence data keys until an approved DigitalOcean-native CMK capability is contractually validated.

These controls support an audit program but do not themselves certify SOC 2 Type II or any financial standard.
