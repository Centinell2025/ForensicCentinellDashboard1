# Mission-Critical Security Controls

## Implemented foundations

- PostgreSQL RLS is forced on cases and audit events using a transaction-local organization context.
- Audit events use a per-organization SHA-256 chain with a transaction advisory lock for ordering.
- Evidence envelope encryption uses one-time AES-256-GCM data keys and a provider-neutral KMS/HSM adapter.
- WebAuthn credential and ABAC policy stores are present for the mandatory-MFA authorization layer.
- SIEM events can be exported with timestamped HMAC-SHA256 signatures and are always emitted as structured JSON.

## Required before claiming production activation

1. Use a non-owner database application role, execute cross-tenant negative tests, and inspect every query plan.
2. Implement WebAuthn registration/assertion ceremonies, recovery, attestation policy, and mandatory step-up checks. Database tables alone are not MFA.
3. Select an external HSM-backed KMS and implement its adapter. DigitalOcean's platform encryption does not replace customer-managed envelope encryption.
4. Store ciphertext only in a private object store; restrict it with short-lived service identities and retention locks where available.
5. Export and sign the latest audit chain hash to an external immutable system. A chain stored only in PostgreSQL is tamper-evident, not superuser-proof.
6. Configure replay protection, delivery queues, dead-letter handling, allowlists, and secret rotation for SIEM delivery.
7. Run restore, failover, region-loss, service-mesh policy, and evidence-decryption exercises with recorded evidence.

## DigitalOcean production topology

- DOKS application cluster with multiple replicas, PodDisruptionBudget, network policy, TLS, and tested Istio policies.
- Managed PostgreSQL Standard with at least one standby for HA, private VPC access, SSL, PITR, firewall rules, and a geographically separate read-only node only when the latency/consistency model permits it.
- External customer-managed HSM/KMS for evidence data keys until an approved DigitalOcean-native CMK capability is contractually validated.

These controls support an audit program but do not themselves certify SOC 2 Type II or any financial standard.
