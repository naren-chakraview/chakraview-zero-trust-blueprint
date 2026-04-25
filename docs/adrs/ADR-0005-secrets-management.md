# ADR-0005: Secrets Management — Vault Primary, AWS Secrets Manager Alternative

**Status**: Accepted  
**Date**: 2024-05-01  
**Deciders**: Platform security team

---

## Context

Kubernetes `Secret` resources are base64-encoded and stored unencrypted in etcd by default. Any user with `get secrets` RBAC permission — or read access to etcd — can read all secrets in their namespace. Storing database credentials, API keys, and TLS private keys in Kubernetes Secrets is a widely-known security antipattern.

A secrets management system must provide:
- Encryption at rest and in transit
- Audit logs of every secret access (who, when, what)
- Automatic rotation with minimal application disruption
- Integration with the workload identity system (SPIFFE SVIDs) so that secrets access is tied to cryptographic identity, not static tokens

---

## Decision

**Primary: HashiCorp Vault with Kubernetes Auth and Agent Injection**

Vault is deployed as a Kubernetes StatefulSet with:
- **AWS KMS auto-unseal** — Vault seals/unseals without manual operator intervention using an AWS KMS key. No Vault operator needs to be paged on a pod restart.
- **Kubernetes auth method** — Vault validates the pod's Kubernetes service account JWT to issue a Vault token. This ties secrets access to the pod's identity without pre-shared credentials.
- **Vault Agent Injector** — An admission webhook that injects a Vault Agent sidecar into pods with `vault.hashicorp.com/agent-inject` annotations. The agent fetches secrets from Vault and writes them to a `tmpfs` volume mounted at `/vault/secrets/`. The application reads secrets from files, not environment variables.
- **PKI secrets engine** — Vault acts as an intermediate CA for application-level TLS certificates (distinct from SPIRE). Short-lived certificates (24h TTL) issued on demand.
- **Dynamic database credentials** — The `database` secrets engine generates time-limited PostgreSQL credentials per pod. A database connection failure is the application signal that credentials need renewal, not a scheduled rotation job.

**Alternative: AWS Secrets Manager with External Secrets Operator**

For AWS-native deployments where operating a Vault StatefulSet is not desirable, AWS Secrets Manager (ASM) via the **External Secrets Operator (ESO)** provides equivalent functionality:

- `ClusterSecretStore` — authenticates to ASM using IRSA (IAM Roles for Service Accounts), tying secret access to the pod's IAM identity (backed by the Kubernetes service account → OIDC federation chain).
- `ExternalSecret` CRDs — declarative mappings from ASM secret paths to Kubernetes `Secret` objects. ESO syncs on a configurable interval (default 1h) and on secret rotation events.
- **Tradeoff**: ASM secrets land as Kubernetes `Secret` objects — they are subject to the same etcd exposure risk. ESO with Secrets Store CSI Driver (instead of `ExternalSecret` CRDs) mounts secrets as files directly, avoiding the Kubernetes Secret intermediary.

---

## Comparison

| Capability | Vault + Agent | AWS Secrets Manager + ESO |
|---|---|---|
| Encryption at rest | Vault storage backend (encrypted) | ASM managed |
| Audit logs | Vault audit log (file/syslog/Splunk) | CloudTrail |
| Dynamic credentials | Yes (database, PKI, AWS, GCP) | No (static rotation only) |
| Secret sync to K8s Secret | No (tmpfs file injection) | Yes (ESO creates K8s Secret) |
| IRSA / SPIFFE integration | Kubernetes auth (SA JWT) | IRSA (SA → OIDC → IAM) |
| Auto-rotation | TTL-based (per-lease) | ASM rotation Lambda |
| Multi-cloud / on-prem | Yes | AWS only |
| Operational burden | High (StatefulSet, unseal, upgrades) | Low (managed service) |

**When to choose AWS SM over Vault:**
- AWS-only deployment; no multi-cloud requirement
- Team does not have Vault operations expertise
- Dynamic credentials (per-pod database credentials) are not required
- Secret rotation cadence is hours, not minutes

---

## Consequences

**Positive (Vault):**
- Dynamic credentials eliminate long-lived database passwords. A compromised pod's database access expires when its Vault lease expires.
- The Vault audit log provides a complete record of every secret read — this is the required evidence for SOC 2 Type II access audits.
- Vault's PKI engine issues short-lived TLS certificates for application-level TLS (distinct from Istio mTLS), enabling zero-config TLS for internal HTTPS endpoints.

**Negative (Vault):**
- Vault is a stateful cluster service. The raft storage backend requires a 3-node cluster for HA. Backup and restore of Vault state is a critical operational procedure.
- If Vault is unavailable, pods with expired secrets cannot refresh — applications must be designed to tolerate a short Vault outage (typically via a grace period in the Vault Agent config).
- The Vault Agent Injector adds a sidecar to every pod using secrets injection. This is an additional container, init container, and volume per pod.

---

## Related

- [ADR-0002](ADR-0002-spiffe-spire.md) — SPIRE as workload identity; Vault Kubernetes auth complements SPIFFE
- `secrets/vault/vault-server.yaml` — Vault StatefulSet with KMS auto-unseal
- `secrets/vault/vault-agent-injector.yaml` — Injector webhook configuration
- `secrets/aws-secrets-manager/external-secrets-operator.yaml` — ESO installation
- `secrets/aws-secrets-manager/secret-stores/` — ClusterSecretStore and ExternalSecret examples
