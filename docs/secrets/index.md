---
title: Secrets
description: Vault (primary) and AWS Secrets Manager via ESO (alternative) — no static credentials, dynamic rotation, audit trail.
tags: [secrets, vault]
---

# Secrets Management

No static credentials. No base64-encoded Kubernetes Secrets. Every secret is encrypted at rest, audit-logged on access, and rotated automatically.

---

## Vault (Primary)

Vault runs as a StatefulSet with AWS KMS auto-unseal. The Vault Agent Injector sidecar writes secrets to a `tmpfs` volume as files — the application reads from files, not environment variables.

### Dynamic Database Credentials

The most powerful Vault capability: instead of storing a long-lived database password, Vault generates time-limited credentials per pod at startup.

```
Pod starts
  → Vault Agent reads annotation vault.hashicorp.com/agent-inject: "true"
  → Agent requests a database credential from Vault's database secrets engine
  → Vault generates a Postgres user: orders_20240501_abc123 (TTL: 1h)
  → Agent writes credentials to /vault/secrets/db-credentials
  → Application reads /vault/secrets/db-credentials
  → After 1h, credentials expire; Vault Agent requests renewal
  → Pod restarts or Agent renews: new credentials, old ones expire
```

A compromised pod's database access expires with the credential TTL. No rotation job, no coordination required.

### Vault Agent Annotation

```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/role: "orders-svc"
  vault.hashicorp.com/agent-inject-secret-db: "database/creds/orders-db-role"
  vault.hashicorp.com/agent-inject-template-db: |
    {{- with secret "database/creds/orders-db-role" -}}
    DB_HOST=orders-postgres.orders.svc.cluster.local
    DB_USER={{ .Data.username }}
    DB_PASS={{ .Data.password }}
    {{- end -}}
```

---

## AWS Secrets Manager (Alternative)

For AWS-native deployments, External Secrets Operator (ESO) syncs ASM secrets to Kubernetes Secrets. Authentication uses IRSA — the pod's IAM identity (from its Kubernetes service account via OIDC federation) authorizes the ASM read.

```
Pod SA → OIDC federation → IAM role (IRSA) → ASM read permission
ESO ClusterSecretStore → AWS API → ExternalSecret → Kubernetes Secret
```

!!! warning "Kubernetes Secret exposure"
    ESO creates Kubernetes `Secret` objects that are stored in etcd. This re-introduces the base64 exposure risk. For higher security, use the **Secrets Store CSI Driver** with ESO: secrets are mounted directly as files without creating a Kubernetes Secret object.

### When to choose AWS SM over Vault

- AWS-only deployment; no multi-cloud requirement
- No dynamic credentials needed (static rotation is sufficient)
- Team does not have Vault operations expertise
- Managed service preferred over self-operated StatefulSet

---

## Reference Implementation

| File | Purpose |
|---|---|
| [`secrets/vault/vault-server.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/secrets/vault/vault-server.yaml) | Vault StatefulSet: AWS KMS auto-unseal, Prometheus metrics, PKI engine |
| [`secrets/aws-secrets-manager/external-secrets-operator.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/secrets/aws-secrets-manager/external-secrets-operator.yaml) | ESO ClusterSecretStore (IRSA auth) + example ExternalSecret for orders DB credentials |
