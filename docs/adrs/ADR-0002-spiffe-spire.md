# ADR-0002: SPIFFE/SPIRE for Workload Identity

**Status**: Accepted  
**Date**: 2024-05-01  
**Deciders**: Platform security team

---

## Context

Workload identity in Kubernetes is weak by default. Kubernetes service accounts are strings bound to namespaces; possession of a pod in a namespace is sufficient to impersonate any service account in that namespace. There is no cryptographic proof of identity, no attestation of what binary is running, and no automatic rotation.

Zero-trust requires that every connection carry proof of identity that cannot be forged, is short-lived (limiting the blast radius of a compromise), and is tied to a verified claim about the workload's origin.

---

## Decision

Adopt **SPIFFE** (Secure Production Identity Framework For Everyone) as the identity standard and **SPIRE** (SPIFFE Runtime Environment) as the implementation.

Every workload in the cluster is assigned a SPIFFE Verifiable Identity Document (SVID):

- **X.509 SVID** — TLS certificate with the SPIFFE ID (`spiffe://chakra.internal/<workload>`) in the Subject Alternative Name. Used for mTLS. Renewed every 1 hour by the SPIRE agent.
- **JWT SVID** — Short-lived JWT signed by SPIRE. Used for OBO token construction when a service makes a downstream call on behalf of an originating user.

The SPIRE server runs as a StatefulSet. SPIRE agents run as a DaemonSet — one per node. Agents attest workloads using the Kubernetes workload attestor (pod UID, service account, namespace, label selectors). The SPIRE server issues SVIDs only to workloads that match a registered entry.

SPIRE acts as the intermediate CA for Istio: Istio's `istio-system/cacerts` secret is populated from the SPIRE-issued intermediate certificate. This means all Istio mTLS certificates are SPIFFE-conformant — Istio's mesh certificates _are_ SVIDs.

---

## SPIFFE ID Namespace

All SPIFFE IDs follow the pattern:

```
spiffe://chakra.internal/ns/<namespace>/sa/<service-account>
```

This mirrors the Kubernetes SPIRE workload attestor output. SPIRE registration entries bind each (`namespace`, `serviceaccount`) pair to a SPIFFE ID. The ZT gateway uses a separate SPIFFE ID:

```
spiffe://chakra.internal/ns/zt-gateway/sa/zt-gateway
```

Peer entries (what each workload is allowed to talk to) are declared in `identity/spiffe-ids.yaml`.

---

## JWT SVID and OBO

When service A calls service B on behalf of user U:

1. Service A requests a JWT SVID from its local SPIRE agent for the audience `spiffe://chakra.internal/ns/orders/sa/orders-svc`.
2. Service A attaches the JWT SVID as `X-SPIFFE-OBO-Token` and its own identity as `X-SPIFFE-Caller-ID`.
3. Service B's Envoy sidecar presents both tokens to OPA via ext_authz.
4. OPA's `validate-obo-chain.rego` verifies: (a) the JWT SVID signature is valid, (b) the audience matches service B's SPIFFE ID, (c) the caller identity is in service B's allow-list.

This is described in full in [ADR-0007](ADR-0007-obo-token-model.md).

---

## Consequences

**Positive:**
- SVIDs rotate every hour without pod restarts — the SPIRE agent delivers new certs to workloads via the SPIFFE Workload API unix socket.
- Revocation is implicit: a one-hour TTL means a compromised SVID is invalid within 60 minutes without a CRL lookup.
- SPIRE workload attestation means a compromised Kubernetes service account alone is not sufficient to get an SVID — the pod must also satisfy the SPIRE registration entry's selector conditions.
- SPIRE supports federation: `spiffe://partner.internal` trust domains can be federated, enabling cross-cluster mTLS without pre-shared certificates.

**Negative:**
- SPIRE is a stateful service. The server stores registration entries in etcd (or SQLite for single-node). Backup and restore procedures must be documented and tested.
- The SPIRE agent unix socket must be mounted into every pod that needs SVID access (or Vault agent injection handles this). The Kubernetes workload attestor requires the SPIRE agent to query the Kubernetes API — RBAC must allow this.
- JWT SVID audiences must be pre-registered. A service calling a new downstream must have the downstream's SPIFFE ID registered as an allowed audience, which requires an operator step.

---

## Alternatives Considered

**cert-manager with ClusterIssuer**  
Issues TLS certificates; no SPIFFE identity, no workload attestation, no JWT SVID support. Rotation requires pod restarts or a custom operator. Rejected.

**AWS ACM Private CA with Kubernetes CSR API**  
AWS-managed CA, certificates issued via Kubernetes CertificateSigningRequest. No SPIFFE ID, no attestation, tight AWS coupling. Viable for AWS-only deployments but not a general reference.

**Istio self-signed CA (default)**  
Istio can act as its own CA with a self-signed root. No SPIFFE attestation — any pod in the mesh gets a cert. Rejected because it does not provide workload identity, only transport encryption.

---

## Related

- [ADR-0001](ADR-0001-zero-trust-model.md) — Three-plane model context
- [ADR-0003](ADR-0003-istio-service-mesh.md) — How Istio consumes SPIRE-issued SVIDs
- [ADR-0007](ADR-0007-obo-token-model.md) — JWT SVID OBO chain semantics
- `identity/spire-server.yaml` — SPIRE server StatefulSet
- `identity/spire-agent.yaml` — SPIRE agent DaemonSet
- `identity/spiffe-ids.yaml` — Workload registration entries
