# ADR-0001: Three-Plane Zero-Trust Model

**Status**: Accepted  
**Date**: 2024-05-01  
**Deciders**: Platform security team

---

## Context

The perimeter security model — trust everything inside the network, block everything outside — fails in a Kubernetes environment for three structural reasons:

1. **Lateral movement**: A single compromised pod has unrestricted access to every other pod in the cluster. Network policies help but are not universally applied.
2. **Credential sprawl**: Static secrets in ConfigMaps and environment variables are exfiltrated in container breakouts and CI pipeline leaks.
3. **No workload identity**: Kubernetes service accounts are namespace-scoped strings, not cryptographic identities. An attacker who can create a pod in a namespace can impersonate any service in that namespace.

Zero-trust resolves all three: every connection is authenticated (no implicit trust), every workload has a cryptographic identity, every secret is rotated and audit-logged.

The question is architecture: a single product (e.g. HashiCorp Boundary, Zscaler Private Access) handles everything but creates a single point of failure and vendor lock-in. Or: compose open standards across three planes, each independently auditable.

---

## Decision

Adopt a **three-plane model**:

| Plane | Component | Responsibility |
|---|---|---|
| **Identity** | SPIFFE/SPIRE | Issue X.509 SVIDs to every workload; rotate every 1 hour |
| **Network** | Istio (Envoy data plane) | Enforce mTLS on every connection; default-deny at L7 |
| **Policy** | OPA/Gatekeeper | Admission control + runtime authz; validate OBO token chains |

The planes are layered, not redundant: Identity is the foundation (Plane 2 and 3 consume SVIDs), Network enforces transport security (Plane 3 operates on authenticated connections), Policy enforces business rules (OBO chain integrity, resource constraints).

---

## Consequences

**Positive:**
- Each plane is independently replaceable. Migrating from Istio to Cilium does not require touching SPIRE or OPA.
- Defense in depth: an Istio misconfiguration does not bypass identity verification; an OPA rule error does not bypass mTLS.
- All components are CNCF projects with audit trails, CVE response processes, and large operator communities.
- OTEL spans from each plane (SVID verification, Istio authz, OPA decision) compose into a single distributed trace — security events and latency analysis share one instrument.

**Negative:**
- Three operational surfaces: SPIRE cluster, Istio control plane, OPA/Gatekeeper. Each has upgrade cycles, failure modes, and tuning requirements.
- SPIRE + Istio together provide redundant certificate management unless carefully integrated. This repo integrates them: SPIRE is the root CA, Istio's `cacerts` mounts the SPIRE-issued intermediate cert so Istio's mTLS certificates are SPIFFE-conformant SVIDs.
- Learning curve: most teams understand either the mesh layer or the policy layer, rarely both. On-call runbooks must be explicit about which plane is responsible for a given failure mode.

---

## Alternatives Considered

**Single-product ZT platform (HashiCorp Boundary + Vault)**  
Handles identity + secrets + network access in one product. Rejected because Boundary does not enforce mTLS between Kubernetes pods — it manages access to services, not pod-to-pod traffic.

**Cilium + Tetragon**  
eBPF-based enforcement at the kernel level. Strong network policy; Tetragon provides runtime security. Rejected for this reference: eBPF-based mTLS is still maturing; SPIFFE integration is less documented than Istio's. This remains the right direction for teams who want one data plane instead of two (eBPF + Envoy).

**Manual mTLS with cert-manager**  
cert-manager can issue mTLS certificates; services load them manually. Rejected because there is no SPIFFE identity, no workload attestation, and rotation requires pod restarts.

---

## Related

- [ADR-0002](ADR-0002-spiffe-spire.md) — SPIFFE/SPIRE identity plane detail
- [ADR-0003](ADR-0003-istio-service-mesh.md) — Istio mesh plane detail
- [ADR-0004](ADR-0004-opa-policy.md) — OPA policy plane detail
- [ADR-0007](ADR-0007-obo-token-model.md) — OBO token model that ties all three planes together
