# ADR-0003: Istio as the mTLS Enforcement Layer

**Status**: Accepted  
**Date**: 2024-05-01  
**Deciders**: Platform security team

---

## Context

Enforcing mTLS between every pair of pods in a Kubernetes cluster at the application level requires every application to implement TLS, certificate loading, rotation, and verification. This is unreliable: some services will do it correctly, others will not, and there is no central enforcement point.

A service mesh moves TLS termination into a sidecar proxy (Envoy) that intercepts all pod traffic. Applications communicate in plain text on loopback; the mesh handles mTLS transparently. A cluster-wide `PeerAuthentication STRICT` policy makes plaintext connections a hard failure — if a pod's sidecar is missing, that pod cannot receive traffic.

---

## Decision

Deploy **Istio** with the following configuration decisions:

**1. STRICT mTLS at cluster scope, not namespace scope**

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system   # cluster-wide when in istio-system
spec:
  mtls:
    mode: STRICT
```

Namespace-scoped `STRICT` policies leave gaps: a new namespace without a policy defaults to `PERMISSIVE`. Cluster-scoped `STRICT` in `istio-system` means any namespace without an explicit override is in strict mode.

**2. Default-deny AuthorizationPolicy**

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: istio-system
spec: {}   # empty spec = deny all
```

Combined with NetworkPolicy default-deny, this creates a two-layer block: L3/L4 at NetworkPolicy, L7 at AuthorizationPolicy. An explicit allow rule is required at both layers for traffic to flow.

**3. SPIRE as the CA**

Istio's `cacerts` secret is populated from the SPIRE-issued intermediate certificate. All Envoy sidecar certificates are SPIFFE SVIDs. See [ADR-0002](ADR-0002-spiffe-spire.md).

**4. OBO header propagation via EnvoyFilter**

An `EnvoyFilter` resource on all sidecars extracts the `X-SPIFFE-OBO-Token` header, validates its JWT signature using the SPIRE trust bundle, and re-attaches it on the outgoing request. This ensures the OBO chain is never silently dropped or forged between hops.

**5. Telemetry API routes traces to OTEL Collector**

```yaml
apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: otel-tracing
  namespace: istio-system
spec:
  tracing:
    - providers:
        - name: otel-tracing
      randomSamplingPercentage: 100
```

`meshConfig.extensionProviders` defines the OTEL Collector OTLP endpoint. 100% sampling on the zero-trust cluster — every connection is a potential security event.

---

## Consequences

**Positive:**
- `PeerAuthentication STRICT` cluster-wide makes mTLS the default and deviations visible — a pod without an Istio sidecar cannot receive traffic from pods in the mesh.
- AuthorizationPolicy enforces L7 allow-lists based on SPIFFE principals, HTTP methods, and paths — not just IP addresses or namespace labels.
- The mesh transparently handles certificate rotation (via SPIRE agent updates) without application changes.
- Istio's Envoy proxies emit metrics, access logs, and traces to the OTEL Collector — every connection is observable without application instrumentation.

**Negative:**
- Envoy sidecar adds latency. P99 overhead at low load: ~0.5ms per hop. At high request rates the relative overhead drops. The `zt-gateway.json` Grafana dashboard shows the exact overhead per topology.
- Istio upgrade cycles require care: CRD schema changes, control plane restarts. GitOps (ArgoCD) manages the upgrade path.
- The interaction between SPIRE-issued certificates and Istio's internal cert rotation is non-trivial. If SPIRE is unavailable, Istio cannot rotate certificates — SVIDs will expire after 1 hour. Documented in the SPIRE runbook.
- `PeerAuthentication STRICT` cluster-wide will break any pod that does not have an Istio sidecar at install time. A phased rollout must label namespaces with `istio-injection: enabled` and verify all pods before enabling cluster-wide STRICT.

---

## Alternatives Considered

**Cilium with WireGuard encryption**  
eBPF-based L3/L4 encryption + network policy in one component. No Envoy overhead. Does not provide L7 AuthorizationPolicy or distributed tracing. SPIFFE integration is less mature. Valid future direction for teams that want to eliminate Envoy sidecars.

**Linkerd**  
Lighter than Istio, Rust proxy (ultralight). Excellent mTLS. No ext_authz support — OPA integration is not possible at the proxy level. Rejected because OBO chain validation requires per-request authz, which needs ext_authz.

**Consul Connect**  
HashiCorp's service mesh. Strong SPIFFE integration. Better multi-cluster story. Rejected for this reference because it requires Consul agents — an additional operational surface not justified when SPIRE already provides the identity plane.

---

## Related

- [ADR-0001](ADR-0001-zero-trust-model.md) — Three-plane model
- [ADR-0002](ADR-0002-spiffe-spire.md) — SPIRE as the CA for Istio
- [ADR-0007](ADR-0007-obo-token-model.md) — OBO header propagation through the mesh
- [ADR-0008](ADR-0008-observability.md) — Istio Telemetry API → OTEL Collector
- `mesh/peer-authentication.yaml` — Cluster-wide STRICT PeerAuthentication
- `mesh/default-deny.yaml` — Default-deny AuthorizationPolicy + NetworkPolicy
- `mesh/obo-propagation/envoy-filter.yaml` — OBO header extraction and re-attachment
