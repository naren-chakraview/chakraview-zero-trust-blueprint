---
title: Mesh
description: Istio mTLS enforcement — STRICT cluster-wide PeerAuthentication, default-deny AuthorizationPolicy, OBO header propagation.
tags: [mesh, istio]
---

# Mesh — Istio mTLS Enforcement

The mesh layer enforces transport security and L7 access control for all pod-to-pod traffic. It consumes SPIFFE SVIDs from SPIRE and enforces OBO header propagation at every hop.

---

## Cluster-Wide STRICT mTLS

```yaml
# Applied in istio-system → covers ALL namespaces
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

`STRICT` mode means: any pod receiving traffic that does not present a valid mTLS client certificate is rejected at the transport layer. A pod without an Istio sidecar (and therefore without a certificate) cannot receive traffic from mesh-enabled pods.

The health-check exception allows kubelet probes on port 8080 (`PERMISSIVE` on that port only) — kubelet cannot do mTLS.

---

## Two-Layer Default Deny

**Layer 1: NetworkPolicy (L3/L4)**

```yaml
# Applied to every namespace
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  # empty ingress/egress = deny all
```

Enforced by the CNI plugin before packets reach the pod. Blocks at IP + port level regardless of TLS.

**Layer 2: AuthorizationPolicy (L7)**

```yaml
# Empty spec in istio-system = deny all cluster-wide
spec: {}
```

Enforced by the Envoy sidecar after mTLS is established. Can inspect HTTP methods, paths, and SPIFFE principals from the TLS cert.

The combination: a packet must pass NetworkPolicy (correct IP/port) AND AuthorizationPolicy (correct SPIFFE principal + HTTP method/path) to reach a service. A NetworkPolicy bypass does not bypass AuthorizationPolicy, and vice versa.

---

## OBO Header Propagation

An `EnvoyFilter` resource runs on all sidecars and the ZT gateway. At every hop it:
1. Extracts the `X-SPIFFE-OBO-Token` header (if present)
2. Appends this service's SPIFFE ID to `X-SPIFFE-Caller-Chain`
3. Preserves the `traceparent` header for OTEL trace continuity
4. Re-attaches all headers on the outbound request

This ensures the OBO chain is never silently dropped between hops, and that the OTEL trace context spans the full call chain.

---

## Telemetry

The `Telemetry` resource (in `mesh/obo-propagation/envoy-filter.yaml`) routes all Istio proxy traces to the OTEL Collector at 100% sampling:

```yaml
spec:
  tracing:
    - providers:
        - name: otel-tracing
      randomSamplingPercentage: 100.0
```

100% sampling is appropriate for a zero-trust cluster where every connection is a security event. The OTEL Collector batches before shipping to Tempo.

---

## Reference Implementation

| File | Purpose |
|---|---|
| [`mesh/peer-authentication.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/mesh/peer-authentication.yaml) | Cluster-wide STRICT PeerAuthentication + kubelet probe exception |
| [`mesh/default-deny.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/mesh/default-deny.yaml) | Default-deny AuthorizationPolicy (L7) + NetworkPolicy (L3/L4) |
| [`mesh/authorization-policies/orders-policy.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/mesh/authorization-policies/orders-policy.yaml) | Example explicit allow: api-gateway → orders-svc |
| [`mesh/obo-propagation/envoy-filter.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/mesh/obo-propagation/envoy-filter.yaml) | OBO header extraction, chain append, traceparent preservation + Telemetry API |
