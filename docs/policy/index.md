---
title: Policy
description: OPA/Gatekeeper (primary) + Kyverno (alternative) — admission control and runtime OBO chain validation.
tags: [policy, opa, kyverno]
---

# Policy — OPA/Gatekeeper

Two modes of enforcement from a single policy language (Rego):

- **Admission control** via Gatekeeper — evaluated on every `CREATE`/`UPDATE` of Kubernetes resources
- **Runtime ext_authz** via OPA DaemonSet — evaluated per request by Envoy before forwarding

---

## Admission Policies

| Policy | What it enforces |
|---|---|
| `require-spiffe-id` | Every Pod must have a registered SPIFFE ID; rejects unregistered workloads at deploy time |
| `no-privileged-containers` | Forbids `privileged: true`, dangerous capabilities (`NET_ADMIN`, `SYS_ADMIN`), `hostPID`, `hostNetwork` (except SPIRE agent) |
| `require-resource-limits` | All containers must declare memory limits — prevents OPA/OTEL DaemonSet starvation |

---

## Runtime OBO Chain Validation

`validate-obo-chain.rego` is the critical runtime policy. It runs per-request on every service and at the ZT gateway.

```rego
allow if {
    # Path 1: direct call (no OBO token) — caller in allow-list
    not has_obo_token
    caller_in_allow_list
}

allow if {
    # Path 2: delegated call — validate full OBO chain
    has_obo_token
    valid_obo_token    # signature + audience + subject + TTL + chain depth
    caller_in_allow_list
}
```

**Decision log output** (forwarded to Loki via OTEL Collector):

```json
{
  "allow": true,
  "caller": "spiffe://chakra.internal/ns/orders/sa/orders-svc",
  "destination": "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
  "obo_present": true,
  "obo_chain": "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway,spiffe://chakra.internal/ns/orders/sa/orders-svc",
  "user_principal": "user@chakra.internal",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "deny_reason": "none"
}
```

Every field is indexed in Loki. The `trace_id` links each authz decision to the corresponding Tempo trace.

---

## OPA DaemonSet Architecture

OPA runs as a DaemonSet — one instance per node — so every `ext_authz` call is to `localhost:9191`. This bounds authz latency to < 3ms p99 regardless of cluster size.

```
Node
├── ZT Gateway Pod       → ext_authz → localhost:9191
├── Orders Pod sidecar   → ext_authz → localhost:9191
├── Inventory Pod sidecar→ ext_authz → localhost:9191
└── OPA DaemonSet Pod    ← SPIRE bundle (ConfigMap refresh 60s)
                         ← policy bundle (ConfigMap)
                         → /var/log/opa/decisions.json (OTEL filelog)
```

---

## Testing Policies

```bash
# Run OPA unit tests
opa test policy/opa/ -v

# Example output:
# PASS: test_direct_allowed_caller (0.001s)
# PASS: test_direct_disallowed_caller (0.001s)
# PASS: test_chain_depth_exceeded (0.001s)
# PASS: test_deny_reason_caller_not_allowed (0.001s)
```

---

## Kyverno Alternative

[:octicons-arrow-right-24: When to choose Kyverno](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/policy/kyverno/README.md)

Kyverno provides admission control with YAML policies. It does not support ext_authz — if OBO chain validation at runtime is required, OPA/Gatekeeper is the only option.

---

## Reference Implementation

| File | Purpose |
|---|---|
| [`policy/opa/policies/validate-obo-chain.rego`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/policy/opa/policies/validate-obo-chain.rego) | Runtime OBO chain validation: JWT signature, audience, chain depth, TTL |
| [`policy/opa/policies/require-spiffe-id.rego`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/policy/opa/policies/require-spiffe-id.rego) | Admission: reject pods with unregistered SPIFFE IDs |
| [`policy/opa/policies/no-privileged-containers.rego`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/policy/opa/policies/no-privileged-containers.rego) | Admission: container security hardening |
| [`policy/opa/tests/obo-chain_test.rego`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/policy/opa/tests/obo-chain_test.rego) | Unit tests for OBO chain policy |
| [`gateway/obo-enforcement/ext-authz-config.yaml`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/gateway/obo-enforcement/ext-authz-config.yaml) | OPA DaemonSet deployment + ext_authz server config |
| [`policy/kyverno/`](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint/blob/main/policy/kyverno/) | Kyverno alternative policies (admission only) |
