# ADR-0004: OPA/Gatekeeper Primary, Kyverno Alternative

**Status**: Accepted  
**Date**: 2024-05-01  
**Deciders**: Platform security team

---

## Context

Policy enforcement in Kubernetes has two distinct modes:

**Admission control** — policies evaluated when a resource is created or updated. A policy violation prevents the resource from being admitted. Examples: require resource limits, forbid privileged containers, require SPIFFE ID annotations.

**Runtime authorization** — policies evaluated per request at runtime. In the service mesh context, this means OPA as an `ext_authz` target: Envoy sends each request to OPA and awaits an allow/deny decision.

The policy engine must handle both modes from a single policy language to avoid maintaining two systems.

---

## Decision

**Primary: OPA with Gatekeeper for admission + standalone OPA for runtime**

OPA (Open Policy Agent) uses Rego, a purpose-built declarative policy language. Gatekeeper is the Kubernetes admission webhook that integrates OPA with the Kubernetes API server.

Architecture:
- **Gatekeeper** runs as a `ValidatingWebhookConfiguration`. Every `CREATE` and `UPDATE` of Pods, Deployments, and Services is evaluated against Rego policies.
- **Standalone OPA** (`opa-envoy-plugin` image) runs as a DaemonSet. Each Envoy sidecar (and the ZT gateway Envoy) sends ext_authz gRPC calls to the local OPA instance.

The two OPA instances share the same policy bundle (loaded from a ConfigMap). This ensures admission-time and runtime-time decisions use the same rules.

**OBO chain validation in OPA**

`validate-obo-chain.rego` is the critical runtime policy. It receives the HTTP request attributes (headers, SPIFFE principal) and:
1. Decodes the `X-SPIFFE-OBO-Token` JWT
2. Verifies the signature against the SPIRE trust bundle (fetched as an OPA bundle)
3. Validates the audience matches the target service's SPIFFE ID
4. Validates the caller's SPIFFE ID is in the target service's allow-list
5. Validates that the chain depth does not exceed the configured maximum (prevents privilege escalation through deep delegation)

The decision log emits `obo.caller`, `obo.via`, `obo.target`, and `allow` as structured fields, all tagged with the `trace_id` from the request headers.

**Alternative: Kyverno**

Kyverno is documented as an alternative for teams that prefer YAML-based policies over Rego. Kyverno's `ClusterPolicy` resources are more readable for engineers who work primarily in Kubernetes YAML. The tradeoff is that Kyverno does not have an ext_authz plugin — it cannot be used for runtime per-request authorization. Teams adopting Kyverno use it for admission control only and use Istio's `AuthorizationPolicy` for runtime enforcement (without the OBO chain validation capability).

```
OPA/Gatekeeper:   Admission control + runtime ext_authz + OBO chain validation
Kyverno:          Admission control only (no OBO chain enforcement at runtime)
```

If OBO chain validation at runtime is a requirement, OPA/Gatekeeper is the only option.

---

## Consequences

**Positive:**
- Single policy language (Rego) for admission and runtime. A policy change is tested once and deployed once.
- OPA's decision log provides an audit trail of every authz decision, including OBO chain details, queryable via OTEL/Loki.
- OPA ext_authz runs per-node (DaemonSet) — no cross-node authz call latency. A node failure only affects pods on that node.
- Gatekeeper's `ConstraintTemplate` + `Constraint` pattern separates policy logic (the template) from configuration (the constraint), enabling reuse.

**Negative:**
- Rego has a learning curve. Teams must invest in Rego training and maintain a `tests/` directory with unit tests for all policies. A policy bug that incorrectly denies traffic is a production incident.
- OPA DaemonSet is an additional resource consumer on every node. At 50MB RSS per node, this is non-trivial on large clusters.
- Gatekeeper admission webhook adds latency to every `kubectl apply`. With `failurePolicy: Fail`, a Gatekeeper outage blocks all deployments — production deployments must have runbook coverage for Gatekeeper failure.

---

## Comparison: OPA/Gatekeeper vs Kyverno

| Capability | OPA/Gatekeeper | Kyverno |
|---|---|---|
| Admission control | Yes (Rego) | Yes (YAML) |
| Runtime ext_authz | Yes (DaemonSet) | No |
| OBO chain validation | Yes | No |
| Policy language | Rego | YAML/CEL |
| Policy testing | `opa test` (unit tests) | `kyverno test` (unit tests) |
| Mutation policies | Yes (Gatekeeper Mutating) | Yes (first-class) |
| Generate resources | No | Yes (generate policies) |
| Learning curve | High (Rego) | Low (YAML) |

Kyverno files are in `policy/kyverno/` with a `README.md` explaining when to choose Kyverno.

---

## Related

- [ADR-0001](ADR-0001-zero-trust-model.md) — Policy plane in the three-plane model
- [ADR-0007](ADR-0007-obo-token-model.md) — OBO semantics that OPA enforces
- `policy/opa/policies/validate-obo-chain.rego` — The critical runtime OBO check
- `policy/opa/policies/require-spiffe-id.rego` — Admission: all pods must have a SPIFFE ID entry
- `policy/kyverno/README.md` — When to choose Kyverno
