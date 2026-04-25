# ADR-0007: On-Behalf-Of Token Semantics End-to-End

**Status**: Accepted  
**Date**: 2024-05-01  
**Deciders**: Platform security team

---

## Context

In a microservices architecture, a user request often flows through a chain of services: API Gateway → Orders → Inventory → Customers. Each service makes a downstream call _on behalf of_ the originating user.

A naive implementation propagates the user's session token to each downstream service. This creates two problems:

1. **Over-privilege**: the Inventory service receives the user's full session token, which may carry permissions far beyond what Inventory needs from Customers.
2. **No service identity in the chain**: if Inventory is compromised, it can use the user's token to call any service the user has access to, not just services in the intended call chain.

The alternative — each service calls downstream with its own service identity — loses the originating user's identity. Downstream services cannot make user-specific authorization decisions.

On-Behalf-Of (OBO) solves both: a service presents its own identity (SPIFFE SVID) _and_ a delegated token (JWT SVID) that attests "this request originated from principal X, delegated through service Y."

---

## Decision

Adopt **SPIFFE JWT SVID as the OBO delegation mechanism**.

### Token construction

When service A (e.g., `orders-svc`) needs to call service B (e.g., `inventory-svc`) on behalf of the originating principal `user@chakra.internal`:

1. Service A requests a JWT SVID from its SPIRE agent:
   ```
   audience: spiffe://chakra.internal/ns/inventory/sa/inventory-svc
   subject: spiffe://chakra.internal/ns/orders/sa/orders-svc
   ```
   The SPIRE agent issues a JWT SVID signed by the SPIRE CA, with a 5-minute TTL.

2. Service A attaches two headers on the outgoing request:
   - `X-SPIFFE-OBO-Token: <JWT SVID>` — the delegation token (signed, audience-scoped)
   - `X-SPIFFE-Caller-Chain: spiffe://chakra.internal/ns/orders/sa/orders-svc` — the call chain (append-only, verified at each hop)

3. The originating user identity is carried in `X-SPIFFE-User-Principal: user@chakra.internal` (set at the ingress gateway, signed with an ingress JWT that the user principal is verified against).

### Validation at each hop

Service B's Envoy sidecar sends the request to OPA via ext_authz. `validate-obo-chain.rego` performs:

```rego
allow if {
    # 1. The JWT SVID audience matches this service
    token.payload.aud == spiffe_id_for_this_service

    # 2. The JWT SVID signature is valid (verified against SPIRE JWKS)
    valid_jwt_signature(token)

    # 3. The caller in the JWT subject is in this service's allow-list
    token.payload.sub in data.allow_list[input.destination.principal]

    # 4. Chain depth does not exceed maximum (prevents unbounded delegation)
    count(caller_chain) <= data.max_chain_depth

    # 5. No chain tampering: each entry in the chain has a valid JWT SVID for its hop
    all_chain_links_valid(caller_chain)
}
```

The SPIRE trust bundle (JWKS) is loaded as an OPA bundle from a ConfigMap that SPIRE populates. OPA refreshes it every 60 seconds.

### Chain depth limit

The maximum chain depth is set per service in `identity/spiffe-ids.yaml`:

```yaml
- spiffe_id: spiffe://chakra.internal/ns/inventory/sa/inventory-svc
  max_obo_chain_depth: 3
  allowed_callers:
    - spiffe://chakra.internal/ns/orders/sa/orders-svc
    - spiffe://chakra.internal/ns/api-gateway/sa/api-gateway
```

A depth limit of 3 allows: ingress → orders → inventory. A chain of 4 or more is rejected — this prevents a compromised service from recursively delegating to itself to escalate privileges.

### OBO in the ZT Gateway

The ZT gateway enforces OBO in the same way as Istio sidecars — via the same `ext_authz` call to OPA. The OBO check at the gateway is the entry point for legacy applications: the legacy app does not need to know about OBO at all. The gateway validates the chain before forwarding.

For _outbound_ calls from the legacy app (legacy app calling a downstream service), the gateway cannot automatically construct the OBO token (it does not know the downstream service's SPIFFE ID). Two options:
1. **Wrapper library**: a thin HTTP client library that legacy apps can adopt without touching business logic. It requests the JWT SVID from the local SPIRE agent and attaches headers.
2. **Outbound gateway pattern**: the legacy app's outbound traffic is routed through an outbound gateway container (same-pod variant) that constructs the OBO token based on a configurable downstream allowlist.

Both options are documented in `gateway/obo-enforcement/`.

### OBO in OTEL traces

Every span produced by a service or gateway includes:
- `obo.caller_principal` — the immediate caller's SPIFFE ID
- `obo.chain` — JSON array of the full call chain (ordered from originator to immediate caller)
- `obo.user_principal` — the originating user (if present)
- `obo.token_ttl_seconds` — remaining TTL of the OBO JWT SVID at validation time

These attributes are set by the OTEL OBO enrichment processor in the OTEL Collector pipeline. See [ADR-0008](ADR-0008-observability.md).

---

## Consequences

**Positive:**
- A service can make user-specific authorization decisions (e.g., "only the user who placed this order can cancel it") without the user's session token traversing the entire service graph.
- OBO tokens are audience-scoped: a compromised `orders-svc` with an OBO token for `inventory-svc` cannot use that token to call `customers-svc`.
- The call chain is auditable: every OPA decision log record contains the full chain. A security incident investigation can reconstruct the exact path a request took.
- Short TTLs (5 minutes) limit the blast radius of a stolen OBO token to the token's remaining lifetime.

**Negative:**
- Every inter-service call requires a JWT SVID request to the SPIRE agent. The SPIRE agent caches SVIDs — the first call within a 5-minute window is the only one that hits the SPIRE server. Applications must be designed to reuse tokens within their TTL.
- Adding a new service-to-service call path requires: (a) updating `identity/spiffe-ids.yaml` with the new allowed caller, (b) reloading the OPA bundle, (c) testing the new path end-to-end. This is intentional friction — undeclared call paths should not silently succeed.
- Legacy applications making outbound calls require either the wrapper library or the outbound gateway. Neither is zero-effort.

---

## Related

- [ADR-0002](ADR-0002-spiffe-spire.md) — JWT SVID issuance by SPIRE
- [ADR-0003](ADR-0003-istio-service-mesh.md) — OBO header propagation in Istio mesh
- [ADR-0004](ADR-0004-opa-policy.md) — OPA enforcing OBO chain validation
- [ADR-0006](ADR-0006-zt-gateway-proxy.md) — ZT gateway as OBO enforcement point for legacy apps
- [ADR-0008](ADR-0008-observability.md) — OBO chain attributes in OTEL spans
- `identity/obo-token-policy.rego` — OPA bundle policy for OBO chain validation
- `mesh/obo-propagation/envoy-filter.yaml` — Envoy filter extracting and re-attaching OBO headers
- `gateway/obo-enforcement/` — OBO enforcement in the ZT gateway
