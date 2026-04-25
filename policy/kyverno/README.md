# Kyverno — Alternative to OPA/Gatekeeper

Kyverno is a Kubernetes-native policy engine that uses YAML/CEL instead of Rego.

## When to choose Kyverno over OPA/Gatekeeper

| Requirement | Use OPA/Gatekeeper | Use Kyverno |
|---|---|---|
| Runtime per-request authz (ext_authz) | **Required** | Not supported |
| OBO chain validation at request time | **Required** | Not supported |
| Team expertise | Rego experience | Kubernetes YAML experience |
| Policy mutation | Supported | First-class (better) |
| Resource generation policies | Not supported | Supported |
| Policy testing | `opa test` | `kyverno test` |
| Admission control only | Supported | Supported |

**Critical limitation:** Kyverno does not have an ext_authz plugin. If your zero-trust requirement includes OBO chain validation at request time (not just at admission time), OPA/Gatekeeper is the only option in this stack.

Kyverno is an excellent choice for teams that:
- Use Istio `AuthorizationPolicy` for runtime enforcement (SPIFFE principal allow-lists)
- Do not need per-request OBO chain depth or audience validation
- Prefer YAML policies that are reviewed alongside Kubernetes manifests
- Need resource generation (e.g., auto-create NetworkPolicy for every new namespace)

## Files

- `policies/require-spiffe-id.yaml` — Kyverno equivalent of OPA's `require-spiffe-id.rego`
- `policies/require-resource-limits.yaml` — Kyverno equivalent of OPA's `no-privileged-containers.rego`

## Running Kyverno tests

```bash
kyverno test policy/kyverno/
```
