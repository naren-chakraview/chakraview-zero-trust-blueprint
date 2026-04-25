package chakra.admission.spiffe

import future.keywords.if
import future.keywords.in

# Admission policy — evaluated by Gatekeeper on every Pod CREATE/UPDATE.
# Ensures every pod has a declared SPIFFE ID entry in the registry.
# A pod without a SPIFFE ID entry will not receive an SVID from SPIRE
# and will therefore be unable to establish mTLS connections.
# Catching this at admission time prevents a silently-unreachable pod.

violation[{"msg": msg}] if {
    input.review.kind.kind == "Pod"
    sa := input.review.object.spec.serviceAccountName
    ns := input.review.object.metadata.namespace
    spiffe_id := sprintf("spiffe://chakra.internal/ns/%v/sa/%v", [ns, sa])
    not spiffe_id_registered(spiffe_id)
    msg := sprintf(
        "Pod uses service account %v/%v but SPIFFE ID %v is not registered in identity/spiffe-ids.yaml. Register the workload before deploying.",
        [ns, sa, spiffe_id]
    )
}

spiffe_id_registered(id) if {
    data.spiffe_registry[id]
}

# Exception: system namespaces and SPIRE itself do not require registration.
violation[{"msg": _}] := x if {
    x := violation_base
    not exempt_namespace(input.review.object.metadata.namespace)
}

exempt_namespace(ns) if {
    ns in {"kube-system", "kube-public", "kube-node-lease", "spire", "istio-system", "cert-manager"}
}
