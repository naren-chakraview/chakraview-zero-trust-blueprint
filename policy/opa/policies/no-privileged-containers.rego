package chakra.admission.security

import future.keywords.if
import future.keywords.in

# Admission policies for container security hardening.
# A privileged container defeats network isolation — it can manipulate
# iptables rules that Istio and NetworkPolicy depend on.

violation[{"msg": msg}] if {
    input.review.kind.kind == "Pod"
    container := input.review.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container %v is privileged. Privileged containers can bypass iptables-based network policies.", [container.name])
}

violation[{"msg": msg}] if {
    input.review.kind.kind == "Pod"
    container := input.review.object.spec.containers[_]
    container.securityContext.capabilities.add[_] in {"NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE"}
    msg := sprintf("Container %v adds dangerous capability %v which can undermine network isolation.", [container.name, container.securityContext.capabilities.add[_]])
}

violation[{"msg": msg}] if {
    input.review.kind.kind == "Pod"
    input.review.object.spec.hostNetwork == true
    msg := "hostNetwork: true is prohibited. Use Kubernetes Services for inter-pod communication."
}

violation[{"msg": msg}] if {
    input.review.kind.kind == "Pod"
    input.review.object.spec.hostPID == true
    not spire_agent_pod(input.review.object)
    msg := "hostPID: true is prohibited except for the SPIRE agent DaemonSet."
}

# Resource limits are required — a pod without limits can starve the OPA DaemonSet.
violation[{"msg": msg}] if {
    input.review.kind.kind == "Pod"
    container := input.review.object.spec.containers[_]
    not container.resources.limits.memory
    not exempt_namespace(input.review.object.metadata.namespace)
    msg := sprintf("Container %v has no memory limit. All containers must declare resource limits.", [container.name])
}

spire_agent_pod(pod) if {
    pod.metadata.namespace == "spire"
    pod.metadata.labels.app == "spire-agent"
}

exempt_namespace(ns) if {
    ns in {"kube-system", "kube-public", "kube-node-lease"}
}
