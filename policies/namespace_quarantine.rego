# @name: namespace-quarantine
# @description: Quarantine all findings in sensitive namespaces
package scanner

sensitive_namespaces := {"kube-system", "kube-public", "kube-node-lease", "cert-manager", "ingress-nginx"}

decision = result {
    sensitive_namespaces[input.namespace]
    input.finding.priority != "Informational"
    result := {
        "action": "quarantine",
        "reason": sprintf("Finding in sensitive namespace %s requires quarantine", [input.namespace]),
        "rule_id": "namespace-quarantine",
        "policy_name": "namespace-quarantine"
    }
}
