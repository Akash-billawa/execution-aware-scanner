# @name: kev-auto-block
# @description: Auto-block egress for KEV findings with EPSS > 0.7
package scanner

decision = result {
    input.finding.kev == true
    input.finding.epss > 0.7
    result := {
        "action": "block",
        "reason": sprintf("KEV finding %s with EPSS %.2f exceeds threshold", [input.finding.cve, input.finding.epss]),
        "rule_id": "kev-auto-block",
        "policy_name": "kev-auto-block"
    }
}
