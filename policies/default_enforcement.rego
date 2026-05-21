# @name: default-enforcement
# @description: Maps priority levels to enforcement actions
package scanner

default decision = {"action": "allow", "reason": "no policy matched", "rule_id": "default", "policy_name": "default-enforcement"}

decision = result {
    input.finding.priority == "Critical"
    result := {
        "action": "block",
        "reason": "Critical finding requires immediate blocking",
        "rule_id": "critical-block",
        "policy_name": "default-enforcement"
    }
}

decision = result {
    input.finding.priority == "High"
    input.finding.kev == true
    result := {
        "action": "quarantine",
        "reason": "High priority KEV finding requires quarantine",
        "rule_id": "high-kev-quarantine",
        "policy_name": "default-enforcement"
    }
}

decision = result {
    input.finding.priority == "High"
    input.finding.kev == false
    result := {
        "action": "alert",
        "reason": "High priority finding requires alerting",
        "rule_id": "high-alert",
        "policy_name": "default-enforcement"
    }
}

decision = result {
    input.finding.priority == "Medium"
    result := {
        "action": "audit",
        "reason": "Medium priority finding requires auditing",
        "rule_id": "medium-audit",
        "policy_name": "default-enforcement"
    }
}
