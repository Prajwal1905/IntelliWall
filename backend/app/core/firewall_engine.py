def smart_firewall(features, source="Device_X"):
    #  rule-based logic

    risk = sum(features) % 100

    if risk > 70:
        action = "BLOCK"
        attack_type = "Suspicious Traffic"
    else:
        action = "ALLOW"
        attack_type = "Normal"

    return action, risk, [], attack_type, "Unknown", 100