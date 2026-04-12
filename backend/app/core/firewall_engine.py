

from app.core.model_loader import predict
from app.core.risk_engine import calculate_risk, decide_action


def smart_firewall(features, source="Device_X"):
    
    
    anomaly, score, _ = predict(features)

    
    data = {
        "requests": features[1],
        "byte_rate": features[2]
    }

    # calculate risk
    risk = calculate_risk(anomaly, score, data)

    # decide action
    action = decide_action(risk)

    # basic classification
    if action == "BLOCK":
        attack_type = "Suspicious Traffic"
        device_status = "Suspicious"
    elif action == "CHALLENGE":
        attack_type = "Potential Threat"
        device_status = "Under Observation"
    else:
        attack_type = "Normal"
        device_status = "Trusted"

    # placeholder values
    reasons = []
    trust_score = 100

    return action, risk, reasons, attack_type, device_status, trust_score