
from app.core.model_loader import predict

def smart_firewall(features, source="Device_X"):
    
    # use model prediction
    anomaly, score, _ = predict(features)

    # basic risk calculation
    risk = int(score)

    # simple decision logic
    if anomaly == 1 or risk > 70:
        action = "BLOCK"
        attack_type = "Suspicious Traffic"
        device_status = "Suspicious"
    else:
        action = "ALLOW"
        attack_type = "Normal"
        device_status = "Trusted"

    # placeholder values
    reasons = []
    trust_score = 100

    return action, risk, reasons, attack_type, device_status, trust_score