from app.core.model_loader import predict
from app.core.risk_engine import calculate_risk, decide_action
from app.core.response_engine import auto_response
from app.db.crud import save_alert
from app.core.blocker import block_ip, is_blocked
from app.core.threat_intel import check_blacklist
from app.core.tls_engine import analyze_tls
from app.core.nlp_engine import detect_threat_keywords
from app.core.federated_engine import federated_anomaly_score

def smart_firewall(features, source="Device_X"):
    # check if already blocked
    if is_blocked(source):
        return "BLOCK", 100, ["Previously blocked"], "Blocked IP", "Blocked", 0

    # check blacklist
    if check_blacklist(source):
        return "BLOCK", 100, ["Blacklisted IP"], "Known Malicious", "Blocked", 0

    anomaly, score, _ = predict(features)
    fed_score = federated_anomaly_score(features)
    score = (score + fed_score) / 2

    data = {
        "requests": features[1],
        "byte_rate": features[2]
    }

    # calculate risk
    risk = calculate_risk(anomaly, score, data)
    tls_risk, tls_reasons = analyze_tls(features)
    risk += tls_risk
    patterns = detect_threat_keywords(str(data))
    # decide action
    action = decide_action(risk)

    # apply blocking
    if action == "BLOCK":
        block_ip(source)

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

  
    isolated, logs = auto_response(action, features, attack_type, source)

    trust_score = 100

    
    save_alert({
        "protocol": "SIMULATED",
        "action": action,
        "risk": risk,
        "attack_type": attack_type,
        "trust_score": trust_score,
        "features": features,
        "source": source
    })

    return action, risk, logs, attack_type, device_status, trust_score