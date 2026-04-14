

from app.core.model_loader import predict
from app.core.risk_engine import calculate_risk, decide_action
from app.core.response_engine import auto_response
from app.core.blocker import block_ip, is_blocked
from app.core.threat_intel import check_blacklist
from app.core.tls_engine import analyze_tls
from app.core.nlp_engine import detect_threat_keywords
from app.core.federated_engine import federated_anomaly_score
from app.core.explain import generate_reasons

device_risk_memory = {}


def smart_firewall(features, source="Device_X"):
   
    if is_blocked(source):
        return "BLOCK", 100, ["Previously blocked"], "Blocked IP", "Blocked", 0

    # blacklist
    if check_blacklist(source):
        return "BLOCK", 100, ["Blacklisted IP"], "Known Malicious", "Blocked", 0

    anomaly, score, _ = predict(features)

    # federated scoring
    fed_score = federated_anomaly_score(features)
    score = (score + fed_score) / 2

    data = {
        "requests": features[1],
        "byte_rate": features[2],
        "packet_size": features[4],
        "avg_packet_interval": features[6] if len(features) > 6 else 1
    }

    # risk
    risk = calculate_risk(anomaly, score, data)

    # TLS
    tls_risk, tls_reasons = analyze_tls(features)
    risk += tls_risk

    # NLP
    patterns = detect_threat_keywords(str(data))
    if patterns:
        risk += 5

    # memory
    if source not in device_risk_memory:
        device_risk_memory[source] = 0

    if risk > 50:
        device_risk_memory[source] += risk
    else:
        device_risk_memory[source] = max(0, device_risk_memory[source] - 10)

    if device_risk_memory[source] > 120:
        risk += 10

    risk = max(0, min(risk, 100))

    # decision
    action = decide_action(risk)

    # block
    if action == "BLOCK":
        block_ip(source)

    # classification
    if action == "BLOCK":
        attack_type = "Suspicious Traffic"
        device_status = "Suspicious"
    elif action == "CHALLENGE":
        attack_type = "Potential Threat"
        device_status = "Under Observation"
    else:
        attack_type = "Normal"
        device_status = "Trusted"

    # response
    isolated, logs = auto_response(action, features, attack_type, source, risk)

    trust_score = 100

    # explain
    reasons = generate_reasons(data, anomaly, score)
    reasons.extend(tls_reasons)

    return action, risk, reasons, attack_type, device_status, trust_score