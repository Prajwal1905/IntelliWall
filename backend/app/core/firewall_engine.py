from app.core.model_loader import predict
from app.core.risk_engine import calculate_risk, decide_action
from app.core.nlp_engine import detect_threat_keywords
from app.core.explain import generate_reasons
from app.core.federated_engine import federated_anomaly_score
from app.core.tls_engine import analyze_tls
from app.core.threat_intel import check_blacklist
from app.core.blocker import is_blocked
from app.core.config import MODE
from app.api.honeypot import blocked_ips

# memory
device_risk_memory = {}
device_trust_score = {}


def smart_firewall(features, source="Device_X", geo=None):

    # blocked / blacklist
    if source in blocked_ips:
        return "BLOCK", 100, ["Blocked via honeypot"], "Blacklisted", "Blocked", 0

    if check_blacklist(source):
        return "BLOCK", 100, ["Blacklisted IP"], "Known Malicious", "Blocked", 0

    if is_blocked(source):
        if device_risk_memory.get(source, 0) > 120:
            return "BLOCK", 100, ["Repeat attacker"], "Repeat Offender", "Blocked", 0

    # ensure features
    if len(features) < 10:
        features = list(features) + [0] * (10 - len(features))

    duration, requests, byte_rate, _, packet_size, _, interval, _, is_encrypted, tls_flag = features

    row = {
        "duration": duration,
        "requests": requests,
        "byte_rate": byte_rate,
        "packet_size": packet_size,
        "avg_packet_interval": interval
    }

    # AI
    anomaly, iso_score, cnn_score = predict(features)
    fed_score = federated_anomaly_score(features)
    combined_score = (iso_score + fed_score) / 2

    # risk
    risk = calculate_risk(anomaly, combined_score, row)

    # CNN boost
    risk += int(cnn_score * 5)

    # TLS
    tls_risk, tls_reasons = analyze_tls(features)
    risk += tls_risk

    # trust system
    if source not in device_trust_score:
        device_trust_score[source] = 100

    device_trust_score[source] -= risk * 0.02
    device_trust_score[source] = max(0, min(100, device_trust_score[source]))

    if device_trust_score[source] < 40:
        risk += 10

    # memory
    if source not in device_risk_memory:
        device_risk_memory[source] = 0

    if risk > 50:
        device_risk_memory[source] += risk
    else:
        device_risk_memory[source] = max(0, device_risk_memory[source] - 15)

    if device_risk_memory[source] > 120:
        risk += 8

    # nlp
    if detect_threat_keywords(str(row)):
        risk += 5

    risk = max(0, min(risk, 100))

    action = decide_action(risk)

    # behavioral override
    repeat = device_risk_memory.get(source, 0) // 100
    if repeat >= 4 and risk >= 50:
        action = "BLOCK"
    elif repeat >= 2 and risk >= 40:
        action = "HONEYPOT"

    # classification
    if risk >= 80:
        device_status = "Blocked"
    elif risk >= 50:
        device_status = "Suspicious"
    else:
        device_status = "Trusted"

    if requests > 70 and interval < 0.2:
        attack_type = "Network Scan"
    elif byte_rate > 7000:
        attack_type = "DDoS"
    elif anomaly == 1:
        attack_type = "Suspicious"
    else:
        attack_type = "Normal"

    reasons = generate_reasons(row, anomaly, iso_score)
    reasons.extend(tls_reasons)

    trust_score = round(device_trust_score[source], 2)

    return action, risk, reasons, attack_type, device_status, trust_score