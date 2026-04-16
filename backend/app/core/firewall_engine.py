
from app.core.model_loader import predict
from app.core.risk_engine import calculate_risk, decide_action
##from app.core.graph_engine import update_graph, get_suspicious_nodes
from app.core.nlp_engine import detect_threat_keywords
from app.core.explain import generate_reasons
from app.core.federated_engine import federated_anomaly_score
from app.core.tls_engine import analyze_tls
from app.core.threat_intel import check_blacklist
from app.core.blocker import is_blocked
from app.core.config import MODE
from app.core.threat_db import is_blacklisted
from app.api.honeypot import blocked_ips

device_risk_memory = {}

device_trust_score = {}


def smart_firewall(features, source="Device_X",geo=None):
    if source in blocked_ips:
        return "BLOCK", 100, ["Manually blocked from Honeypot"], "Blacklisted", "Blocked", 0
    is_known_threat = False

    if is_blacklisted(source):
        is_known_threat = True
        risk = 100
    if is_blocked(source):
        if device_risk_memory.get(source, 0) > 120:
            return "BLOCK", 100, ["Previously blocked IP"], "Repeat Offender", "Blocked", 0
        else:
        
            device_risk_memory[source] = 0
    if check_blacklist(source):
       return "BLOCK", 100, ["Blacklisted IP detected"], "Known Malicious IP", "Blocked", 0
    #  Ensure always 10 features
    if len(features) < 10:
        features = list(features) + [0] * (10 - len(features))

    
    duration, total_fwd_packets, flow_bytes_s, flow_packets_s, packet_length_mean, packet_length_std, flow_iat_mean, flow_iat_std, is_encrypted, tls_suspicious = features

    row = {
        "duration": duration,
        "requests": total_fwd_packets,
        "byte_rate": flow_bytes_s,
        "packet_size": packet_length_mean,
        "avg_packet_interval": flow_iat_mean
    }

   
    anomaly, iso_score, cnn_score = predict(features)

    
    fed_score = federated_anomaly_score(features)
    print(f"[Federated Score]: {fed_score:.4f}")

    combined_iso = (iso_score + fed_score) / 2
    
    
    if not is_known_threat:
        risk = calculate_risk(anomaly, combined_iso, row)
    else:
        risk = 100
    if MODE == "REAL":
        if risk < 60:

            if ":" in source:
                risk -= 3   

            if geo and not geo.get("proxy", False) and not geo.get("hosting", False):
                risk -= 3

            if device_trust_score.get(source, 100) > 90:
                risk -= 2
    

    #  CNN influence 
    risk += int(cnn_score * 5)

    #tls 
    tls_risk, tls_reasons = analyze_tls(features)
    risk += tls_risk

    #zero trust
    if source not in device_trust_score:
        device_trust_score[source] = 100

    device_trust_score[source] -= risk * 0.02
    device_trust_score[source] = max(0, min(100, device_trust_score[source]))

    if device_trust_score[source] < 30:
        risk += 15
    elif device_trust_score[source] < 60:
        risk += 8

    #memory
    if source not in device_risk_memory:
        device_risk_memory[source] = 0

    if risk > 50:
        device_risk_memory[source] += risk
    else:
   
        device_risk_memory[source] = max(0, device_risk_memory[source] - 20) 

    device_risk_memory[source] = min(device_risk_memory[source], 200)

    if device_risk_memory[source] > 150 and risk > 60:
        risk += 10
    elif device_risk_memory[source] > 80 and risk > 50:
        risk += 5
    
    #graph
    #update_graph(source, risk)
    
    #suspicious_nodes = get_suspicious_nodes()
    
    #nlp
    patterns = detect_threat_keywords(str(row))

    
    risk = max(0, min(risk, 100))

    action = decide_action(risk)

# behavioral override 
    repeat_count = device_risk_memory.get(source, 0) // 100

    suspicious_signal = (
       total_fwd_packets > 70 or
       flow_bytes_s > 5000 or
       flow_iat_mean < 0.1 
       
    )

#  STRONG ATTACK
    if repeat_count >= 5 and suspicious_signal:
       action = "BLOCK"

#  MEDIUM ATTACK 
    elif 3 <= repeat_count < 5 and suspicious_signal and risk >= 40:
        action = "HONEYPOT"

    if risk >= 85:
        device_status = "Blocked "
    elif risk >= 60:
        device_status = "Suspicious "
    else:
        device_status = "Trusted "



    if total_fwd_packets > 70 and flow_iat_mean < 0.2:
        attack_type = "T1046 - Network Scan"

    elif flow_bytes_s > 7000 and total_fwd_packets > 80:
        attack_type = "T1498 - DDoS Attack"

    elif anomaly == 1 and flow_bytes_s > 3000:
        attack_type = "T1071 - Command & Control"

    elif anomaly == 1:
        attack_type = "Suspicious Behavior"

    else:
        attack_type = "Normal"

    
    reasons = generate_reasons(row, anomaly, iso_score)
    reasons.extend(tls_reasons)

    trust_score = round(device_trust_score[source], 2)
    if is_known_threat:
       action = "BLOCK"
       attack_type = "Known Threat"
       reasons.append("Blacklisted IP")
    return action, risk, reasons, attack_type, device_status, trust_score


