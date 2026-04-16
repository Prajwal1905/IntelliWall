def calculate_risk(anomaly, score, data):

    risk = 5  

    normalized_score = max(min(score, 1), -1)
    confidence_risk = int((1 - normalized_score) * 18)
    risk += confidence_risk

    if anomaly == 1:
        risk += 15

    if data["packet_size"] > 1800:
        risk += 4

    if data["requests"] > 120:
        risk += 15

    if data["byte_rate"] > 6000:
        risk += 5
    
    if data["requests"] > 100 and data["byte_rate"] > 7000:
        risk += 12
    
    if data["avg_packet_interval"] < 0.02:
        risk += 4

    return min(max(risk, 0), 100)

def decide_action(risk):
    if risk >= 85:
        return "BLOCK"
    elif risk >= 45:
        return "HONEYPOT"
    elif risk >= 30:
        return "CHALLENGE"
    else:
        return "ALLOW"