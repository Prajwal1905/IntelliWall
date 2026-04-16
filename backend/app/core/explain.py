def generate_reasons(data, anomaly, score):
    reasons = []

    if anomaly:
        if score < -0.2:
            reasons.append("Strong anomaly detected (high confidence)")
        else:
            reasons.append("Moderate anomaly detected")

    if data["packet_size"] > 1200:
        reasons.append("Unusually large packet size")

    if data["requests"] > 50:
        reasons.append("High request frequency")

    if data["byte_rate"] > 5000:
        reasons.append("Abnormal data transfer rate")

    if data["avg_packet_interval"] < 0.05:
        reasons.append("Suspicious rapid packet intervals")

    return reasons


def explain_decision(row, patterns, graph_flag):
    
    reasons = []
    
    # AI anomaly
    if row.get("anomaly", 0) == 1:
        reasons.append("Anomalous behavior detected")
    
    # Feature-based reasons
    if row["packet_size"] > 1000:
        reasons.append("Unusually high packet size")
    
    if row["requests"] > 40:
        reasons.append("Too many requests (possible flood)")
    
    if row["avg_packet_interval"] < 10:
        reasons.append("Very fast packet rate")
    
    if row["duration"] > 150:
        reasons.append("Long connection duration")
    
    # NLP patterns
    reasons.extend(patterns)
    
    # Graph
    if graph_flag == 1:
        reasons.append("Suspicious network behavior (graph anomaly)")
    
    return reasons
