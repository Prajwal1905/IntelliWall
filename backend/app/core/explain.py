def generate_reasons(data, anomaly, score):
    reasons = []

    if anomaly:
        reasons.append("Anomalous behavior detected")

    if data["packet_size"] > 1200:
        reasons.append("Large packet size")

    if data["requests"] > 50:
        reasons.append("High request frequency")

    if data["byte_rate"] > 5000:
        reasons.append("High data transfer rate")

    return reasons