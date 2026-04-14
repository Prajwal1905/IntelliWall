def generate_reasons(data, anomaly, score):
    reasons = []

    if anomaly:
        if score < -0.2:
            reasons.append("Strong anomaly detected")
        else:
            reasons.append("Moderate anomaly detected")

    if data["packet_size"] > 1200:
        reasons.append("Large packet size")

    if data["requests"] > 50:
        reasons.append("High request rate")

    if data["byte_rate"] > 5000:
        reasons.append("High data transfer")

    if data["avg_packet_interval"] < 0.05:
        reasons.append("Rapid packet intervals")

    return reasons


def explain_decision(row, patterns=None, graph_flag=0):
    reasons = []

    # anomaly
    if row.get("anomaly", 0) == 1:
        reasons.append("Anomalous behavior")

    # features
    if row["packet_size"] > 1000:
        reasons.append("Large packets")

    if row["requests"] > 40:
        reasons.append("High traffic")

    if row["avg_packet_interval"] < 0.1:
        reasons.append("Fast packet rate")

    if row["duration"] > 150:
        reasons.append("Long connection")

    # patterns
    if patterns:
        reasons.extend(patterns)

    # graph
    if graph_flag:
        reasons.append("Graph anomaly detected")

    return reasons