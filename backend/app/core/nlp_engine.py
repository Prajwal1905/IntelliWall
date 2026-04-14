def detect_threat_keywords(text=""):
    threats = []

    keywords = {
        "ddos": "DDoS attack pattern",
        "bot": "Botnet activity",
        "c2": "Command & Control traffic"
    }

    for key, value in keywords.items():
        if key in text.lower():
            threats.append(value)

    return threats


def match_threat_patterns(row):
    patterns = []

    if row["packet_size"] > 1200 and row["requests"] > 40:
        patterns.append("DDoS pattern")

    if row["requests"] > 30 and row["duration"] > 150:
        patterns.append("Botnet activity")

    if row["byte_rate"] < 5 and row["duration"] > 200:
        patterns.append("C2 communication")

    if row["packet_size"] > 1000:
        patterns.append("Traffic flood")

    return patterns