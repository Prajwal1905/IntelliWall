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