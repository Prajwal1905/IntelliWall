# basic risk calculation logic

def calculate_risk(anomaly, score, data):
    
    # simple base risk
    risk = int(score)

    # increase risk if anomaly detected
    if anomaly == 1:
        risk += 20

    # basic traffic checks
    if data["requests"] > 100:
        risk += 10

    if data["byte_rate"] > 5000:
        risk += 10

    return min(risk, 100)


def decide_action(risk):
    if risk > 70:
        return "BLOCK"
    elif risk > 40:
        return "CHALLENGE"
    else:
        return "ALLOW"