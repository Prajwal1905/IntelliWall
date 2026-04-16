def analyze_tls(features):
    is_encrypted = features[8]
    tls_suspicious = features[9]

    tls_risk = 0
    reasons = []

    if is_encrypted:
        tls_risk += 2
        reasons.append("Encrypted communication")

    if tls_suspicious:
        tls_risk += 4
        reasons.append("Unusual TLS packet size")

    
    if is_encrypted and features[2] > 5000:
        tls_risk += 5
        reasons.append("High data rate over TLS")

    if is_encrypted and features[6] < 0.02:
        tls_risk += 3
        reasons.append("Suspicious rapid TLS communication")

    if is_encrypted and tls_suspicious:
        tls_risk += 3
        reasons.append("Potential hidden threat in encrypted traffic")

    return tls_risk, reasons
