


def analyze_tls(features):
    # safe indexing
    is_encrypted = features[8] if len(features) > 8 else 0
    tls_suspicious = features[9] if len(features) > 9 else 0

    tls_risk = 0
    reasons = []

    if is_encrypted:
        tls_risk += 2
        reasons.append("Encrypted communication detected")

    # suspicious TLS pattern
    if tls_suspicious:
        tls_risk += 4
        reasons.append("Unusual TLS packet behavior")

    # high throughput over TLS
    if is_encrypted and features[2] > 5000:
        tls_risk += 5
        reasons.append("High data transfer over TLS")

    if is_encrypted and features[6] < 0.02:
        tls_risk += 3
        reasons.append("Rapid TLS communication pattern")

    # combined suspicious behavior
    if is_encrypted and tls_suspicious:
        tls_risk += 3
        reasons.append("Potential hidden threat in encrypted traffic")

    return tls_risk, reasons