def load_model():
    print("Model initialized (prototype)")


def predict(features):
    # simple mock logic

    score = sum(features) % 100

    if score > 60:
        anomaly = 1
    else:
        anomaly = 0

    return anomaly, score, 0.5