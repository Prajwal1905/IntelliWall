import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data")

model1 = joblib.load(os.path.join(DATA_PATH, "iso_client1.pkl"))
model2 = joblib.load(os.path.join(DATA_PATH, "iso_client2.pkl"))
model3 = joblib.load(os.path.join(DATA_PATH, "iso_client3.pkl"))


def federated_anomaly_score(features):
    try:
        features_8 = features[:8]

        s1 = model1.decision_function([features_8])[0]
        s2 = model2.decision_function([features_8])[0]
        s3 = model3.decision_function([features_8])[0]

        # average score
        final_score = (s1 + s2 + s3) / 3

        print(f"[Federated] A:{s1:.4f}, B:{s2:.4f}, C:{s3:.4f}")

        return final_score

    except Exception as e:
        print("Federated Error:", e)
        return 0