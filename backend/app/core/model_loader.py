
import joblib
import numpy as np
from tensorflow.keras.models import load_model as keras_load_model

iso_model = None
cnn_model = None
scaler = None

def load_model():
    global iso_model, cnn_model, scaler

    iso_model = joblib.load("app/data/iso_model_real.pkl")
    cnn_model = keras_load_model("app/data/cnn_model.h5")
    scaler = joblib.load("app/data/scaler.pkl")


def predict(features):
    global iso_model, cnn_model, scaler

    # convert to numpy
    X = np.array([features[:8]])

    
    X_scaled = scaler.transform(X)

    
    iso_pred = iso_model.predict(X_scaled)[0]   # -1 / 1
    iso_score = iso_model.decision_function(X_scaled)[0]

    anomaly = 1 if iso_pred == -1 else 0

   
    cnn_score = cnn_model.predict(X_scaled, verbose=0)[0][0]

    return anomaly, iso_score, cnn_score