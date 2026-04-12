# firewall logic with model + risk + response system

from app.core.model_loader import predict
from app.core.risk_engine import calculate_risk, decide_action
from app.core.response_engine import auto_response
from app.db.crud import save_alert

def smart_firewall(features, source="Device_X"):
    
   
    anomaly, score, _ = predict(features)

   
    data = {
        "requests": features[1],
        "byte_rate": features[2]
    }

    # calculate risk
    risk = calculate_risk(anomaly, score, data)

    # decide action
    action = decide_action(risk)

    # basic classification
    if action == "BLOCK":
        attack_type = "Suspicious Traffic"
        device_status = "Suspicious"
    elif action == "CHALLENGE":
        attack_type = "Potential Threat"
        device_status = "Under Observation"
    else:
        attack_type = "Normal"
        device_status = "Trusted"

    
    isolated, logs = auto_response(action, features, attack_type, source)
    trust_score = 100
    # save alert to database
    save_alert({
       "protocol": "SIMULATED",
       "action": action,
       "risk": risk,
       "attack_type": attack_type,
       "trust_score": trust_score,
       "features": features,
       "source": source
    })
    

    return action, risk, logs, attack_type, device_status, trust_score