import requests
from app.core.blocker import block_ip


def auto_response(action, features=None, attack_type=None, source=None, risk=None):
    logs = []
    isolated = False

    
    if action == "BLOCK":
        result = block_ip(source if source else "unknown")
        logs.append(f"{result}")
        logs.append("Blocked suspicious source")

        isolated = True

    
    if action == "HONEYPOT" or (action == "BLOCK" and risk and risk >= 80):
        logs.append("Redirected to honeypot")

        try:
            requests.post(
                "http://127.0.0.1:8000/honeypot",
                json={
                    "source": source,
                    "features": features,
                    "attack_type": attack_type,
                    "risk": risk
                },
                timeout=5
            )
        except Exception as e:
            logs.append(f"Honeypot error: {str(e)}")

    
    elif action == "CHALLENGE":
        logs.append("User challenged with verification")

    return isolated, logs