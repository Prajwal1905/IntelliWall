import requests
from app.core.blocker import block_ip
def auto_response(action, risk=None, features=None, attack_type=None, source=None, geo=None):
    logs = []
    isolated = False

    #  BLOCK only high-risk
    if action == "BLOCK" and risk and risk >= 85:
        result = block_ip(source if source else "unknown")
        logs.append(f"{result}")
        logs.append("Blocked high-risk attacker")
        isolated = True

    #  HONEYPOT only real threats
    elif action == "HONEYPOT" :
        print(" HONEYPOT TRIGGERED", source, risk)
        logs.append("Redirected to honeypot")

        try:
            print("Sending to honeypot...")

            requests.post(
                "http://127.0.0.1:8000/honeypot",
                json={
                    "source": source,
                    "features": features,
                    "attack_type": attack_type,
                    "risk": risk ,
                    "lat": geo.get("lat") if geo else None,
                    "lon": geo.get("lon") if geo else None,
                    "country": geo.get("country") if geo else "Unknown",
                    "isp": geo.get("isp") if geo else "Unknown",
                },
                timeout=5
            )

        except Exception as e:
            logs.append(f"Honeypot error: {str(e)}")

    #  CHALLENGE
    elif action == "CHALLENGE":
        logs.append("User challenged with verification")

    return isolated, logs
