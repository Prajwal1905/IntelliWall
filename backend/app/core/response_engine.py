import requests
from app.core.blocker import block_ip

def auto_response(action, features=None, attack_type=None, source=None):
    logs = []
    isolated = False

    if action == "BLOCK":
       
        result = block_ip(source if source else "unknown")
        logs.append(f" {result}")
        logs.append("Redirected to honeypot")

        isolated = True

        try:
            print("Sending to honeypot...")

            res = requests.post(
                "http://127.0.0.1:8000/honeypot",
                json={
                    "features": features,
                    "attack_type": attack_type
                },
                timeout=5
            )

            print("Honeypot response:", res.status_code)

        except Exception as e:
            logs.append(f"Honeypot error: {str(e)}")
            print("Honeypot error:", e)

    elif action == "CHALLENGE":
        logs.append("User challenged with verification")

    return isolated, logs