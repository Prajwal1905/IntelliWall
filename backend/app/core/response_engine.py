from datetime import datetime

honeypot_logs = []

def auto_response(action, features=None, attack_type=None, source=None):
    logs = []
    isolated = False

    if action == "BLOCK":
        logs.append(f"Blocked source: {source}")
        logs.append(f"Detected attack: {attack_type}")
        isolated = True

        
        log = {
            "timestamp": str(datetime.now()),
            "attack_type": attack_type,
            "source": source
        }

        honeypot_logs.append(log)
        logs.append("Redirected to honeypot")

    elif action == "CHALLENGE":
        logs.append(f"Challenge issued to source: {source}")

    else:
        logs.append("Traffic allowed")

    return isolated, logs