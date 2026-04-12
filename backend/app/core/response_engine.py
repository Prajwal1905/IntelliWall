def auto_response(action, features=None, attack_type=None, source=None):
    logs = []
    isolated = False

    if action == "BLOCK":
        logs.append(f"Blocked source: {source}")
        logs.append(f"Detected attack: {attack_type}")
        isolated = True

    elif action == "CHALLENGE":
        logs.append(f"Challenge issued to source: {source}")

    else:
        logs.append("Traffic allowed")

    return isolated, logs