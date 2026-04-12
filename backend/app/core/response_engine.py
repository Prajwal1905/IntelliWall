def auto_response(action, features=None, attack_type=None, source=None):
    logs = []
    isolated = False

    if action == "BLOCK":
        logs.append("Blocked suspicious source")
        isolated = True

    elif action == "CHALLENGE":
        logs.append("User challenged for verification")

    else:
        logs.append("Traffic allowed")

    return isolated, logs