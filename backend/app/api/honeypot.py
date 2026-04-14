from fastapi import APIRouter
from datetime import datetime
from app.core.blocklist import blocked_ips

router = APIRouter()

honeypot_logs = []


@router.post("/honeypot")
def capture_attack(data: dict):
    log = {
        "timestamp": str(datetime.now()),
        "source": data.get("source"),
        "attack_type": data.get("attack_type"),
        "risk": data.get("risk", 0),
        "features": data.get("features"),
    }

    honeypot_logs.append(log)

    print("\n HONEYPOT CAPTURED ATTACK")
    print(log)

    return {"status": "captured"}


@router.get("/honeypot/logs")
def get_logs():
    profiles = {}

    for log in honeypot_logs:
        ip = log.get("source", "unknown")

        if ip not in profiles:
            profiles[ip] = {
                "source": ip,
                "count": 0,
                "max_risk": 0,
                "total_risk": 0,
                "attack_types": set()
            }

        profiles[ip]["count"] += 1
        profiles[ip]["max_risk"] = max(
            profiles[ip]["max_risk"], log.get("risk", 0)
        )
        profiles[ip]["total_risk"] += log.get("risk", 0)

        if log.get("attack_type"):
            profiles[ip]["attack_types"].add(log["attack_type"])

    # enhance
    for p in profiles.values():
        avg_risk = p["total_risk"] / p["count"]
        threat_score = (p["count"] * 5) + avg_risk

        if threat_score >= 80:
            level = "HIGH"
        elif threat_score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        p["avg_risk"] = round(avg_risk, 2)
        p["threat_score"] = round(threat_score, 2)
        p["level"] = level
        p["attack_types"] = list(p["attack_types"])

    # remove blocked
    profiles = {
        ip: p for ip, p in profiles.items()
        if ip not in blocked_ips
    }

    return {
        "logs": honeypot_logs[-50:],
        "profiles": list(profiles.values())
    }


@router.post("/honeypot/block")
def block_ip(data: dict):
    ip = data.get("ip")

    if ip:
        blocked_ips.add(ip)

    return {"status": "blocked"}