from fastapi import APIRouter
from datetime import datetime
from app.core.blocklist import blocked_ips

router = APIRouter()

honeypot_logs = []


@router.post("/honeypot")
def capture_attack(data: dict):
    log = {
        "timestamp": str(datetime.now()),
        "source": data.get("source", "unknown"),
        "attack_type": data.get("attack_type"),
        "risk": data.get("risk", 0),
        "features": data.get("features"),
    }

    honeypot_logs.append(log)

    print("\n HONEYPOT CAPTURED ATTACK")
    print("Source:", log["source"])
    print("Type:", log["attack_type"])
    print("-" * 40)

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
                "attack_types": set()
            }

        profiles[ip]["count"] += 1
        profiles[ip]["max_risk"] = max(
            profiles[ip]["max_risk"], log.get("risk", 0)
        )

        if log.get("attack_type"):
            profiles[ip]["attack_types"].add(log["attack_type"])

    for p in profiles.values():
        p["attack_types"] = list(p["attack_types"])

    # remove blocked IPs
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
        print(f"BLOCKED IP: {ip}")

    return {"status": "blocked"}