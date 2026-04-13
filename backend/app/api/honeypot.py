from fastapi import APIRouter
from datetime import datetime

router = APIRouter()

honeypot_logs = []


@router.post("/honeypot")
def capture_attack(data: dict):
    log = {
        "timestamp": str(datetime.now()),
        "attack_type": data.get("attack_type"),
        "features": data.get("features"),
        "source": data.get("source", "unknown")
    }

    honeypot_logs.append(log)

    print("\n HONEYPOT CAPTURED ATTACK")
    print("Attack Type:", log["attack_type"])
    print("Source:", log["source"])
    print("-" * 40)

    return {"status": "captured"}


@router.get("/honeypot/logs")
def get_logs():
    return honeypot_logs