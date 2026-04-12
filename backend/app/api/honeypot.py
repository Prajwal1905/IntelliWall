from fastapi import APIRouter
from datetime import datetime

router = APIRouter()

honeypot_logs = []

@router.post("/honeypot")
def capture_attack(data: dict):
    log = {
        "timestamp": str(datetime.now()),
        "attack_type": data.get("attack_type"),
    }

    honeypot_logs.append(log)

    print("Honeypot captured attack:", log)

    return {"status": "captured"}


@router.get("/honeypot/logs")
def get_logs():
    return honeypot_logs