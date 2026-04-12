from fastapi import APIRouter
from app.core.firewall_engine import smart_firewall

router = APIRouter()

@router.post("/analyze")
def analyze():
    # dummy example 
    action, risk, reasons, attack_type, device_status, trust_score = smart_firewall(
        [100, 10, 500, 10, 50, 5, 0.1, 0.05, 1, 0],
        "test_device"
    )

    return {
        "action": action,
        "risk": risk,
        "attack_type": attack_type
    }