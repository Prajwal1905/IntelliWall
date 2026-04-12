from fastapi import APIRouter
from app.core.firewall_engine import smart_firewall
from app.db.crud import get_alerts

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


@router.get("/alerts")
def fetch_alerts():
    alerts = get_alerts()

    return [
        {
            "protocol": a.protocol,
            "action": a.action,
            "risk": a.risk,
            "attack_type": a.attack_type,
            "trust_score": a.trust_score,
            "timestamp": a.timestamp,
            "source": a.source
        }
        for a in alerts
    ]