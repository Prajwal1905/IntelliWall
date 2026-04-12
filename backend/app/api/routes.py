from fastapi import APIRouter
from app.core.firewall_engine import smart_firewall
from app.db.crud import get_alerts
from app.schemas.request import TrafficRequest
from app.core.graph_engine import update_graph

router = APIRouter()

@router.post("/analyze")
def analyze(data: TrafficRequest):

    features = [
        data.duration,
        data.requests,
        data.byte_rate,
        data.requests / (data.duration + 1),
        data.packet_size,
        data.packet_size * 0.1,
        data.avg_packet_interval,
        data.avg_packet_interval * 0.5,
        1,
        0
    ]

    action, risk, reasons, attack_type, device_status, trust_score = smart_firewall(
        features,
        data.source
    )

    graph = update_graph(data.source, risk)

    return {
        "action": action,
        "risk": risk,
        "attack_type": attack_type,
        "device_status": device_status,
        "graph": graph
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