# routes.py

from fastapi import APIRouter
import networkx as n
from app.core.auth_middleware import verify_token
from fastapi import Depends

from app.schemas.request import TrafficRequest

from app.core.firewall_engine import smart_firewall
from app.core.graph_engine import update_graph, G
from app.core.response_engine import auto_response
from app.core.geo import get_geo_from_ip 
from app.core.blocklist import blocked_ips

from app.db.database import SessionLocal
from app.db.models import Alert


router = APIRouter()

@router.post("/analyze")
def analyze(data: TrafficRequest, token: str = Depends(verify_token)):
    

    # Convert input into feature vector (ML model input)
    features = [
        data.duration,
        data.requests,
        data.byte_rate,
        data.requests / (data.duration + 1),
        data.packet_size,
        data.packet_size * 0.1,
        data.avg_packet_interval,
        data.avg_packet_interval * 0.5,
        0,
        0
    ]

    # Run firewall engine
    action, risk, reasons, attack_type, device_status, trust_score = smart_firewall(
        features,
        data.source
    )
    if risk >= 30 or action in ["BLOCK", "CHALLENGE"]:
        blocked_ips.add(data.source)
        print(f" FIREWALL AUTO BLOCKED: {data.source}")
    # Update network graph
    graph = update_graph(data.source, risk)

    # Trigger automated response
    isolated, logs = auto_response(action, features, attack_type)
    
    db = SessionLocal()

    try:
        geo = get_geo_from_ip(data.source)

        new_alert = Alert(
            protocol=str(data.protocol),
            action=action,
            risk=risk,
            attack_type=attack_type,
            trust_score=trust_score,
            source=data.source,
            isp=geo.get("isp", "Unknown"),
            proxy=geo.get("proxy", False),
            hosting=geo.get("hosting", False),
            lat=geo.get("lat", 0),
            lon=geo.get("lon", 0),
            country=geo.get("country", "Unknown"),
        )

        db.add(new_alert)
        db.commit()

    finally:
        db.close()

    return {
        "action": action,
        "risk": risk,
        "attack_type": attack_type,
        "device_status": device_status,
        "trust_score": trust_score,
        "reasons": reasons,
        "isolated": isolated,
        "honeypot": logs,
        "graph": graph
    }


@router.get("/alerts")
def get_alerts(token: str = Depends(verify_token)):
    
    db = SessionLocal()

    try:
        alerts = db.query(Alert).order_by(Alert.id.desc()).limit(50).all()

        result = []

        for a in alerts:
           

            result.append({
                "protocol": a.protocol,
                "action": a.action,
                "risk": a.risk,
                "attack_type": a.attack_type,
                "trust_score": a.trust_score,
                "timestamp": a.timestamp,
                "source": a.source,
                "isp": a.isp,
                "proxy": a.proxy,
                "hosting": a.hosting,

                "lat": a.lat,
                "lon": a.lon,
                "country": a.country,
            })

        return result

    finally:
        db.close()


@router.get("/graph")
def get_graph():
    import copy

    #  Copy graph 
    filtered_G = copy.deepcopy(G)

    #  Remove blocked nodes
    for ip in list(filtered_G.nodes):
        if ip in blocked_ips:
            filtered_G.remove_node(ip)

    return nx.node_link_data(filtered_G)


@router.get("/risk")
def get_system_risk(token: str = Depends(verify_token)):
    db = SessionLocal()

    try:
        alerts = db.query(Alert).order_by(Alert.id.desc()).limit(50).all()

        active_risks = []

        for a in alerts:
            #  ignore blocked IPs
            if a.source in blocked_ips:
                continue

            # ignore safe traffic
            if a.risk < 10:
                continue

            active_risks.append(a.risk)

        if not active_risks:
            return {"risk": 5}

        final_risk = sum(active_risks) / len(active_risks)

        return {"risk": int(final_risk)}

    finally:
        db.close()