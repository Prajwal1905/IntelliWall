from fastapi import FastAPI
from app.api.routes import router
from app.api.honeypot import router as honeypot_router
from app.core.model_loader import load_model
from app.core.firewall_engine import smart_firewall
from fastapi.middleware.cors import CORSMiddleware
from app.core.packet_engine import start_sniffing
from app.core.response_engine import auto_response
from app.db.crud import save_alert
from app.core.geo import get_geo_from_ip

import threading
import time

app = FastAPI(title="SentinelX NGFW")

load_model()

app.include_router(router)
app.include_router(honeypot_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

last_event_time = {}

def is_duplicate(source):
    now = time.time()
    if source in last_event_time and now - last_event_time[source] < 2:
        return True
    last_event_time[source] = now
    return False


def handle_packet(data):
    features = data["features"]
    protocol = data.get("protocol", "unknown")
    source = data.get("source", "unknown_device")

    if is_duplicate(source):
        return

    
    action, risk, reasons, attack_type, device_status, trust_score = smart_firewall(
        features, source
    )

   
    geo = get_geo_from_ip(source)

    
    if geo["proxy"]:
        risk += 2
        reasons.append("Proxy detected")

    if geo["hosting"]:
        risk += 2
        reasons.append("Hosting network")

    risk = max(0, min(risk, 100))

    isolated, logs = auto_response(action, features, attack_type, source)

    
    save_alert({
        "protocol": protocol,
        "action": action,
        "risk": risk,
        "attack_type": attack_type,
        "trust_score": trust_score,
        "features": features,
        "source": source,
        "lat": geo["lat"],
        "lon": geo["lon"],
        "country": geo["country"],
        "isp": geo["isp"],
        "proxy": geo["proxy"],
        "hosting": geo["hosting"]
    })

    
    print("\n FIREWALL RESULT")
    print("Source:", source)
    print("Protocol:", protocol)
    print("Action:", action)
    print("Risk:", risk)
    print("Attack Type:", attack_type)
    print(" Location:", geo["country"])
    print("-" * 50)


def start_packet_monitoring():
    start_sniffing(handle_packet)


threading.Thread(target=start_packet_monitoring, daemon=True).start()