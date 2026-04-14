from fastapi import FastAPI
from app.api.routes import router
from app.api.honeypot import router as honeypot_router, blocked_ips
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
attacker_profile = {}


def is_duplicate(source):
    now = time.time()
    if source in last_event_time and now - last_event_time[source] < 2:
        return True
    last_event_time[source] = now
    return False


def update_attacker_profile(source, risk):
    if source not in attacker_profile:
        attacker_profile[source] = {
            "count": 0,
            "max_risk": 0,
            "last_seen": time.time()
        }

    attacker_profile[source]["count"] += 1
    attacker_profile[source]["max_risk"] = max(
        attacker_profile[source]["max_risk"], risk
    )
    attacker_profile[source]["last_seen"] = time.time()


def handle_packet(data):
    features = data["features"]
    protocol = data.get("protocol", "unknown")
    source = data.get("source", "unknown_device")

    if is_duplicate(source):
        return

    geo = get_geo_from_ip(source)

    action, risk, reasons, attack_type, device_status, trust_score = smart_firewall(
        features, source
    )

    # auto block high risk
    if risk >= 70 or action == "BLOCK":
        blocked_ips.add(source)

    # geo adjustments
    if geo["proxy"]:
        risk += 2
    if geo["hosting"]:
        risk += 2

    # trust-based reduction
    if trust_score > 80:
        risk -= 3

    risk = max(0, min(risk, 100))

    update_attacker_profile(source, risk)

    isolated, logs = auto_response(action, features, attack_type, source, risk)

    if source in blocked_ips:
        return

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

    print(f" {source} | {action} | Risk:{risk} | {attack_type}")


def start_packet_monitoring():
    start_sniffing(handle_packet)


threading.Thread(target=start_packet_monitoring, daemon=True).start()