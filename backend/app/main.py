from fastapi import FastAPI
from app.api.routes import router
from app.api.honeypot import router as honeypot_router
from app.core.model_loader import load_model
from app.core.packet_engine import start_sniffing
from app.core.firewall_engine import smart_firewall
import threading

app = FastAPI(title="IntelliWall NGFW")

load_model()


app.include_router(router)
app.include_router(honeypot_router)


@app.get("/")
def root():
    return {"message": "IntelliWall API running"}

def handle_packet(data):
    features = data["features"]
    protocol = data.get("protocol", "unknown")
    source = data.get("source", "unknown_device")

    print("\n📡 Incoming Packet")
    print("Source:", source)
    print("Protocol:", protocol)
    print("Features:", features)

    action, risk, reasons, attack_type, device_status, trust_score = smart_firewall(
        features, source
    )

    print(" Decision:", action)
    print(" Risk:", risk)
    print(" Attack Type:", attack_type)
    print("-" * 40)

def start_packet_monitoring():
    start_sniffing(handle_packet)


thread = threading.Thread(target=start_packet_monitoring, daemon=True)
thread.start()