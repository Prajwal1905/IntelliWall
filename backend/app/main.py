from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import List
from app.api.routes import router
from app.core.model_loader import load_model
from app.core.firewall_engine import smart_firewall
from fastapi.middleware.cors import CORSMiddleware
from app.core.packet_engine import start_sniffing
from app.core.response_engine import auto_response
from app.api.honeypot import router as honeypot_router
from app.api.auth import router as auth_router
from app.api.report import report_router
import threading
import time
import requests as req
from app.db.crud import save_alert
from app.core.geo import get_geo_from_ip
from app.core.config import MODE
from app.api.honeypot import blocked_ips, honeypot_logs
from fastapi import APIRouter
from datetime import datetime
import random
import warnings
warnings.filterwarnings("ignore")

app = FastAPI(title="IntelliWall NGFW")

load_model()

app.include_router(router)
app.include_router(honeypot_router)
app.include_router(auth_router, prefix="/auth")
app.include_router(report_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        print(f"  {T.CYAN}[WS] Client connected — {len(self.active)} active{T.RESET}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

@app.websocket("/ws/threats")
async def threat_websocket(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

class T:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

def action_color(action):
    a = (action or "").upper()
    if a == "BLOCK":     return T.RED
    if a == "HONEYPOT":  return T.MAGENTA
    if a == "CHALLENGE": return T.YELLOW
    return T.GREEN

def risk_color(risk):
    if risk >= 70: return T.RED
    if risk >= 40: return T.YELLOW
    return T.GREEN

def log_event(action, source, risk, attack_type, country, extra=""):
    ac  = action_color(action)
    rc  = risk_color(risk)
    tag = f"{ac}{T.BOLD}[{action:<10}]{T.RESET}"
    ip  = f"{T.WHITE}{source:<18}{T.RESET}"
    r   = f"risk={rc}{str(risk):<3}{T.RESET}"
    att = f"{T.DIM}{(attack_type or 'Unknown'):<28}{T.RESET}"
    geo = f"{T.CYAN}{country or 'Unknown'}{T.RESET}"
    ex  = f"  {T.DIM}{extra}{T.RESET}" if extra else ""
    print(f"  {tag} {ip} {r}  {att} {geo}{ex}")

def print_banner():
    print(f"\n{T.CYAN}{'━'*65}{T.RESET}")
    print(f"{T.BOLD}{T.WHITE}   INTELLIWALL NGFW  ─  LIVE THREAT FEED{T.RESET}")
    print(f"{T.CYAN}{'━'*65}{T.RESET}\n")
    print(f"  {T.DIM}{'ACTION':<12} {'SOURCE IP':<18} {'RISK':<9} {'ATTACK TYPE':<28} COUNTRY{T.RESET}")
    print(f"  {T.DIM}{'─'*62}{T.RESET}\n")

def print_section(title):
    print(f"\n  {T.DIM}── {title} {'─' * max(0, 40 - len(title))}{T.RESET}")


last_event_time  = {}
attacker_profile = {}

def is_duplicate(source):
    now = time.time()
    if source in last_event_time:
        if now - last_event_time[source] < 2:
            return True
    last_event_time[source] = now
    return False

def update_attacker_profile(source, risk):
    if source not in attacker_profile:
        attacker_profile[source] = {"count": 0, "max_risk": 0, "last_seen": time.time()}
    attacker_profile[source]["count"]   += 1
    attacker_profile[source]["max_risk"] = max(attacker_profile[source]["max_risk"], risk)
    attacker_profile[source]["last_seen"] = time.time()


def handle_packet(data):
    source = data.get("source", "")

    if MODE == "DEMO" and ":" in source:
        return

    protocol = data.get("protocol", "")
    features = data["features"].copy()

    features[0] = min(features[0], 1500)
    features[2] = min(features[2], 8000)
    features[6] = max(features[6], 0.05)

    if is_duplicate(source):
        return

    geo = get_geo_from_ip(source)
    action, risk, reasons, attack_type, device_status, trust_score = smart_firewall(features, source, geo)
    action_clean = action.strip().upper()

    if risk >= 70 or action_clean == "BLOCK":
        blocked_ips.add(source)

    geo = get_geo_from_ip(source)

    if geo["proxy"]:   risk += 2
    if geo["hosting"]: risk += 2
    if not geo["proxy"] and not geo["hosting"]: risk -= 5
    if trust_score > 80:   risk -= 5
    elif trust_score > 60: risk -= 3

    if action == "ALLOW":
        if trust_score > 80:   risk -= 2
        elif trust_score > 60: risk -= 3
        if not geo["proxy"] and not geo["hosting"]: risk -= 2

    risk = max(0, min(risk, 100))
    if risk > 70: risk = int(risk * 0.9)
    if risk < 30: risk = int(risk * 0.8)

    update_attacker_profile(source, risk)
    profile      = attacker_profile.get(source, {})
    repeat_count = profile.get("count", 0)

    if action == "ALLOW" and trust_score > 90 and not geo["proxy"] and not geo["hosting"]:
        action = "ALLOW"

    suspicious_signal = (
        features[0] > 1000 or
        features[2] > 7000 or
        features[6] < 0.1  or
        features[8] == 1
    )

    if action != "BLOCK" and risk >= 50:
        if repeat_count >= 5 and suspicious_signal:
            action = "BLOCK"
        elif 3 <= repeat_count < 5 and suspicious_signal:
            action = "HONEYPOT"

    isolated, logs = auto_response(action, risk, features, attack_type, source, geo)

    if source in blocked_ips and action_clean not in ("BLOCK", "HONEYPOT"):
        return

    save_alert({
        "protocol":    protocol,
        "action":      action,
        "risk":        risk,
        "attack_type": attack_type,
        "trust_score": trust_score,
        "features":    features,
        "source":      source,
        "lat":         geo["lat"],
        "lon":         geo["lon"],
        "country":     geo["country"],
        "isp":         geo["isp"],
        "proxy":       geo["proxy"],
        "hosting":     geo["hosting"],
    })

    extra = ""
    if action == "BLOCK":      extra = " auto-blocked"
    elif action == "HONEYPOT": extra = " trap triggered"
    elif geo["proxy"]:         extra = "proxy detected"
    elif geo["hosting"]:       extra = "hosting network"

    log_event(action, source, risk, attack_type, geo["country"], extra)

    # ── FEDERATED THREAT SHARING 
    if action == "BLOCK" and risk >= 70:
        share_threat_to_nodes(source, risk, attack_type, geo.get("country", "Unknown"))

    # ── ATTACK PATTERN CORRELATION 
    if action in ("BLOCK", "HONEYPOT") and risk >= 40:
        campaign = correlate_attacks(source, risk, attack_type, geo.get("country", "Unknown"))
        if campaign:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(manager.broadcast({
                        "type":     "campaign",
                        "campaign": campaign,
                    }))
            except Exception:
                pass

    # ── BROADCAST TO WEBSOCKET CLIENTS 
    if action in ("BLOCK", "HONEYPOT") and risk >= 50:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(manager.broadcast({
                    "type":        "threat",
                    "source":      source,
                    "action":      action,
                    "risk":        risk,
                    "attack_type": attack_type,
                    "country":     geo.get("country", "Unknown"),
                    "isp":         geo.get("isp", "Unknown"),
                    "timestamp":   str(datetime.now()),
                }))
        except Exception:
            pass


# ─── PACKET MONITORING
def start_packet_monitoring():
    start_sniffing(handle_packet)

thread = threading.Thread(target=start_packet_monitoring, daemon=True)
thread.start()


# ─── SIMULATION DATA 
SIMULATION_PACKETS = [
    {"features": [200,  20,  500,   30,  40,  10,  0.95,  0.2,   0, 0], "protocol": "HTTP",  "source": "8.8.8.8"},
    {"features": [180,  18,  480,   28,  38,  9,   0.93,  0.2,   0, 0], "protocol": "HTTPS", "source": "1.1.1.1"},
    {"features": [150,  15,  400,   25,  35,  8,   0.91,  0.2,   0, 0], "protocol": "HTTP",  "source": "185.60.216.35"},
    {"features": [1200, 150, 7000,  250, 350, 100, 0.08,  0.02,  1, 0], "protocol": "TCP",   "source": "45.67.89.10"},
    {"features": [1100, 140, 6500,  230, 330, 90,  0.1,   0.03,  1, 0], "protocol": "TCP",   "source": "91.108.4.1"},
    {"features": [1000, 130, 5500,  220, 320, 90,  0.08,  0.02,  1, 0], "protocol": "TCP",   "source": "103.21.244.1"},
    {"features": [900,  120, 5000,  210, 310, 85,  0.09,  0.02,  1, 0], "protocol": "HTTP",  "source": "196.12.55.100"},
    {"features": [950,  125, 5200,  215, 315, 87,  0.09,  0.02,  1, 0], "protocol": "TCP",   "source": "41.203.64.1"},
    {"features": [1500, 200, 8000,  400, 500, 150, 0.05,  0.005, 1, 1], "protocol": "UDP",   "source": "5.188.206.14"},
    {"features": [1400, 180, 7500,  350, 450, 130, 0.04,  0.006, 1, 1], "protocol": "TCP",   "source": "185.220.101.1"},
    {"features": [1600, 210, 8500,  420, 520, 160, 0.03,  0.004, 1, 1], "protocol": "UDP",   "source": "222.186.42.1"},
    {"features": [1450, 190, 7800,  380, 480, 140, 0.04,  0.005, 1, 1], "protocol": "TCP",   "source": "218.92.0.1"},
    {"features": [1350, 170, 7200,  340, 440, 120, 0.05,  0.007, 1, 1], "protocol": "UDP",   "source": "31.184.192.1"},
    {"features": [2500, 200, 15000, 400, 500, 150, 0.01,  0.005, 1, 1], "protocol": "UDP",   "source": "77.83.36.1"},
    {"features": [2600, 210, 16000, 420, 520, 160, 0.01,  0.005, 1, 1], "protocol": "UDP",   "source": "194.165.16.1"},
    {"features": [2400, 190, 14000, 380, 480, 140, 0.02,  0.008, 1, 1], "protocol": "TCP",   "source": "45.142.212.1"},
    {"features": [2800, 220, 18000, 450, 550, 180, 0.005, 0.002, 1, 1], "protocol": "UDP",   "source": "176.97.210.1"},
]

HONEYPOT_PACKETS = [
    {"source": "185.220.101.45", "attack_type": "Admin Panel Probe",       "risk": 85, "country": "Germany",      "lat": 51.1657, "lon": 10.4515,  "isp": "Tor Exit Node"},
    {"source": "91.108.56.12",   "attack_type": "Credential Attack",       "risk": 95, "country": "Russia",       "lat": 55.7558, "lon": 37.6173,  "isp": "Rostelecom"},
    {"source": "103.35.74.1",    "attack_type": "Env File Probe",          "risk": 90, "country": "China",        "lat": 39.9042, "lon": 116.4074, "isp": "Chinanet"},
    {"source": "41.203.64.100",  "attack_type": "WordPress Probe",         "risk": 80, "country": "Nigeria",      "lat": 6.5244,  "lon": 3.3792,   "isp": "Airtel Nigeria"},
    {"source": "5.188.206.200",  "attack_type": "Shell Access Attempt",    "risk": 98, "country": "Russia",       "lat": 59.9311, "lon": 30.3609,  "isp": "Petersburg Internet"},
    {"source": "196.12.55.200",  "attack_type": "Data Exfiltration Probe", "risk": 88, "country": "South Africa", "lat": -30.5595,"lon": 22.9375,  "isp": "Telkom SA"},
    {"source": "194.165.16.100", "attack_type": "Config Probe",            "risk": 82, "country": "Iran",         "lat": 35.6892, "lon": 51.3890,  "isp": "Irancell"},
    {"source": "45.142.212.100", "attack_type": "Backup File Probe",       "risk": 87, "country": "Netherlands",  "lat": 52.3676, "lon": 4.9041,   "isp": "LeaseWeb"},
    {"source": "218.92.0.200",   "attack_type": "phpMyAdmin Probe",        "risk": 85, "country": "China",        "lat": 31.2304, "lon": 121.4737, "isp": "China Telecom"},
    {"source": "77.83.36.100",   "attack_type": "Admin Panel Probe",       "risk": 86, "country": "Netherlands",  "lat": 52.1326, "lon": 5.2913,   "isp": "Serverius"},
]

TRAP_HITS = [
    {"path": "/admin",       "ua": "sqlmap/1.7.8#stable (https://sqlmap.org)",     "ip": "185.220.101.45"},
    {"path": "/login",       "ua": "python-requests/2.28.0",                        "ip": "91.108.56.12"},
    {"path": "/.env",        "ua": "Go-http-client/1.1",                            "ip": "103.35.74.1"},
    {"path": "/shell",       "ua": "nikto/2.1.6",                                   "ip": "5.188.206.200"},
    {"path": "/wp-admin",    "ua": "Mozilla/5.0 zgrab/0.x",                         "ip": "41.203.64.100"},
    {"path": "/phpmyadmin",  "ua": "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "ip": "194.165.16.100"},
    {"path": "/config",      "ua": "curl/7.68.0",                                   "ip": "77.83.36.100"},
    {"path": "/backup",      "ua": "nuclei/2.9.1 (projectdiscovery.io)",            "ip": "218.92.0.200"},
    {"path": "/api/v1/users","ua": "python-httpx/0.23.0",                           "ip": "196.12.55.200"},
]

def run_simulation():
    time.sleep(5)
    print_banner()

    round_num = 0
    while True:
        round_num += 1
        print_section(f"Simulation Round {round_num}")

        # ── Regular packet simulation ──
        subset = random.sample(SIMULATION_PACKETS, k=min(6, len(SIMULATION_PACKETS)))
        for pkt in subset:
            handle_packet(pkt)
            time.sleep(2)

        if round_num % 2 == 0:
            print_section("Trap Endpoint Hits")
            trap_subset = random.sample(TRAP_HITS, k=min(3, len(TRAP_HITS)))
            for trap in trap_subset:
                try:
                    req.get(
                        f"http://127.0.0.1:8000{trap['path']}",
                        headers={
                            "User-Agent":      trap["ua"],
                            "X-Forwarded-For": trap["ip"],
                        },
                        timeout=2
                    )
                    print(f"  {T.MAGENTA}{T.BOLD}[TRAP HIT  ]{T.RESET} {T.WHITE}{trap['path']:<20}{T.RESET} {T.DIM}from {trap['ip']:<18} via {trap['ua'][:35]}{T.RESET}")
                except Exception as e:
                    pass
                time.sleep(1)

        if round_num % 3 == 0:
            print_section("Honeypot Events")
            hp_subset = random.sample(HONEYPOT_PACKETS, k=min(3, len(HONEYPOT_PACKETS)))
            for hp in hp_subset:
                log = {
                    "timestamp":    str(datetime.now()),
                    "source":       hp["source"],
                    "attack_type":  hp["attack_type"],
                    "risk":         hp["risk"],
                    "lat":          hp["lat"],
                    "lon":          hp["lon"],
                    "country":      hp["country"],
                    "isp":          hp["isp"],
                    "is_deception": True,
                    "fingerprint":  None,
                }
                honeypot_logs.append(log)
                rc = risk_color(hp["risk"])
                print(f"  {T.MAGENTA}{T.BOLD}[HONEYPOT  ]{T.RESET} {T.WHITE}{hp['source']:<18}{T.RESET} risk={rc}{hp['risk']:<3}{T.RESET}  {T.DIM}{hp['attack_type']:<28}{T.RESET} {T.CYAN}{hp['country']}{T.RESET}")
                time.sleep(1)

        time.sleep(15)


sim_thread = threading.Thread(target=run_simulation, daemon=True)
sim_thread.start()

demo_router = APIRouter()

DEMO_SCENARIO = [
    {"features": [800,  100, 4000,  200, 300, 80,  0.12,  0.03,  1, 0], "protocol": "TCP",  "source": "91.108.56.12",   "label": "Port Scan"},
    {"features": [900,  110, 4500,  210, 310, 85,  0.10,  0.02,  1, 0], "protocol": "TCP",  "source": "103.35.74.1",    "label": "Service Probe"},
    {"features": [1300, 160, 7200,  260, 360, 110, 0.07,  0.02,  1, 1], "protocol": "HTTP", "source": "5.188.206.200",  "label": "Exploit Attempt"},
    {"features": [1400, 175, 7600,  280, 380, 120, 0.06,  0.015, 1, 1], "protocol": "TCP",  "source": "185.220.101.45", "label": "Credential Brute Force"},
    {"features": [1500, 190, 8000,  350, 450, 140, 0.05,  0.01,  1, 1], "protocol": "TCP",  "source": "194.165.16.100", "label": "Honeypot Trigger"},
    {"features": [2500, 220, 15000, 420, 520, 160, 0.01,  0.005, 1, 1], "protocol": "UDP",  "source": "77.83.36.100",   "label": "DDoS Burst"},
    {"features": [2800, 240, 18000, 460, 560, 180, 0.005, 0.002, 1, 1], "protocol": "UDP",  "source": "45.142.212.100", "label": "DDoS Escalation"},
]

@demo_router.post("/demo/attack")
def trigger_demo_attack():
    def run_scenario():
        print(f"\n  {T.BOLD}{T.RED}{'━'*55}{T.RESET}")
        print(f"  {T.BOLD}{T.WHITE}   DEMO ATTACK SCENARIO — STARTING{T.RESET}")
        print(f"  {T.BOLD}{T.RED}{'━'*55}{T.RESET}\n")

        for stage in DEMO_SCENARIO:
            label = stage.get("label", "")
            pkt   = {k: v for k, v in stage.items() if k != "label"}
            print(f"  {T.YELLOW} Stage: {label:<30}{T.RESET} from {T.CYAN}{pkt['source']}{T.RESET}")
            handle_packet(pkt)
            time.sleep(2)

        print(f"\n  {T.BOLD}{T.GREEN}{'━'*55}{T.RESET}")
        print(f"  {T.BOLD}{T.GREEN}   DEMO COMPLETE — ALL THREATS NEUTRALIZED{T.RESET}")
        print(f"  {T.BOLD}{T.GREEN}{'━'*55}{T.RESET}\n")

    t = threading.Thread(target=run_scenario, daemon=True)
    t.start()
    return {"status": "started", "stages": len(DEMO_SCENARIO)}


@demo_router.post("/demo/reset")
def reset_demo():
    from app.api.honeypot import honeypot_logs, trap_stats
    honeypot_logs.clear()
    trap_stats.clear()
    blocked_ips._data.clear()
    last_event_time.clear()
    attacker_profile.clear()
    print(f"\n  {T.CYAN}[RESET] All data cleared — ready for fresh demo{T.RESET}\n")
    return {"status": "reset"}


app.include_router(demo_router)
#zero trust score enfpoint
zero_trust_router = APIRouter()

@zero_trust_router.get("/trust-score/{ip}")
def get_trust_score(ip: str):
    from app.core.firewall_engine import device_trust_score, device_risk_memory
    from app.core.geo import get_geo_from_ip

    geo = get_geo_from_ip(ip)

    trust  = device_trust_score.get(ip, 100)
    memory = device_risk_memory.get(ip, 0)

    # Calculate each factor contribution
    factors = []
    total_deduction = 0

    # Geo risk
    country = geo.get("country", "")
    HIGH_RISK_COUNTRIES = ["Russia","China","Iran","Ukraine","Netherlands","Germany","Nigeria","North Korea"]
    if country in HIGH_RISK_COUNTRIES:
        deduct = -20
        factors.append({"factor": "Geo Risk", "value": deduct, "reason": f"High-risk country: {country}"})
        total_deduction += abs(deduct)

    # Proxy
    if geo.get("proxy"):
        deduct = -15
        factors.append({"factor": "Proxy Detected", "value": deduct, "reason": "VPN/Proxy masking real location"})
        total_deduction += abs(deduct)

    # Hosting
    if geo.get("hosting"):
        deduct = -10
        factors.append({"factor": "Hosting Network", "value": deduct, "reason": "VPS/Cloud provider — not residential"})
        total_deduction += abs(deduct)

    # Trust score decay
    if trust < 30:
        deduct = -25
        factors.append({"factor": "Trust Depleted", "value": deduct, "reason": f"Trust score critically low: {round(trust, 1)}"})
        total_deduction += abs(deduct)
    elif trust < 60:
        deduct = -15
        factors.append({"factor": "Trust Degraded", "value": deduct, "reason": f"Trust score below threshold: {round(trust, 1)}"})
        total_deduction += abs(deduct)

    # Repeat offender
    if memory > 150:
        deduct = -25
        factors.append({"factor": "Repeat Offender", "value": deduct, "reason": f"High attack memory: {memory}"})
        total_deduction += abs(deduct)
    elif memory > 80:
        deduct = -15
        factors.append({"factor": "Suspicious History", "value": deduct, "reason": f"Previous suspicious activity: {memory}"})
        total_deduction += abs(deduct)
    elif memory > 0:
        deduct = -5
        factors.append({"factor": "Minor History", "value": deduct, "reason": f"Some prior activity: {memory}"})
        total_deduction += abs(deduct)

    # Blacklisted
    if ip in blocked_ips:
        deduct = -30
        factors.append({"factor": "Blacklisted", "value": deduct, "reason": "IP is on active blocklist"})
        total_deduction += abs(deduct)

    # IPv6 bonus
    if ":" in ip:
        factors.append({"factor": "IPv6 Address", "value": 5, "reason": "IPv6 — lower attack surface"})

    # Final score
    final_score = max(0, 100 - total_deduction)

    if final_score >= 80:   verdict = "TRUSTED"
    elif final_score >= 60: verdict = "MONITOR"
    elif final_score >= 30: verdict = "SUSPICIOUS"
    else:                   verdict = "DENY"

    return {
        "ip":           ip,
        "trust_score":  round(trust, 1),
        "final_score":  final_score,
        "verdict":      verdict,
        "factors":      factors,
        "geo":          {"country": country, "isp": geo.get("isp", "Unknown")},
        "memory":       memory,
        "blacklisted":  ip in blocked_ips,
    }

app.include_router(zero_trust_router)

# ─── ATTACK PATTERN CORRELATION ENGINE 
correlation_router = APIRouter()

# Store recent attack events for correlation
recent_attacks = []  # list of {ip, time, country, risk, attack_type}
detected_campaigns = []  # list of detected coordinated campaigns

CORRELATION_WINDOW = 60  # seconds — attacks within this window are correlated
MIN_CAMPAIGN_SIZE  = 2  # minimum IPs to flag as coordinated

def correlate_attacks(source, risk, attack_type, country):
    """Called on every BLOCK/HONEYPOT — checks for coordinated attack patterns."""
    now = time.time()

    # Add to recent attacks
    recent_attacks.append({
        "ip":          source,
        "time":        now,
        "country":     country,
        "risk":        risk,
        "attack_type": attack_type,
        "timestamp":   str(datetime.now()),
    })

    # Keep only last 5 minutes of attacks
    recent_attacks[:] = [a for a in recent_attacks if now - a["time"] < 300]

    # Find attacks within correlation window
    window_attacks = [a for a in recent_attacks if now - a["time"] < CORRELATION_WINDOW]

    if len(window_attacks) < MIN_CAMPAIGN_SIZE:
        return None

    # Group by country
    from collections import Counter
    country_groups = {}
    for a in window_attacks:
        c = a["country"] or "Unknown"
        if c not in country_groups:
            country_groups[c] = []
        country_groups[c].append(a)

    # Check for coordinated campaign
    for country, attacks in country_groups.items():
        unique_ips = list({a["ip"] for a in attacks})
        if len(unique_ips) >= MIN_CAMPAIGN_SIZE:
            # Check if this campaign already detected recently
            recent_campaigns = [c for c in detected_campaigns
                              if now - c["detected_at"] < 60
                              and c["country"] == country]
            if recent_campaigns:
                continue

            # Determine campaign type
            attack_types = [a["attack_type"] for a in attacks]
            if any("DDoS" in t for t in attack_types):
                campaign_type = "DISTRIBUTED DDOS"
                threat_level  = "CRITICAL"
            elif any("Scan" in t for t in attack_types):
                campaign_type = "COORDINATED SCAN"
                threat_level  = "HIGH"
            elif any("Credential" in t or "Brute" in t for t in attack_types):
                campaign_type = "CREDENTIAL STUFFING"
                threat_level  = "HIGH"
            else:
                campaign_type = "COORDINATED ATTACK"
                threat_level  = "HIGH"

            avg_risk = sum(a["risk"] for a in attacks) / len(attacks)
            campaign = {
                "id":           f"campaign_{int(now)}",
                "detected_at":  now,
                "timestamp":    str(datetime.now()),
                "country":      country,
                "campaign_type":campaign_type,
                "threat_level": threat_level,
                "ips":          unique_ips[:10],
                "ip_count":     len(unique_ips),
                "avg_risk":     round(avg_risk, 1),
                "attack_types": list(set(attack_types)),
                "confidence":   min(95, 60 + len(unique_ips) * 5),
                "window_secs":  CORRELATION_WINDOW,
            }
            detected_campaigns.append(campaign)
            if len(detected_campaigns) > 20:
                detected_campaigns.pop(0)

            print(f"\n  {T.RED}{T.BOLD}[CAMPAIGN DETECTED] {campaign_type} from {country}{T.RESET}")
            print(f"  {T.DIM}{len(unique_ips)} IPs coordinating — confidence {campaign['confidence']}%{T.RESET}")
            return campaign

    return None

@correlation_router.get("/correlation/campaigns")
def get_campaigns():
    now = time.time()
    active = [c for c in detected_campaigns if now - c["detected_at"] < 300]
    return {
        "campaigns":       list(reversed(active)),
        "total_detected":  len(detected_campaigns),
        "active_count":    len(active),
        "recent_attacks":  len([a for a in recent_attacks if now - a["time"] < 60]),
    }

app.include_router(correlation_router)

# ─── FEDERATED THREAT SHARING
federated_router = APIRouter()

# Simulated federated nodes
FEDERATED_NODES = [
    {"id": "node_mumbai",    "name": "Node Mumbai",    "location": "Mumbai, IN",    "lat": 19.076, "lon": 72.877},
    {"id": "node_delhi",     "name": "Node Delhi",     "location": "Delhi, IN",     "lat": 28.613, "lon": 77.209},
    {"id": "node_bangalore", "name": "Node Bangalore", "location": "Bangalore, IN", "lat": 12.971, "lon": 77.594},
    {"id": "node_singapore", "name": "Node Singapore", "location": "Singapore, SG", "lat": 1.352,  "lon": 103.820},
    {"id": "node_london",    "name": "Node London",    "location": "London, UK",    "lat": 51.507, "lon": -0.128},
]

# Shared threat intel log
shared_threats = []
node_stats     = {n["id"]: {"threats_received": 0, "threats_shared": 0, "status": "online"} for n in FEDERATED_NODES}

def share_threat_to_nodes(source, risk, attack_type, country):
    
    import random as _r
    
    receiving = _r.sample(FEDERATED_NODES[1:], k=min(3, len(FEDERATED_NODES)-1))
    entry = {
        "timestamp":    str(datetime.now()),
        "source_ip":    source,
        "risk":         risk,
        "attack_type":  attack_type,
        "country":      country,
        "shared_from":  FEDERATED_NODES[0]["name"],
        "shared_to":    [n["name"] for n in receiving],
        "pre_blocked":  len(receiving),
    }
    shared_threats.append(entry)
    if len(shared_threats) > 50:
        shared_threats.pop(0)

    # Update stats
    node_stats[FEDERATED_NODES[0]["id"]]["threats_shared"] += 1
    for n in receiving:
        node_stats[n["id"]]["threats_received"] += 1
        # Pre-block on receiving nodes too
        blocked_ips.add(source)

    print(f"  {T.CYAN}[FEDERATED] {source} shared to {len(receiving)} nodes — pre-blocked globally{T.RESET}")
    return entry

@federated_router.get("/federated/nodes")
def get_federated_nodes():
    nodes = []
    for n in FEDERATED_NODES:
        stats = node_stats.get(n["id"], {})
        nodes.append({
            **n,
            "status":            stats.get("status", "online"),
            "threats_shared":    stats.get("threats_shared", 0),
            "threats_received":  stats.get("threats_received", 0),
        })
    return {
        "nodes":          nodes,
        "shared_threats": shared_threats[-10:],
        "total_shared":   len(shared_threats),
        "protected_ips":  len(set(t["source_ip"] for t in shared_threats)),
    }

@federated_router.get("/federated/shared")
def get_shared_threats():
    return {"shared_threats": shared_threats[-20:]}

app.include_router(federated_router)
