from fastapi import APIRouter, Request
from datetime import datetime
from app.core.blocklist import blocked_ips

router = APIRouter()

honeypot_logs = []
trap_stats    = {}

# ── DECEPTION ESCALATION ENGINE 
# Tracks how many times each IP has hit traps
# Escalates deception before blocking — extracts maximum intel
ip_hit_counts = {}  # ip → hit count

ESCALATION_STAGES = {
    1: {
        "stage":       "INITIAL CONTACT",
        "action":      "DECEIVE",
        "description": "First contact — giving fake success to keep attacker engaged",
        "block":       False,
    },
    2: {
        "stage":       "DEEPENING TRAP",
        "action":      "ESCALATE",
        "description": "Second hit — providing deeper fake access to extract more intel",
        "block":       False,
    },
    3: {
        "stage":       "MAXIMUM DECEPTION",
        "action":      "EXTRACT",
        "description": "Third hit — feeding fake database dump for maximum intelligence",
        "block":       False,
    },
    4: {
        "stage":       "TERMINATION",
        "action":      "BLOCK",
        "description": "Full profile captured — terminating connection and blacklisting",
        "block":       True,
    },
}

# Escalating fake responses per stage
STAGE_RESPONSES = {
    "Admin Panel Probe": {
        1: {"status": "ok", "role": "viewer", "session": "active"},
        2: {"status": "ok", "role": "admin", "session": "active", "users": 142},
        3: {"status": "ok", "role": "superadmin", "db_access": True, "backup_url": "/backup"},
        4: None,  # BLOCKED
    },
    "Credential Attack": {
        1: {"token": "eyJhbGci.fake.stage1", "role": "viewer"},
        2: {"token": "eyJhbGci.fake.stage2", "role": "admin", "2fa": "disabled"},
        3: {"token": "eyJhbGci.fake.stage3", "role": "superadmin", "users": [{"email": "ceo@company.com"}, {"email": "finance@company.com"}]},
        4: None,
    },
    "Shell Access Attempt": {
        1: {"output": "Permission denied", "uid": "1000(www-data)"},
        2: {"output": "root@server:~#", "uid": "0(root)", "cwd": "/var/www"},
        3: {"output": "root@server:~#", "uid": "0(root)", "files": ["db_backup.sql", "config.env", "private.key"]},
        4: None,
    },
    "Env File Probe": {
        1: {"DB_HOST": "localhost", "DB_NAME": "app_db"},
        2: {"DB_HOST": "localhost", "DB_PASS": "fake_pass_123", "REDIS_URL": "redis://localhost"},
        3: {"DB_HOST": "localhost", "DB_PASS": "fake_pass_123", "API_KEY": "sk-fake-abc123", "JWT_SECRET": "fake_secret", "AWS_KEY": "AKIAFAKE123"},
        4: None,
    },
}

def get_escalation_response(trap_name: str, stage: int) -> dict:
    
    responses = STAGE_RESPONSES.get(trap_name, {})
    if stage in responses and responses[stage] is not None:
        return responses[stage]
    # Default escalating responses
    defaults = {
        1: {"status": "ok", "message": "Access granted"},
        2: {"status": "ok", "message": "Full access granted", "data": "loading..."},
        3: {"status": "ok", "message": "Superadmin access", "dump": "generating..."},
    }
    return defaults.get(stage, {"status": "ok"})


# ── KNOWN SCANNER SIGNATURES 
KNOWN_SCANNERS = {
    "sqlmap":     "SQLMap - SQL Injection Scanner",
    "nikto":      "Nikto - Web Vulnerability Scanner",
    "masscan":    "Masscan - Port Scanner",
    "nmap":       "Nmap - Network Scanner",
    "zgrab":      "ZGrab - Banner Grabber",
    "gobuster":   "Gobuster - Directory Brute Forcer",
    "dirbuster":  "DirBuster - Directory Brute Forcer",
    "hydra":      "Hydra - Credential Brute Forcer",
    "metasploit": "Metasploit Framework",
    "curl":       "cURL - Likely Automated",
    "python":     "Python Script - Likely Automated",
    "go-http":    "Go HTTP Client - Likely Scanner",
    "zgrab2":     "ZGrab2 - Banner Grabber",
    "nuclei":     "Nuclei - Vulnerability Scanner",
    "wfuzz":      "WFuzz - Web Fuzzer",
    "burp":       "Burp Suite - Web Proxy",
}

SKIP_HEADERS = {"cookie", "authorization", "x-api-key", "x-token"}

from typing import Optional
def detect_scanner(user_agent: str) -> Optional[str]:
    ua = user_agent.lower()
    for sig, name in KNOWN_SCANNERS.items():
        if sig in ua:
            return name
    return None

def safe_headers(headers: dict) -> dict:
    return {
        k: ("***REDACTED***" if k.lower() in SKIP_HEADERS else v)
        for k, v in headers.items()
        if k.lower() not in {"host", "content-length"}
    }

async def extract_fingerprint(request: Request) -> dict:
    user_agent = request.headers.get("user-agent", "—")
    scanner    = detect_scanner(user_agent)
    query      = dict(request.query_params)

    body = None
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            ct = request.headers.get("content-type", "")
            if "application/json" in ct:
                body = await request.json()
            elif "form" in ct:
                form = await request.form()
                body = dict(form)
            else:
                raw = await request.body()
                body = raw.decode("utf-8", errors="replace")[:500]
        except Exception:
            body = None

    credentials = None
    if isinstance(body, dict):
        user_keys = {"username", "user", "email", "login", "name"}
        pass_keys = {"password", "pass", "pwd", "secret", "token"}
        cred_user = next((body[k] for k in user_keys if k in body), None)
        cred_pass = next((body[k] for k in pass_keys if k in body), None)
        if cred_user or cred_pass:
            credentials = {
                "username": cred_user or "—",
                "password": "***" if cred_pass else "—",
            }

    return {
        "user_agent":   user_agent,
        "scanner":      scanner,
        "method":       request.method,
        "path":         str(request.url.path),
        "query_params": query if query else None,
        "headers":      safe_headers(dict(request.headers)),
        "body":         body if not credentials else "***credential attempt***",
        "credentials":  credentials,
        "referer":      request.headers.get("referer"),
        "x_forwarded":  request.headers.get("x-forwarded-for"),
        "accept_lang":  request.headers.get("accept-language"),
    }


async def _trigger_honeypot(request: Request, trap_name: str, risk: int = 85):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host

    
    ip_hit_counts[client_ip] = ip_hit_counts.get(client_ip, 0) + 1
    hit_count = ip_hit_counts[client_ip]
    stage_num = min(hit_count, 4)
    stage_info = ESCALATION_STAGES[stage_num]

    fingerprint = await extract_fingerprint(request)

    if fingerprint["scanner"]:
        risk = min(100, risk + 10)

    # Risk escalates with each hit
    escalated_risk = min(100, risk + (hit_count - 1) * 8)

    geo = {"lat": 0, "lon": 0, "country": "Unknown", "isp": "Unknown"}
    try:
        from app.core.geo import get_geo_from_ip
        geo = get_geo_from_ip(client_ip)
    except Exception:
        pass

    log = {
        "timestamp":        str(datetime.now()),
        "source":           client_ip,
        "attack_type":      trap_name,
        "risk":             escalated_risk,
        "lat":              geo["lat"],
        "lon":              geo["lon"],
        "country":          geo["country"],
        "isp":              geo["isp"],
        "is_deception":     True,
        "fingerprint":      fingerprint,
        "escalation_stage": stage_num,
        "escalation_info":  stage_info,
        "total_hits":       hit_count,
    }

    if trap_name == "Credential Attack":
        log["risk"] = min(100, escalated_risk + 40)
    elif trap_name == "Shell Access Attempt":
        log["risk"] = min(100, escalated_risk + 10)

    honeypot_logs.append(log)
    trap_stats[trap_name] = trap_stats.get(trap_name, 0) + 1

    if stage_info["block"]:
        blocked_ips.add(client_ip)
        print(f"\n  [ESCALATION] {client_ip} — Stage 4 TERMINATION — blacklisted after {hit_count} hits")
    else:
        print(f"\n  [ESCALATION] {client_ip} — Stage {stage_num}: {stage_info['stage']} — still deceiving ({hit_count} hits)")

    print(f"   Scanner : {fingerprint['scanner'] or 'Unknown'}")
    print(f"   UA      : {fingerprint['user_agent'][:80]}")
    if fingerprint["credentials"]:
        print(f"   Creds   : {fingerprint['credentials']}")

    return log, stage_num, stage_info


@router.post("/honeypot")
def capture_attack(data: dict):
    log = {
        "timestamp":    str(datetime.now()),
        "source":       data.get("source"),
        "attack_type":  data.get("attack_type"),
        "risk":         data.get("risk", 0),
        "features":     data.get("features"),
        "lat":          data.get("lat"),
        "lon":          data.get("lon"),
        "country":      data.get("country"),
        "isp":          data.get("isp"),
        "is_deception": True,
        "fingerprint":  None,
    }
    attack_type = log.get("attack_type", "")
    if attack_type == "Credential Attack":
        log["risk"] += 40
    elif attack_type == "Bot":
        log["risk"] += 30
    log["risk"] = min(log["risk"], 100)
    honeypot_logs.append(log)
    return {"status": "captured"}



@router.get("/admin")
@router.post("/admin")
async def fake_admin(request: Request):
    log, stage, info = await _trigger_honeypot(request, "Admin Panel Probe")
    return get_escalation_response("Admin Panel Probe", stage) if not info["block"] else {"error": "Not found"}

@router.get("/wp-admin")
@router.post("/wp-admin")
async def fake_wp_admin(request: Request):
    log, stage, info = await _trigger_honeypot(request, "WordPress Probe")
    return {"wp": "login", "version": "6.4.2", "access": "granted" if stage > 1 else "pending"} if not info["block"] else {"error": "Not found"}

@router.get("/login")
@router.post("/login")
async def fake_login(request: Request):
    log, stage, info = await _trigger_honeypot(request, "Credential Attack")
    return get_escalation_response("Credential Attack", stage) if not info["block"] else {"error": "Unauthorized"}

@router.get("/.env")
async def fake_env(request: Request):
    log, stage, info = await _trigger_honeypot(request, "Env File Probe", risk=90)
    return get_escalation_response("Env File Probe", stage) if not info["block"] else {"error": "Not found"}

@router.get("/config")
@router.post("/config")
async def fake_config(request: Request):
    log, stage, info = await _trigger_honeypot(request, "Config Probe", risk=80)
    return {"debug": True, "level": stage, "db": "mongodb://admin:fake@localhost"} if not info["block"] else {"error": "Not found"}

@router.get("/shell")
@router.post("/shell")
async def fake_shell(request: Request):
    log, stage, info = await _trigger_honeypot(request, "Shell Access Attempt", risk=95)
    return get_escalation_response("Shell Access Attempt", stage) if not info["block"] else {"error": "Connection refused"}

@router.get("/api/v1/users")
async def fake_users(request: Request):
    log, stage, info = await _trigger_honeypot(request, "Data Exfiltration Probe", risk=88)
    if info["block"]: return {"error": "Unauthorized"}
    count = [2, 5, 142][min(stage-1, 2)]
    return {"users": [{"id": i+1, "email": f"user{i+1}@company.com"} for i in range(count)]}

@router.get("/phpmyadmin")
@router.post("/phpmyadmin")
async def fake_phpmyadmin(request: Request):
    log, stage, info = await _trigger_honeypot(request, "phpMyAdmin Probe", risk=85)
    return {"pma_version": "5.2.1", "tables": stage * 12, "server": "MySQL 8.0"} if not info["block"] else {"error": "Not found"}

@router.get("/backup")
@router.get("/backup.zip")
@router.get("/backup.sql")
async def fake_backup(request: Request):
    log, stage, info = await _trigger_honeypot(request, "Backup File Probe", risk=88)
    return {"file": f"backup_stage{stage}.sql", "size": f"{stage * 0.8:.1f}GB", "status": "ready"} if not info["block"] else {"error": "Not found"}

@router.get("/honeypot/escalation")
def get_escalation_status():
    """Returns current escalation stage per IP."""
    return {
        "escalation": [
            {
                "ip":        ip,
                "hits":      count,
                "stage":     min(count, 4),
                "stage_info": ESCALATION_STAGES[min(count, 4)],
                "blocked":   ip in blocked_ips,
            }
            for ip, count in ip_hit_counts.items()
        ]
    }


@router.get("/honeypot/logs")
def get_logs():
    profiles = {}

    for log in honeypot_logs:
        ip = log.get("source", "unknown")
        if ip not in profiles:
            profiles[ip] = {"source": ip, "count": 0, "max_risk": 0, "total_risk": 0, "last_seen": log["timestamp"], "attack_types": set(), "scanners": set()}

        profiles[ip]["count"]      += 1
        profiles[ip]["max_risk"]    = max(profiles[ip]["max_risk"], log.get("risk", 0))
        profiles[ip]["total_risk"] += log.get("risk", 0)
        profiles[ip]["last_seen"]   = log["timestamp"]

        if log.get("attack_type"):
            profiles[ip]["attack_types"].add(log["attack_type"])

        fp = log.get("fingerprint") or {}
        if fp.get("scanner"):
            profiles[ip]["scanners"].add(fp["scanner"])

    for ip in profiles:
        p            = profiles[ip]
        avg_risk     = p["total_risk"] / p["count"]
        threat_score = (p["count"] * 5) + avg_risk

        if threat_score >= 100:  level = "CRITICAL"
        elif threat_score >= 60: level = "HIGH"
        elif threat_score >= 30: level = "MEDIUM"
        else:                    level = "LOW"

        try:
            last_time   = datetime.strptime(p["last_seen"], "%Y-%m-%d %H:%M:%S.%f")
            seconds_ago = (datetime.now() - last_time).total_seconds()
            is_active   = seconds_ago < 10
        except Exception:
            is_active = False

        p["avg_risk"]      = round(avg_risk, 2)
        p["threat_score"]  = round(threat_score, 2)
        p["level"]         = level
        p["is_active"]     = is_active
        p["is_suspicious"] = p["threat_score"] >= 60
        p["attack_types"]  = list(p["attack_types"])
        p["scanners"]      = list(p["scanners"])

    profiles = {ip: p for ip, p in profiles.items() if ip not in blocked_ips}
    sessions = build_sessions(honeypot_logs[-50:])
    sessions = [s for s in sessions if s["source"] not in blocked_ips]

    return {
        "logs":       honeypot_logs[-50:],
        "profiles":   list(profiles.values()),
        "sessions":   sessions,
        "trap_stats": trap_stats,
    }

def build_sessions(logs):
    sessions = {}
    for log in logs:
        ip = log.get("source", "unknown")
        if ip not in sessions:
            sessions[ip] = {"source": ip, "count": 0, "start": log["timestamp"], "end": log["timestamp"], "total_risk": 0, "attack_types": set()}
        sessions[ip]["count"]      += 1
        sessions[ip]["end"]         = log["timestamp"]
        sessions[ip]["total_risk"] += log.get("risk", 0)
        if log.get("attack_type"):
            sessions[ip]["attack_types"].add(log["attack_type"])

    result = []
    for s in sessions.values():
        avg_risk = s["total_risk"] / s["count"]
        pattern  = "BURST ATTACK" if s["count"] > 10 else "REPEATED" if s["count"] > 5 else "LOW"
        result.append({"source": s["source"], "count": s["count"], "avg_risk": round(avg_risk, 2), "pattern": pattern, "start": s["start"], "end": s["end"], "attack_types": list(s["attack_types"])})
    return result


@router.post("/honeypot/block")
def block_ip(data: dict):
    ip = data.get("ip")
    if ip:
        blocked_ips.add(ip)
        print(f" BLOCKED IP: {ip}")
    return {"status": "blocked"}

@router.get("/honeypot/blacklist")
def get_blacklist():
    return {"blocked_ips": list(blocked_ips)}

@router.get("/honeypot/trap-stats")
def get_trap_stats():
    return {"traps": [{"name": n, "hits": h} for n, h in sorted(trap_stats.items(), key=lambda x: -x[1])]}

@router.get("/honeypot/fingerprints")
def get_fingerprints():
    return {"fingerprints": [{"timestamp": l["timestamp"], "source": l["source"], "attack_type": l["attack_type"], "risk": l["risk"], "country": l.get("country", "Unknown"), "fingerprint": l.get("fingerprint")} for l in honeypot_logs if l.get("fingerprint")][-30:]}
