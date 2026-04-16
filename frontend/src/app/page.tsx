"use client";

import { useEffect, useState } from "react";
import RiskMeter from "../components/RiskMeter";
import AlertsPanel from "../components/AlertsPanel";
import MetricsBar from "../components/MetricsBar";
import NetworkGraph from "../components/NetworkGraph";
import ThreatTimeline from "../components/ThreatTimeline";
import TopAttackers from "../components/TopAttackers";
import dynamic from "next/dynamic";
import FederatedPanel from "../components/FederatedPanel";

const GeoMap = dynamic(() => import("../components/GeoMap"), { ssr: false });

import HoneypotPanel from "../components/HoneypotPanel";
import { getAlerts, getRisk } from "../lib/api";

type Alert = {
  protocol: string;
  action: string;
  risk: number;
  attack_type: string;
  trust_score: number;
  timestamp: string;
};

const S = {
  page: {
    width: "100%",
    minHeight: "100vh",
    background: "#020617",
    display: "flex",
    justifyContent: "center",
  } as React.CSSProperties,

  inner: {
    width: "100%",
    maxWidth: "1400px",
    padding: "24px",
    display: "flex",
    flexDirection: "column" as const,
    gap: "20px",
  } as React.CSSProperties,

  card: {
    background: "#0a1628",
    border: "1px solid #1e293b",
    borderRadius: "14px",
    overflow: "hidden",
  } as React.CSSProperties,

  cardHeader: {
    padding: "14px 20px",
    borderBottom: "1px solid #1e293b",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
  } as React.CSSProperties,

  cardTitle: {
    fontSize: "13px",
    fontWeight: 600,
    color: "#94a3b8",
    textTransform: "uppercase" as const,
    letterSpacing: "0.08em",
    margin: 0,
  } as React.CSSProperties,

  cardBody: {
    padding: "16px",
  } as React.CSSProperties,
};

export default function Home() {
  const [alerts, setAlerts]                 = useState<Alert[]>([]);
  const [systemRisk, setSystemRisk]         = useState(5);
  const [checkingAuth, setCheckingAuth]     = useState(true);
  const [blacklistCount, setBlacklistCount] = useState(0);
  const [demoRunning, setDemoRunning]       = useState(false);
  const [notifications, setNotifications]   = useState<any[]>([]);
  const [campaigns, setCampaigns]           = useState<any[]>([]);

  // ── AUTH CHECK ──
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }
    const checkBackend = async () => {
      try {
        await fetch("http://127.0.0.1:8000/risk");
        setCheckingAuth(false);
      } catch {
        localStorage.removeItem("token");
        window.location.href = "/login";
      }
    };
    checkBackend();
  }, []);

  // ── RISK ──
  useEffect(() => {
    const fetchRisk = async () => {
      try {
        const risk = await getRisk();
        setSystemRisk(risk);
      } catch (err) {
        console.error("Risk fetch failed", err);
      }
    };
    fetchRisk();
    const interval = setInterval(fetchRisk, 3000);
    return () => clearInterval(interval);
  }, []);

  // ── ALERTS ──
  useEffect(() => {
    const fetchData = async () => {
      const data = await getAlerts();
      setAlerts(data);
    };
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  // ── BLACKLIST COUNT ──
  useEffect(() => {
    const fetchBlacklist = async () => {
      try {
        const res  = await fetch("http://127.0.0.1:8000/honeypot/blacklist");
        const data = await res.json();
        setBlacklistCount((data.blocked_ips || []).length);
      } catch (e) {}
    };
    fetchBlacklist();
    const interval = setInterval(fetchBlacklist, 3000);
    return () => clearInterval(interval);
  }, []);

  // ── WEBSOCKET LIVE THREATS ──
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: any  = null;

    const connect = () => {
      try {
        ws = new WebSocket("ws://127.0.0.1:8000/ws/threats");

        ws.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data);
            if (data.type === "threat") {
              const id = Date.now();
              setNotifications(prev => [{ ...data, id }, ...prev].slice(0, 5));
              setTimeout(() => {
                setNotifications(prev => prev.filter(n => n.id !== id));
              }, 5000);
            }
            if (data.type === "campaign") {
              const id = Date.now();
              setCampaigns(prev => [{ ...data.campaign, id }, ...prev].slice(0, 3));
              setTimeout(() => {
                setCampaigns(prev => prev.filter(c => c.id !== id));
              }, 15000);
            }
          } catch {}
        };

        ws.onclose = () => {
          reconnectTimer = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          ws?.close();
        };
      } catch {}
    };

    connect();
    return () => {
      ws?.close();
      clearTimeout(reconnectTimer);
    };
  }, []);

  const totalAlerts  = alerts.length;
  const blocked      = alerts.filter((a) => a.action === "BLOCK").length;
  const totalBlocked = blocked + blacklistCount;

  const handleDemoAttack = async () => {
    setDemoRunning(true);
    await fetch("http://127.0.0.1:8000/demo/attack", { method: "POST" });
    setTimeout(() => setDemoRunning(false), 16000);
  };

  const handleReset = async () => {
    if (confirm("Reset all demo data?")) {
      await fetch("http://127.0.0.1:8000/demo/reset", { method: "POST" });
    }
  };

  // Add keyframes to document
  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = `
      @keyframes slideIn {
        from { opacity: 0; transform: translateX(40px); }
        to   { opacity: 1; transform: translateX(0); }
      }
      @keyframes shrink {
        from { width: 100%; }
        to   { width: 0%; }
      }
    `;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  // ── POLL CAMPAIGNS (fallback if WebSocket fails) ──
useEffect(() => {
  const fetchCampaigns = async () => {
    try {
      const res  = await fetch("http://127.0.0.1:8000/correlation/campaigns");
      const data = await res.json();
      if (data.campaigns?.length > 0) {
        setCampaigns(data.campaigns.slice(0, 3).map((c: any) => ({ ...c, id: c.id || Date.now() })));
      }
    } catch {}
  };
  fetchCampaigns();
  const interval = setInterval(fetchCampaigns, 3000);
  return () => clearInterval(interval);
}, []);

  if (checkingAuth) {
    return (
      <div style={{
        minHeight: "100vh", display: "flex", alignItems: "center",
        justifyContent: "center", background: "#020617",
        color: "#94a3b8", fontSize: "14px", gap: "10px",
      }}>
        <div style={{
          width: "16px", height: "16px",
          border: "2px solid #334155", borderTopColor: "#3b82f6",
          borderRadius: "50%", animation: "spin 0.8s linear infinite",
        }} />
        Checking authentication...
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  return (
    <div style={S.page}>
      <div style={S.inner}>

        {/* ── TOPBAR ── */}
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          paddingBottom: "16px", borderBottom: "1px solid #1e293b",
        }}>

          {/* Left: Logo */}
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{
              width: "8px", height: "8px", borderRadius: "50%",
              background: "#22c55e", boxShadow: "0 0 6px #22c55e",
            }} />
            <h1 style={{ fontSize: "18px", fontWeight: 700, color: "white", margin: 0, letterSpacing: "0.04em" }}>
              IntelliWall
            </h1>
            <span style={{
              fontSize: "11px", color: "#475569", background: "#0f172a",
              border: "1px solid #1e293b", borderRadius: "6px", padding: "2px 8px",
            }}>
              LIVE
            </span>
          </div>

          {/* Right: Controls */}
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <a href="/report" style={{
              padding: "8px 16px",
              background: "transparent",
              border: "1px solid #475569",
              color: "#94a3b8",
              borderRadius: "8px",
              fontSize: "13px",
              fontWeight: 500,
              cursor: "pointer",
              textDecoration: "none",
            }}>
              Report
            </a>
            <button
              onClick={handleDemoAttack}
              disabled={demoRunning}
              style={{
                padding: "8px 16px",
                background: demoRunning ? "rgba(59,130,246,0.1)" : "transparent",
                border: "1px solid #3b82f6", color: "#60a5fa",
                borderRadius: "8px", fontSize: "13px", fontWeight: 500,
                cursor: demoRunning ? "default" : "pointer",
                transition: "background 0.2s",
                display: "flex", alignItems: "center", gap: 6,
              }}
              onMouseEnter={(e) => { if (!demoRunning) e.currentTarget.style.background = "rgba(59,130,246,0.1)"; }}
              onMouseLeave={(e) => { if (!demoRunning) e.currentTarget.style.background = demoRunning ? "rgba(59,130,246,0.1)" : "transparent"; }}
            >
              {demoRunning && (
                <span style={{
                  width: 8, height: 8, borderRadius: "50%", background: "#60a5fa",
                  display: "inline-block", animation: "spin 0.8s linear infinite",
                }} />
              )}
              {demoRunning ? "Running..." : "Demo Attack"}
            </button>

            <button
              onClick={handleReset}
              style={{
                padding: "8px 16px", background: "transparent",
                border: "1px solid #475569", color: "#64748b",
                borderRadius: "8px", fontSize: "13px", fontWeight: 500,
                cursor: "pointer", transition: "background 0.2s",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(71,85,105,0.1)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              Reset
            </button>

            <button
              onClick={() => { localStorage.removeItem("token"); window.location.href = "/login"; }}
              style={{
                padding: "8px 16px", background: "transparent",
                border: "1px solid #dc2626", color: "#f87171",
                borderRadius: "8px", fontSize: "13px", fontWeight: 500,
                cursor: "pointer", transition: "background 0.2s",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(220,38,38,0.1)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              Logout
            </button>

          </div>
        </div>{/* ── END TOPBAR ── */}

        {/* ── LIVE THREAT NOTIFICATIONS ── */}
        <div style={{ position: "fixed", top: 20, right: 20, zIndex: 9999, display: "flex", flexDirection: "column", gap: 8, pointerEvents: "none" }}>
          {notifications.map((n) => {
            const isBlock    = n.action === "BLOCK";
            const isHoneypot = n.action === "HONEYPOT";
            const color      = isBlock ? "#f87171" : isHoneypot ? "#c084fc" : "#fbbf24";
            const bg         = isBlock ? "rgba(248,113,113,0.12)" : isHoneypot ? "rgba(192,132,252,0.12)" : "rgba(251,191,36,0.12)";
            const border     = isBlock ? "rgba(248,113,113,0.35)" : isHoneypot ? "rgba(192,132,252,0.35)" : "rgba(251,191,36,0.35)";
            const icon = isBlock ? "[BLOCK]" : isHoneypot ? "[TRAP]" : "[WARN]";
            const label      = isBlock ? "BLOCKED" : isHoneypot ? "HONEYPOT" : "CHALLENGE";

            return (
              <div key={n.id} style={{
                background: bg, border: `1px solid ${border}`,
                borderRadius: 10, padding: "12px 16px",
                minWidth: 320, maxWidth: 380,
                backdropFilter: "blur(8px)",
                boxShadow: `0 4px 20px rgba(0,0,0,0.4), 0 0 20px ${color}20`,
                animation: "slideIn 0.3s ease-out",
                pointerEvents: "auto",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color, background: `${color}20`, border: `1px solid ${color}40`, borderRadius: 4, padding: "2px 6px" }}>{icon}</span>
                  <span style={{ fontSize: 12, fontWeight: 700, color, letterSpacing: "0.06em" }}>
                     LIVE THREAT — {label}
                  </span>
                  <span style={{ marginLeft: "auto", fontSize: 10, color: "rgba(148,163,184,0.6)" }}>
                    {new Date(n.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ display: "flex", gap: 12, fontSize: 11 }}>
                  <span style={{ fontFamily: "ui-monospace,monospace", color: "#e2e8f0", fontWeight: 600 }}>{n.source}</span>
                  <span style={{ color: "rgba(148,163,184,0.7)" }}>·</span>
                  <span style={{ color: "rgba(148,163,184,0.8)" }}>{n.country}</span>
                  <span style={{ color: "rgba(148,163,184,0.7)" }}>·</span>
                  <span style={{ color, fontWeight: 600 }}>risk {n.risk}</span>
                </div>
                <div style={{ fontSize: 11, color: "rgba(148,163,184,0.6)", marginTop: 4 }}>{n.attack_type}</div>
                {/* Progress bar — auto dismiss timer */}
                <div style={{ marginTop: 8, height: 2, borderRadius: 99, background: "rgba(255,255,255,0.1)", overflow: "hidden" }}>
                  <div style={{ height: "100%", background: color, borderRadius: 99, animation: "shrink 5s linear forwards" }} />
                </div>
              </div>
            );
          })}
        </div>

        {/* ── COORDINATED ATTACK BANNER ── */}
        {campaigns.map((camp) => (
          <div key={camp.id} style={{
            background: "rgba(220,38,38,0.08)",
            border: "1px solid rgba(220,38,38,0.35)",
            borderRadius: 12,
            padding: "14px 20px",
            animation: "slideIn 0.4s ease-out",
            display: "flex",
            alignItems: "center",
            gap: 16,
          }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#f87171", flexShrink: 0, border: "1px solid rgba(248,113,113,0.3)", borderRadius: 6, padding: "4px 8px" }}>ALERT</div>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: "#f87171", letterSpacing: "0.06em" }}>
                  COORDINATED ATTACK DETECTED — {camp.campaign_type}
                </span>
                <span style={{ fontSize: 10, fontWeight: 700, color: "#f87171",
                  background: "rgba(248,113,113,0.15)", border: "1px solid rgba(248,113,113,0.3)",
                  borderRadius: 5, padding: "2px 8px" }}>
                  {camp.threat_level}
                </span>
                <span style={{ fontSize: 10, color: "#64748b", marginLeft: "auto" }}>
                  Confidence: {camp.confidence}%
                </span>
              </div>
              <div style={{ fontSize: 12, color: "#94a3b8" }}>
                <span style={{ color: "#f87171", fontWeight: 600 }}>{camp.ip_count} IPs</span>
                {" "}from{" "}
                <span style={{ color: "#60a5fa", fontWeight: 600 }}>{camp.country}</span>
                {" "}coordinating within{" "}
                <span style={{ fontWeight: 600 }}>{camp.window_secs}s</span>
                {" "}— avg risk{" "}
                <span style={{ color: "#f87171", fontWeight: 600 }}>{camp.avg_risk}</span>
                {" "}— likely botnet campaign
              </div>
              <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                {(camp.ips || []).slice(0, 6).map((ip: string) => (
                  <span key={ip} style={{ fontFamily: "ui-monospace,monospace", fontSize: 10,
                    color: "#94a3b8", background: "rgba(248,113,113,0.08)",
                    border: "1px solid rgba(248,113,113,0.2)", borderRadius: 4, padding: "1px 6px" }}>
                    {ip}
                  </span>
                ))}
                {camp.ip_count > 6 && <span style={{ fontSize: 10, color: "#64748b" }}>+{camp.ip_count - 6} more</span>}
              </div>
            </div>
            <button onClick={() => setCampaigns(prev => prev.filter(c => c.id !== camp.id))}
              style={{ background: "transparent", border: "none", color: "#475569", fontSize: 18, cursor: "pointer", flexShrink: 0 }}>
              ✕
            </button>
          </div>
        ))}

        

        {/* ── METRICS BAR ── */}
        <div style={{ ...S.card, padding: "16px 20px" }}>
          <MetricsBar
            alerts={totalAlerts}
            blocked={totalBlocked}
            risk={systemRisk}
            devices={alerts.length}
          />
        </div>

        {/* ── ROW 1: Network Graph + Risk + Top Attackers ── */}
        <div style={{ display: "grid", gridTemplateColumns: "3fr 1fr", gap: "20px", height: "420px" }}>

          <div style={{ ...S.card, display: "flex", flexDirection: "column" }}>
            <div style={S.cardHeader}>
              <p style={S.cardTitle}>Network Graph</p>
              <div style={{
                fontSize: "11px", color: "#22c55e",
                background: "rgba(34,197,94,0.08)",
                border: "1px solid rgba(34,197,94,0.2)",
                borderRadius: "6px", padding: "2px 8px",
              }}>Live</div>
            </div>
            <div style={{ flex: 1, padding: "8px", overflow: "hidden" }}>
              <NetworkGraph />
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "20px", height: "420px" }}>

            <div style={{ ...S.card, flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "16px" }}>
              <p style={{ fontSize: "11px", fontWeight: 600, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.08em", margin: "0 0 12px" }}>
                Risk Level
              </p>
              <RiskMeter risk={systemRisk} />
            </div>

            <div style={{ ...S.card, flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
              <div style={S.cardHeader}>
                <p style={S.cardTitle}>Top Attackers</p>
              </div>
              <div style={{ flex: 1, padding: "12px", overflow: "hidden" }}>
                <TopAttackers alerts={alerts} />
              </div>
            </div>

          </div>
        </div>

        {/* ── ROW 2: Threat Timeline + Geo Map ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", height: "380px" }}>

          <div style={{ ...S.card, display: "flex", flexDirection: "column" }}>
            <div style={S.cardHeader}>
              <p style={S.cardTitle}>Threat Timeline</p>
            </div>
            <div style={{ flex: 1, padding: "12px", overflow: "hidden" }}>
              <ThreatTimeline alerts={alerts} />
            </div>
          </div>

          <div style={{ ...S.card, display: "flex", flexDirection: "column" }}>
            <div style={S.cardHeader}>
              <p style={S.cardTitle}>Attack Origins</p>
            </div>
            <div style={{ flex: 1, minHeight: "0" }}>
              <GeoMap alerts={alerts} />
            </div>
          </div>

        </div>

        {/* ── HONEYPOT INTELLIGENCE ── */}
        <div style={S.card}>
          <div style={S.cardHeader}>
            <p style={S.cardTitle}>Honeypot Intelligence</p>
          </div>
          <div style={S.cardBody}>
            <HoneypotPanel />
          </div>
        </div>
        <div style={S.card}>
          <FederatedPanel />
        </div>

        {/* ── ALERTS PANEL ── */}
        <div style={S.card}>
          <div style={S.cardHeader}>
            <p style={S.cardTitle}>Alert Log</p>
            <span style={{ fontSize: "12px", color: "#64748b" }}>
              {totalAlerts} total · {totalBlocked} blocked
            </span>
          </div>
          <div style={S.cardBody}>
            <AlertsPanel />
          </div>
        </div>

      </div>
    </div>
  );
}
