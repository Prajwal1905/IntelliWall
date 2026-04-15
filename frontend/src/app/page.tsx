"use client";

import { useEffect, useState } from "react";
import RiskMeter from "../components/RiskMeter";
import AlertsPanel from "../components/AlertsPanel";
import MetricsBar from "../components/MetricsBar";
import NetworkGraph from "../components/NetworkGraph";
import ThreatTimeline from "../components/ThreatTimeline";
import TopAttackers from "../components/TopAttackers";
import dynamic from "next/dynamic";

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
