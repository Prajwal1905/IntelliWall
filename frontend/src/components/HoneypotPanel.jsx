"use client";

import React, { useEffect, useState, useRef } from "react";
import dynamic from "next/dynamic";

const HoneypotMap = dynamic(() => import("./HoneypotMap"), { ssr: false });

const BASE_URL = "http://127.0.0.1:8000";

const C = {
  pageBg:        "#020617",
  cardBg:        "#0a1628",
  cardBg2:       "#0f172a",
  border:        "#1e293b",
  textPrimary:   "#ffffff",
  textSecondary: "#94a3b8",
  textMuted:     "#64748b",
  textDim:       "#475569",
  green:         "#22c55e",
  greenBg:       "rgba(34,197,94,0.08)",
  greenBorder:   "rgba(34,197,94,0.2)",
  blue:          "#3b82f6",
  blueBg:        "rgba(59,130,246,0.08)",
  blueBorder:    "rgba(59,130,246,0.2)",
  red:           "#f87171",
  redDeep:       "#dc2626",
  redBg:         "rgba(220,38,38,0.10)",
  redBorder:     "rgba(220,38,38,0.25)",
  yellow:        "#fbbf24",
  yellowBg:      "rgba(251,191,36,0.08)",
  yellowBorder:  "rgba(251,191,36,0.2)",
  orange:        "#fb923c",
  orangeBg:      "rgba(251,146,60,0.08)",
  orangeBorder:  "rgba(251,146,60,0.2)",
  purple:        "#c084fc",
};

function riskColor(r)  { return r >= 70 ? C.red : r >= 40 ? C.yellow : C.green; }
function riskLabel(r)  { return r >= 70 ? "Critical" : r >= 40 ? "Suspicious" : "Low"; }
function levelColor(l) { return l === "CRITICAL" ? C.red : l === "HIGH" ? "#fb923c" : l === "MEDIUM" ? C.yellow : C.green; }
function deriveFlowStatus(logs) {
  if (!logs.length) return "safe";
  const avg = logs.slice(0, 10).reduce((s, l) => s + (l.risk || 0), 0) / Math.min(logs.length, 10);
  return avg >= 70 ? "attack" : avg >= 40 ? "suspicious" : "safe";
}

// ─── TIMESTAMP FORMATTER ─────────────────────────────────────────────────────
function formatTs(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts.replace(" ", "T"));
    if (isNaN(d.getTime())) return ts.slice(11, 19) || "—";
    return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  } catch { return "—"; }
}

// ─── FINGERPRINT PANEL ───────────────────────────────────────────────────────
function FpRow({ label, value, color }) {
  if (!value || value === "—") return null;
  return (
    <div style={{ display: "flex", gap: 8, padding: "4px 0", alignItems: "flex-start" }}>
      <span style={{ fontSize: 11, color: C.textDim, minWidth: 110, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 11, color: color || C.textSecondary, fontFamily: "ui-monospace,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 260 }}>
        {String(value)}
      </span>
    </div>
  );
}

function SectionDivider({ title, color }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, margin: "10px 0 6px" }}>
      <span style={{ fontSize: 9, fontWeight: 700, color: color || C.textDim, letterSpacing: "0.1em", textTransform: "uppercase" }}>{title}</span>
      <div style={{ flex: 1, height: 1, background: C.border }} />
    </div>
  );
}

function FingerprintPanel({ fp, log }) {
  const hasHttp   = !!fp;
  const hasPacket = !!(log?.features);
  const features  = log?.features || [];

  const entropyVal   = features[6] != null ? features[6].toFixed(3) : null;
  const entropyColor = features[6] < 0.1 ? C.red : features[6] < 0.3 ? C.yellow : C.green;
  const entropyNote  = features[6] < 0.1 ? " ← encrypted/suspicious" : features[6] < 0.3 ? " ← low entropy" : "";

  return (
    <div style={{ background: "rgba(2,6,23,0.7)", borderTop: `1px solid ${C.border}`, padding: "14px 20px" }}>
      <div style={{ display: "grid", gridTemplateColumns: hasHttp && hasPacket ? "1fr 1fr" : "1fr", gap: "0 32px" }}>

        {/* ── LAYER 1: APPLICATION FINGERPRINT (HTTP trap data) ── */}
        {hasHttp && (
          <div>
            <SectionDivider title="Application Layer — HTTP Fingerprint" color={C.purple} />
            {fp.scanner && (
              <div style={{ display: "flex", gap: 8, padding: "4px 0", alignItems: "center" }}>
                <span style={{ fontSize: 11, color: C.textDim, minWidth: 110, flexShrink: 0 }}>Scanner</span>
                <span style={{ fontSize: 11, fontWeight: 700, color: C.red, fontFamily: "ui-monospace,monospace",
                  background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: 4, padding: "1px 6px" }}>
                  ⚠ {fp.scanner}
                </span>
              </div>
            )}
            <FpRow label="User Agent"   value={fp.user_agent} />
            <FpRow label="Method"       value={fp.method}     color={fp.method === "POST" ? C.yellow : null} />
            <FpRow label="Path"         value={fp.path} />
            <FpRow label="X-Forwarded"  value={fp.x_forwarded} />
            <FpRow label="Referer"      value={fp.referer} />
            <FpRow label="Accept-Lang"  value={fp.accept_lang} />
            <FpRow label="Query Params" value={fp.query_params ? JSON.stringify(fp.query_params) : null} />
            {fp.credentials && (
              <div style={{ display: "flex", gap: 8, padding: "4px 0" }}>
                <span style={{ fontSize: 11, color: C.textDim, minWidth: 110, flexShrink: 0 }}>Credentials</span>
                <span style={{ fontSize: 11, color: C.red, fontFamily: "ui-monospace,monospace",
                  background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: 4, padding: "1px 6px" }}>
                  {fp.credentials.username} / {fp.credentials.password}
                </span>
              </div>
            )}
          </div>
        )}

        {/* ── LAYER 2: NETWORK FINGERPRINT (Packet analysis) ── */}
        {hasPacket && (
          <div>
            <SectionDivider title="Network Layer — Packet Analysis" color={C.blue} />
            <FpRow label="Protocol"    value={log.attack_type} />
            <FpRow label="Country"     value={log.country} />
            <FpRow label="ISP"         value={log.isp} />
            {features[0] != null && <FpRow label="Packet Count"  value={`${features[0]}  ${features[0] > 1000 ? "← high volume" : ""}`} color={features[0] > 1000 ? C.red : null} />}
            {features[2] != null && <FpRow label="Byte Rate"     value={`${features[2]}  ${features[2] > 7000 ? "← flood detected" : ""}`} color={features[2] > 7000 ? C.red : null} />}
            {entropyVal   && <FpRow label="Entropy"       value={`${entropyVal}${entropyNote}`} color={entropyColor} />}
            {features[8] != null && <FpRow label="Suspicious Flag" value={features[8] === 1 ? "YES ← anomalous pattern" : "No"} color={features[8] === 1 ? C.red : C.green} />}
            <FpRow label="Risk Score"  value={`${log.risk || 0}%`} color={riskColor(log.risk || 0)} />
          </div>
        )}

        {/* ── NEITHER — fallback ── */}
        {!hasHttp && !hasPacket && (
          <div style={{ padding: "8px 0" }}>
            <span style={{ fontSize: 12, color: C.textDim }}>No analysis data available</span>
          </div>
        )}

      </div>

      {/* ── ESCALATION INFO ── */}
      {log?.escalation_stage && (
        <div style={{ marginTop: 10, padding: "8px 12px", borderRadius: 7, display: "flex", alignItems: "center", gap: 10,
          background: log.escalation_stage >= 4 ? "rgba(248,113,113,0.08)" : "rgba(251,191,36,0.06)",
          border: `1px solid ${log.escalation_stage >= 4 ? "rgba(248,113,113,0.25)" : "rgba(251,191,36,0.2)"}` }}>
          <span style={{ fontSize: 14 }}>{log.escalation_stage >= 4 ? "🚫" : log.escalation_stage === 3 ? "🎣" : log.escalation_stage === 2 ? "🪤" : "👁"}</span>
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: log.escalation_stage >= 4 ? "#f87171" : "#fbbf24", letterSpacing: "0.06em" }}>
              DECEPTION STAGE {log.escalation_stage}/4 — {log.escalation_info?.stage}
            </div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>{log.escalation_info?.description}</div>
            <div style={{ fontSize: 10, color: "#475569", marginTop: 1 }}>Total hits from this IP: {log.total_hits}</div>
          </div>
        </div>
      )}

      {/* ── THREAT ATTRIBUTION + KILL CHAIN + ZERO DAY ── */}
      {hasPacket && <ThreatIntelPanel log={log} fp={fp} />}
    </div>
  );
}

// ── THREAT ATTRIBUTION DATA ───────────────────────────────────────────────────
const THREAT_ACTORS = [
  {
    name: "APT28 (Fancy Bear)",
    color: "#f87171",
    flag: "🇷🇺",
    match: (log, fp) =>
      ["Russia", "Ukraine"].includes(log?.country) &&
      (log?.features?.[0] > 900 || log?.features?.[6] < 0.1) &&
      ["T1046 - Network Scan", "Port Scan", "DDoS Attack"].some(t => log?.attack_type?.includes(t.split(" ")[0])),
    desc: "Russian GRU cyber unit — known for network reconnaissance and credential theft",
  },
  {
    name: "APT41 (Double Dragon)",
    color: "#fb923c",
    flag: "🇨🇳",
    match: (log, fp) =>
      log?.country === "China" &&
      log?.features?.[2] > 5000,
    desc: "Chinese state actor — targets financial and tech infrastructure",
  },
  {
    name: "Lazarus Group",
    color: "#c084fc",
    flag: "🇰🇷",
    match: (log, fp) =>
      ["China", "Netherlands"].includes(log?.country) &&
      log?.features?.[6] < 0.08,
    desc: "North Korean APT — known for encrypted C2 channels and low entropy traffic",
  },
  {
    name: "Kimsuky",
    color: "#fbbf24",
    flag: "🌐",
    match: (log, fp) =>
      log?.isp?.toLowerCase().includes("fastvps") ||
      log?.isp?.toLowerCase().includes("tor"),
    desc: "Uses VPS/Tor infrastructure to mask origin — credential harvesting specialist",
  },
  {
    name: "Anonymous Scanner",
    color: "#94a3b8",
    flag: "🌐",
    match: (log, fp) =>
      fp?.scanner != null,
    desc: "Automated scanning tool detected — likely opportunistic attacker",
  },
];

const KILL_CHAIN = [
  { stage: "Reconnaissance",  attacks: ["T1046", "Port Scan", "Network Scan", "Service Probe"] },
  { stage: "Exploitation",    attacks: ["T1190", "Exploit", "Credential", "Brute Force", "Shell"] },
  { stage: "C2 Channel",      attacks: ["T1071", "C2", "Command"] },
  { stage: "Exfiltration",    attacks: ["Exfiltration", "Data", "Backup"] },
  { stage: "Impact",          attacks: ["DDoS", "Flood", "Burst"] },
];

function getKillChainStage(attackType) {
  if (!attackType) return null;
  for (const kc of KILL_CHAIN) {
    if (kc.attacks.some(a => attackType.includes(a))) return kc.stage;
  }
  return null;
}

function getNextStage(stage) {
  const order = ["Reconnaissance", "Exploitation", "C2 Channel", "Exfiltration", "Impact"];
  const idx = order.indexOf(stage);
  return idx >= 0 && idx < order.length - 1 ? order[idx + 1] : null;
}

function ThreatIntelPanel({ log, fp }) {
  const attackType = log?.attack_type || "";
  const risk       = log?.risk || 0;
  const features   = log?.features || [];

  // Attribution
  const actor = THREAT_ACTORS.find(a => a.match(log, fp));

  // Kill chain
  const stage     = getKillChainStage(attackType);
  const nextStage = stage ? getNextStage(stage) : null;

  // Zero day detection
  const isZeroDay = (
    risk >= 60 &&
    (attackType === "Unknown" || attackType === "" || attackType === "Suspicious Behavior") &&
    features[8] === 1
  );

  if (!actor && !stage && !isZeroDay) return null;

  return (
    <div style={{ marginTop: 12, paddingTop: 12, borderTop: `1px solid ${C.border}`, display: "flex", flexDirection: "column", gap: 8 }}>

      {/* Zero Day Alert */}
      {isZeroDay && (
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", background: "rgba(248,113,113,0.08)", border: `1px solid rgba(248,113,113,0.3)`, borderRadius: 8 }}>
          <span style={{ fontSize: 14 }}>⚠</span>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.red, letterSpacing: "0.06em" }}>POTENTIAL ZERO DAY DETECTED</div>
            <div style={{ fontSize: 10, color: C.textMuted, marginTop: 2 }}>Unknown attack pattern — no existing signature match — AI flagged anomalous behavior</div>
          </div>
        </div>
      )}

      {/* Kill Chain */}
      {stage && (
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", background: "rgba(251,191,36,0.06)", border: `1px solid rgba(251,191,36,0.2)`, borderRadius: 8 }}>
          <span style={{ fontSize: 12 }}>⛓</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.yellow, letterSpacing: "0.04em", marginBottom: 4 }}>
              MITRE ATT&CK KILL CHAIN
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
              {["Reconnaissance","Exploitation","C2 Channel","Exfiltration","Impact"].map((s, i) => {
                const isActive = s === stage;
                const isPast   = ["Reconnaissance","Exploitation","C2 Channel","Exfiltration","Impact"].indexOf(s) <
                                 ["Reconnaissance","Exploitation","C2 Channel","Exfiltration","Impact"].indexOf(stage);
                return (
                  <React.Fragment key={s}>
                    <span style={{
                      fontSize: 9, fontWeight: 600, padding: "2px 7px", borderRadius: 4,
                      letterSpacing: "0.04em",
                      color:      isActive ? "#020617" : isPast ? C.yellow : C.textDim,
                      background: isActive ? C.yellow  : isPast ? "rgba(251,191,36,0.15)" : "transparent",
                      border:     `1px solid ${isActive ? C.yellow : isPast ? "rgba(251,191,36,0.3)" : C.border}`,
                    }}>{s}</span>
                    {i < 4 && <span style={{ fontSize: 9, color: C.textDim }}>→</span>}
                  </React.Fragment>
                );
              })}
            </div>
            {nextStage && (
              <div style={{ fontSize: 10, color: C.textMuted, marginTop: 4 }}>
                Next likely stage: <span style={{ color: C.red, fontWeight: 600 }}>{nextStage}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Threat Actor Attribution */}
      {actor && (
        <div style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "8px 12px", background: `${actor.color}0d`, border: `1px solid ${actor.color}40`, borderRadius: 8 }}>
          <span style={{ fontSize: 14, flexShrink: 0 }}>{actor.flag}</span>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: actor.color, letterSpacing: "0.04em" }}>
              THREAT ACTOR: {actor.name}
            </div>
            <div style={{ fontSize: 10, color: C.textMuted, marginTop: 2 }}>{actor.desc}</div>
          </div>
          <span style={{ marginLeft: "auto", fontSize: 9, fontWeight: 600, color: actor.color, background: `${actor.color}15`, border: `1px solid ${actor.color}30`, borderRadius: 4, padding: "2px 6px", whiteSpace: "nowrap", flexShrink: 0 }}>
            Pattern Match
          </span>
        </div>
      )}

    </div>
  );
}

// ─── SHARED UI ───────────────────────────────────────────────────────────────
function SectionLabel({ children }) {
  return <p style={{ fontSize: 13, fontWeight: 600, color: C.textSecondary, textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>{children}</p>;
}
function LiveBadge() {
  return <span style={{ fontSize: 11, color: C.green, background: C.greenBg, border: `1px solid ${C.greenBorder}`, borderRadius: 6, padding: "2px 8px", fontWeight: 500 }}>Live</span>;
}
function StatusBadge({ children, variant = "gray" }) {
  const map = {
    red:    { color: C.red,           bg: C.redBg,    border: C.redBorder },
    yellow: { color: C.yellow,        bg: C.yellowBg, border: C.yellowBorder },
    green:  { color: C.green,         bg: C.greenBg,  border: C.greenBorder },
    blue:   { color: C.blue,          bg: C.blueBg,   border: C.blueBorder },
    gray:   { color: C.textSecondary, bg: "rgba(148,163,184,0.08)", border: "rgba(148,163,184,0.18)" },
  };
  const s = map[variant] || map.gray;
  return <span style={{ fontSize: 10, fontWeight: 600, padding: "2px 8px", borderRadius: 6, whiteSpace: "nowrap", color: s.color, background: s.bg, border: `1px solid ${s.border}`, letterSpacing: "0.04em" }}>{children}</span>;
}
function Card({ children, style = {} }) {
  return <div style={{ background: C.cardBg, border: `1px solid ${C.border}`, borderRadius: 14, overflow: "hidden", ...style }}>{children}</div>;
}
function CardHeader({ left, right }) {
  return <div style={{ padding: "14px 20px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>{left}{right}</div>;
}
function MetricCard({ label, value, sub, valueColor, accentBorder }) {
  return (
    <div style={{ background: C.cardBg2, border: `1px solid ${accentBorder || C.border}`, borderRadius: 12, padding: "18px 22px" }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 10 }}>{label}</div>
      <div style={{ fontSize: 30, fontWeight: 700, color: valueColor || C.textPrimary, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: C.textDim, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}
function LiveDot() {
  return <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, display: "inline-block", flexShrink: 0, boxShadow: `0 0 5px ${C.green}`, animation: "hp-pulse 1.5s infinite" }} />;
}
function TimelineCanvas({ logs }) {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const W = canvas.offsetWidth || 500, H = 72;
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, W, H);
    if (!logs.length) return;
    const now = Date.now(), span = 5 * 60 * 1000, bins = 30;
    const buckets = Array(bins).fill(0);
    logs.forEach(l => {
      const age = now - new Date(l.timestamp).getTime();
      if (age < span) { const bi = Math.floor((1 - age / span) * (bins - 1)); buckets[bi]++; }
    });
    const maxB = Math.max(...buckets, 1);
    const bw = W / bins;
    buckets.forEach((v, i) => {
      const h = (v / maxB) * (H - 8);
      const ratio = v / maxB;
      ctx.fillStyle = v === 0 ? "#1e293b" : ratio > 0.7 ? "#ef4444" : ratio > 0.3 ? "#f59e0b" : "#22c55e";
      ctx.beginPath(); ctx.roundRect(i * bw + 1, H - h, bw - 3, h, 3); ctx.fill();
    });
  }, [logs]);
  return <canvas ref={ref} style={{ width: "100%", height: 72, display: "block" }} />;
}

// ─── ATTACK FLOW ──────────────────────────────────────────────────────────────
const FLOW_CFG = {
  safe:       { color: C.green,  bg: C.greenBg,  border: C.greenBorder,  label: "SECURE",       sub: "All traffic nominal",           pulse: "af-pulse-green"  },
  suspicious: { color: C.yellow, bg: C.yellowBg, border: C.yellowBorder, label: "SUSPICIOUS",   sub: "Anomalous activity detected",   pulse: "af-pulse-yellow" },
  attack:     { color: C.red,    bg: C.redBg,    border: C.redBorder,    label: "UNDER ATTACK", sub: "Malicious traffic intercepted", pulse: "af-pulse-red"    },
};
const FLOW_NODES = [
  { key: "attacker", label: "Attacker",  sub: "External",  icon: "⚡", glowOn: ["attack", "suspicious"] },
  { key: "ai",       label: "AI Engine", sub: "Analyzing", icon: "◈",  glowOn: ["safe", "attack", "suspicious"] },
  { key: "firewall", label: "Firewall",  sub: "Filtering", icon: "⬡",  glowOn: ["attack", "suspicious"] },
  { key: "network",  label: "Network",   sub: "Protected", icon: "◎",  glowOn: ["safe"] },
];

function ParticleTrack({ status, color }) {
  const canvasRef = useRef(null);
  const animRef   = useRef(null);
  const pRef      = useRef([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const W = canvas.offsetWidth || 160, H = 24;
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext("2d");
    const count = status === "attack" ? 8 : status === "suspicious" ? 6 : 4;
    pRef.current = Array.from({ length: count }, (_, i) => ({
      x: (W / count) * i, speed: 0.7 + Math.random() * 0.7,
      r: status === "attack" ? 3 : 2.5, op: 0.5 + Math.random() * 0.5, trail: [],
    }));
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      pRef.current.forEach(p => {
        p.x += p.speed;
        if (p.x > W + 8) p.x = -8;
        p.trail.push(p.x);
        if (p.trail.length > 8) p.trail.shift();
        p.trail.forEach((tx, ti) => {
          ctx.beginPath(); ctx.arc(tx, H / 2, p.r * 0.5, 0, Math.PI * 2);
          ctx.fillStyle = color; ctx.globalAlpha = (ti / p.trail.length) * p.op * 0.35; ctx.fill();
        });
        ctx.beginPath(); ctx.arc(p.x, H / 2, p.r, 0, Math.PI * 2);
        ctx.fillStyle = color; ctx.globalAlpha = p.op; ctx.fill();
        ctx.globalAlpha = 1;
      });
      animRef.current = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [status, color]);

  return (
    <div style={{ flex: 1, position: "relative", height: 24 }}>
      <div style={{ position: "absolute", top: "50%", left: 0, right: 0, height: 2, transform: "translateY(-50%)", background: C.border, borderRadius: 99, overflow: "hidden" }}>
        <div className={status === "attack" ? "af-track-flash" : "af-track-slide"} style={{ position: "absolute", top: 0, left: 0, height: "100%", width: "35%", background: color, borderRadius: 99, opacity: 0.7 }} />
      </div>
      <canvas ref={canvasRef} style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }} />
    </div>
  );
}

function AttackFlow({ status = "safe" }) {
  const cfg = FLOW_CFG[status] || FLOW_CFG.safe;
  return (
    <Card style={{ position: "relative" }}>
      {status === "attack" && (
        <div className="af-bg-attack" style={{ position: "absolute", inset: 0, background: "rgba(220,38,38,0.04)", pointerEvents: "none", zIndex: 0 }} />
      )}
      <CardHeader
        left={<SectionLabel>Traffic Flow</SectionLabel>}
        right={
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className={cfg.pulse} style={{ width: 7, height: 7, borderRadius: "50%", background: cfg.color, display: "inline-block", flexShrink: 0 }} />
            <span style={{ fontSize: 11, fontWeight: 700, color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: 6, padding: "2px 10px", letterSpacing: "0.06em" }}>
              {cfg.label}
            </span>
          </div>
        }
      />
      <div style={{ padding: "20px 24px 16px", position: "relative", zIndex: 1 }}>
        <div style={{ display: "flex", alignItems: "center" }}>
          {FLOW_NODES.map((n, i) => {
            const glow = n.glowOn.includes(status);
            return (
              <React.Fragment key={n.key}>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6, minWidth: 64, flexShrink: 0 }}>
                  <div style={{ width: 44, height: 44, borderRadius: 10, background: glow ? `${cfg.color}18` : C.cardBg2, border: `1px solid ${glow ? cfg.color : C.border}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, transition: "all 0.4s", boxShadow: glow ? `0 0 10px ${cfg.color}30` : "none" }}>
                    {n.icon}
                  </div>
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: glow ? cfg.color : C.textSecondary, letterSpacing: "0.04em" }}>{n.label}</div>
                    <div style={{ fontSize: 10, color: C.textDim, marginTop: 2 }}>{n.sub}</div>
                  </div>
                </div>
                {i < FLOW_NODES.length - 1 && <ParticleTrack status={status} color={cfg.color} />}
              </React.Fragment>
            );
          })}
        </div>
        <div style={{ marginTop: 18, padding: "10px 16px", background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: cfg.color, display: "inline-block" }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: cfg.color }}>{cfg.sub}</span>
          </div>
          <span style={{ fontSize: 11, color: C.textMuted, fontFamily: "ui-monospace,monospace" }}>{new Date().toLocaleTimeString()}</span>
        </div>
      </div>
    </Card>
  );
}


const INTENT_RULES = [
  {
    intent:    "DATA THEFT",
    color:     "#f87171",
    bg:        "rgba(248,113,113,0.08)",
    border:    "rgba(248,113,113,0.25)",
    icon:      "💾",
    bizRisk:   "CRITICAL — User PII & credentials at risk",
    target:    "Database / User Records",
    signals:   ["exfil", "user", "backup", "env", "credential"],
    features:  (f) => f[2] > 6000,
  },
  {
    intent:    "SABOTAGE",
    color:     "#ef4444",
    bg:        "rgba(239,68,68,0.08)",
    border:    "rgba(239,68,68,0.25)",
    icon:      "💥",
    bizRisk:   "CRITICAL — Service availability threatened",
    target:    "Core Infrastructure",
    signals:   ["ddos", "flood", "burst", "escalation"],
    features:  (f) => f[0] > 2000 || f[2] > 12000,
  },
  {
    intent:    "ESPIONAGE",
    color:     "#c084fc",
    bg:        "rgba(192,132,252,0.08)",
    border:    "rgba(192,132,252,0.25)",
    icon:      "🔍",
    bizRisk:   "HIGH — Infrastructure mapping in progress",
    target:    "Network Topology / Services",
    signals:   ["scan", "probe", "recon", "t1046", "port"],
    features:  (f) => f[6] < 0.15,
  },
  {
    intent:    "RANSOMWARE PREP",
    color:     "#fb923c",
    bg:        "rgba(251,146,60,0.08)",
    border:    "rgba(251,146,60,0.25)",
    icon:      "🔐",
    bizRisk:   "CRITICAL — Ransomware deployment likely",
    target:    "File Systems / Backups",
    signals:   ["shell", "admin", "backup", "config", "wp-admin"],
    features:  (f) => f[8] === 1 && f[0] > 1000,
  },
  {
    intent:    "CRYPTOMINING",
    color:     "#fbbf24",
    bg:        "rgba(251,191,36,0.08)",
    border:    "rgba(251,191,36,0.25)",
    icon:      "⛏",
    bizRisk:   "MEDIUM — Server resources targeted",
    target:    "Compute Resources",
    signals:   ["shell", "phpmyadmin", "config"],
    features:  (f) => f[0] > 800 && f[6] < 0.2,
  },
  {
    intent:    "COMPETITOR INTEL",
    color:     "#60a5fa",
    bg:        "rgba(96,165,250,0.08)",
    border:    "rgba(96,165,250,0.25)",
    icon:      "🕵️",
    bizRisk:   "MEDIUM — Business intelligence gathering",
    target:    "API Endpoints / Config",
    signals:   ["api", "config", "env", "user"],
    features:  (f) => f[6] > 0.3,
  },
];

function classifyIntent(profile, logs) {
  const ip      = profile.source;
  const ipLogs  = logs.filter(l => l.source === ip);
  const features = ipLogs[0]?.features || Array(10).fill(0);
  const allText  = [
    ...(profile.attack_types || []),
    ...ipLogs.map(l => l.attack_type || ""),
    ...ipLogs.map(l => l.fingerprint?.path || ""),
  ].join(" ").toLowerCase();

  const scored = INTENT_RULES.map(rule => {
    let score = 0;
    rule.signals.forEach(sig => { if (allText.includes(sig)) score += 25; });
    if (rule.features(features)) score += 20;
    if (profile.count > 3) score += 10;
    return { ...rule, confidence: Math.min(score, 97) };
  }).filter(r => r.confidence > 0)
    .sort((a, b) => b.confidence - a.confidence);

  return scored.slice(0, 2);
}

function IntentClassifierPanel({ profiles, logs }) {
  if (!profiles.length) return null;

  const topProfiles = [...profiles]
    .sort((a, b) => b.threat_score - a.threat_score)
    .slice(0, 4);

  const allIntents = topProfiles
    .map(p => ({ profile: p, intents: classifyIntent(p, logs) }))
    .filter(x => x.intents.length > 0);

  if (!allIntents.length) return null;

  return (
    <Card>
      <CardHeader
        left={<SectionLabel>Attacker Intent Analysis</SectionLabel>}
        right={
          <span style={{ fontSize: 10, fontWeight: 600, color: C.orange,
            background: C.orangeBg, border: `1px solid ${C.orangeBorder}`,
            borderRadius: 6, padding: "2px 8px" }}>
            AI Classified
          </span>
        }
      />
      <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>

        {/* Legend */}
        <div style={{ fontSize: 11, color: C.textDim, padding: "8px 12px", background: "rgba(100,116,139,0.05)", border: `1px solid ${C.border}`, borderRadius: 8 }}>
          AI classifies what each attacker is actually trying to accomplish — translating technical attacks into business risk.
        </div>

        {allIntents.map(({ profile, intents }, pi) => {
          const primary   = intents[0];
          const secondary = intents[1];
          if (!primary) return null;

          return (
            <div key={profile.source} style={{ background: C.cardBg2, border: `1px solid ${primary.border}`, borderRadius: 12, overflow: "hidden" }}>

              {/* Header */}
              <div style={{ padding: "10px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", background: `${primary.color}08` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 16 }}>{primary.icon}</span>
                  <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 12, fontWeight: 700, color: C.textPrimary }}>{profile.source}</span>
                </div>
                <span style={{ fontSize: 10, color: C.textDim }}>risk {profile.avg_risk}% · {profile.count} hits</span>
              </div>

              <div style={{ padding: "12px 16px", display: "flex", flexDirection: "column", gap: 10 }}>

                {/* Primary intent */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div>
                      <div style={{ fontSize: 10, color: C.textDim, marginBottom: 3 }}>PRIMARY INTENT</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: primary.color }}>{primary.intent}</div>
                    </div>
                  </div>
                  {/* Confidence bar */}
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                    <span style={{ fontSize: 11, fontWeight: 700, color: primary.color }}>{primary.confidence}% confidence</span>
                    <div style={{ width: 100, height: 5, borderRadius: 99, background: C.border, overflow: "hidden" }}>
                      <div style={{ width: `${primary.confidence}%`, height: "100%", background: primary.color, borderRadius: 99, transition: "width 0.6s ease" }} />
                    </div>
                  </div>
                </div>

                {/* Business risk */}
                <div style={{ display: "flex", gap: 16, fontSize: 11 }}>
                  <div>
                    <span style={{ color: C.textDim }}>Business Risk  </span>
                    <span style={{ color: primary.color, fontWeight: 600 }}>{primary.bizRisk}</span>
                  </div>
                </div>
                <div style={{ fontSize: 11 }}>
                  <span style={{ color: C.textDim }}>Predicted Target  </span>
                  <span style={{ color: C.textSecondary, fontFamily: "ui-monospace,monospace" }}>{primary.target}</span>
                </div>

                {/* Secondary intent */}
                {secondary && secondary.confidence > 20 && (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 10px", background: `${secondary.color}08`, border: `1px solid ${secondary.color}25`, borderRadius: 7 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 12 }}>{secondary.icon}</span>
                      <div>
                        <div style={{ fontSize: 9, color: C.textDim }}>SECONDARY INTENT</div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: secondary.color }}>{secondary.intent}</div>
                      </div>
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 700, color: secondary.color }}>{secondary.confidence}%</span>
                  </div>
                )}

                {/* Attack evidence */}
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(profile.attack_types || []).map(t => (
                    <span key={t} style={{ fontSize: 9, color: primary.color, background: primary.bg, border: `1px solid ${primary.border}`, borderRadius: 4, padding: "2px 7px" }}>
                      → {t}
                    </span>
                  ))}
                </div>

              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}


function AttackerDNA({ profile, logs: allLogs }) {
  const canvasRef = useRef(null);
  const ip        = profile.source;
  const ipLogs    = allLogs.filter(l => l.source === ip);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const W = canvas.offsetWidth || 300, H = 48;
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, W, H);

    const features  = ipLogs[0]?.features || [];
    const risk      = profile.avg_risk || 50;
    const entropy   = features[6] != null ? features[6] : 0.5;
    const packets   = Math.min(features[0] || 500, 1500);
    const suspicious= features[8] === 1;
    const count     = profile.count || 1;

    // Generate deterministic seed from IP
    const seed = ip.split(".").reduce((a, b) => a + parseInt(b || 0), 0);

    const bands = 48;
    const bw    = W / bands;

    for (let i = 0; i < bands; i++) {
      // Deterministic height based on IP + position + attack features
      const phase   = (seed + i * 7) % 100 / 100;
      const entropy_mod = entropy < 0.1 ? 0.9 : entropy < 0.3 ? 0.6 : 0.3;
      const h = H * 0.2 + H * 0.7 * (
        0.4 * Math.sin(i * 0.4 + seed * 0.1) +
        0.3 * Math.sin(i * 0.8 + phase * Math.PI) +
        0.3 * entropy_mod * Math.cos(i * 0.3 + count * 0.2)
      );
      const barH = Math.max(4, Math.abs(h));

      // Color based on risk + entropy
      const r = Math.round(risk >= 70 ? 248 : risk >= 40 ? 251 : 34);
      const g = Math.round(risk >= 70 ? 113 : risk >= 40 ? 191 : 197);
      const b = Math.round(risk >= 70 ? 113 : risk >= 40 ? 36  : 94);
      const alpha = 0.3 + 0.7 * (i % 3 === 0 ? 1 : i % 3 === 1 ? 0.6 : 0.35);

      ctx.fillStyle = `rgba(${r},${g},${b},${alpha})`;
      ctx.fillRect(i * bw + 0.5, (H - barH) / 2, bw - 1, barH);

      // Suspicious pattern overlay — darker spikes
      if (suspicious && i % 5 === 0) {
        ctx.fillStyle = `rgba(248,113,113,0.9)`;
        ctx.fillRect(i * bw + 0.5, H * 0.1, bw - 1, H * 0.8);
      }
    }

    // Scan line effect
    ctx.fillStyle = "rgba(255,255,255,0.04)";
    ctx.fillRect(0, H/2 - 0.5, W, 1);

  }, [profile, allLogs]);

  return (
    <canvas ref={canvasRef} style={{ width: "100%", height: 48, display: "block", borderRadius: 4 }} />
  );
}

function AttackerDNAPanel({ profiles, logs }) {
  if (!profiles.length) return null;
  const top = [...profiles].sort((a, b) => b.threat_score - a.threat_score).slice(0, 5);

  return (
    <Card>
      <CardHeader
        left={<SectionLabel>Attacker Behavioral DNA</SectionLabel>}
        right={
          <span style={{ fontSize: 10, fontWeight: 600, color: "#c084fc",
            background: "rgba(192,132,252,0.08)", border: "1px solid rgba(192,132,252,0.2)",
            borderRadius: 6, padding: "2px 8px" }}>
            Unique Signature Per Attacker
          </span>
        }
      />
      <div style={{ padding: "8px 16px 16px" }}>
        <div style={{ fontSize: 10, color: C.textDim, marginBottom: 12, lineHeight: 1.5 }}>
          Each strand is generated from packet behavior, entropy, timing and attack patterns.
          Identical DNA across different IPs indicates the same threat actor.
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {top.map((p, i) => {
            const rc = riskColor(p.avg_risk);
            return (
              <div key={p.source} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {/* IP + stats row */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 10, color: C.textDim, minWidth: 16 }}>#{i+1}</span>
                    <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 12, fontWeight: 600, color: C.textSecondary }}>{p.source}</span>
                    {p.is_suspicious && <StatusBadge variant="red">High Risk</StatusBadge>}
                  </div>
                  <div style={{ display: "flex", gap: 12, fontSize: 10, color: C.textDim }}>
                    <span>risk <span style={{ color: rc, fontWeight: 600 }}>{p.avg_risk}%</span></span>
                    <span>hits <span style={{ color: C.textSecondary, fontWeight: 600 }}>{p.count}</span></span>
                    <span>score <span style={{ color: C.red, fontWeight: 600 }}>{p.threat_score}</span></span>
                  </div>
                </div>
                {/* DNA strand */}
                <AttackerDNA profile={p} logs={logs} />
                {/* Attack types */}
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(p.attack_types || []).map(t => (
                    <span key={t} style={{ fontSize: 9, color: C.textDim, background: "rgba(100,116,139,0.1)", border: `1px solid ${C.border}`, borderRadius: 4, padding: "1px 6px" }}>{t}</span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </Card>
  );
}


function ConversationLog({ logs }) {
  
  const byIP = {};
  logs.forEach(l => {
    if (!l.source) return;
    if (!byIP[l.source]) byIP[l.source] = [];
    byIP[l.source].push(l);
  });

  
  const conversations = Object.entries(byIP)
    .filter(([ip, events]) => events.length >= 1)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 3);

  if (conversations.length === 0) return null;

  // Fake server response per attack type
  function serverResponse(log) {
    const t = (log.attack_type || "").toLowerCase();
    const fp = log.fingerprint;
    if (t.includes("credential") || t.includes("login")) {
      const creds = fp?.credentials;
      return {
        text: creds
          ? `{"token":"eyJhbGci.fake.token","user":"${creds.username}","expires":3600}`
          : `{"token":"eyJhbGci.fake.token","expires":3600}`,
        type: "deception",
      };
    }
    if (t.includes("admin") || t.includes("panel"))
      return { text: `{"status":"ok","role":"superadmin","session":"active"}`, type: "deception" };
    if (t.includes("env") || t.includes("config"))
      return { text: `{"DB_HOST":"localhost","DB_PASS":"secret123","API_KEY":"sk-abc123"}`, type: "deception" };
    if (t.includes("shell"))
      return { text: `{"output":"root@server:~#","uid":"0(root)","status":"connected"}`, type: "deception" };
    if (t.includes("exfil") || t.includes("user"))
      return { text: `{"users":[{"id":1,"email":"admin@company.com","role":"superadmin"}]}`, type: "deception" };
    if (t.includes("scan") || t.includes("probe"))
      return { text: `{"services":["ssh:22","http:80","https:443","mysql:3306"]}`, type: "info" };
    if (t.includes("block") || t.includes("ddos"))
      return { text: `CONNECTION TERMINATED — IP BLACKLISTED`, type: "block" };
    return { text: `{"status":"ok"}`, type: "deception" };
  }

  function attackerMessage(log) {
    const fp  = log.fingerprint;
    const t   = log.attack_type || "Unknown";
    if (fp?.path && fp?.method) {
      const creds = fp.credentials
        ? ` ${JSON.stringify({ username: fp.credentials.username, password: "***" })}`
        : "";
      return `${fp.method} ${fp.path}${creds}`;
    }
    return `[${t}] — packet-level attack`;
  }

  const typeColor = { deception: C.yellow, info: C.blue, block: C.red };
  const typeLabel = { deception: "DECEPTION", info: "INFO", block: "BLOCKED" };

  return (
    <Card>
      <CardHeader
        left={<SectionLabel>Attacker Conversation Log</SectionLabel>}
        right={
          <span style={{ fontSize: 10, fontWeight: 600, color: C.purple,
            background: "rgba(192,132,252,0.08)", border: "1px solid rgba(192,132,252,0.2)",
            borderRadius: 6, padding: "2px 8px" }}>
            Live Deception Feed
          </span>
        }
      />
      <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>
        {conversations.map(([ip, events]) => (
          <div key={ip} style={{ background: C.cardBg2, border: `1px solid ${C.border}`, borderRadius: 12, overflow: "hidden" }}>

            
            <div style={{ padding: "10px 14px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", background: "rgba(0,0,0,0.2)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 7, height: 7, borderRadius: "50%", background: C.red, boxShadow: `0 0 5px ${C.red}`, display: "inline-block", animation: "hp-pulse 1s infinite" }} />
                <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 12, fontWeight: 700, color: C.textPrimary }}>{ip}</span>
              </div>
              <span style={{ fontSize: 10, color: C.textDim }}>{events.length} exchanges</span>
            </div>

            
            <div style={{ padding: "10px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
              {events.slice(-5).map((log, i) => {
                const resp    = serverResponse(log);
                const isLast  = i === events.slice(-5).length - 1;
                const isBlock = log.risk >= 85 || resp.type === "block";

                return (
                  <div key={i} style={{ display: "flex", flexDirection: "column", gap: 4 }}>

                    {/* Attacker message */}
                    <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: C.red, minWidth: 72, flexShrink: 0, fontFamily: "ui-monospace,monospace", paddingTop: 2 }}>
                        ATTACKER →
                      </span>
                      <span style={{ fontSize: 11, color: C.textSecondary, fontFamily: "ui-monospace,monospace", background: "rgba(248,113,113,0.06)", border: "1px solid rgba(248,113,113,0.15)", borderRadius: 5, padding: "3px 8px", flex: 1, wordBreak: "break-all" }}>
                        {attackerMessage(log)}
                      </span>
                    </div>

                    
                    <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: typeColor[resp.type] || C.green, minWidth: 72, flexShrink: 0, fontFamily: "ui-monospace,monospace", paddingTop: 2 }}>
                        SERVER  →
                      </span>
                      <div style={{ flex: 1, display: "flex", alignItems: "flex-start", gap: 6 }}>
                        <span style={{ fontSize: 11, color: typeColor[resp.type] || C.green, fontFamily: "ui-monospace,monospace",
                          background: `${typeColor[resp.type]}10` || C.greenBg,
                          border: `1px solid ${typeColor[resp.type]}30`,
                          borderRadius: 5, padding: "3px 8px", flex: 1, wordBreak: "break-all" }}>
                          {resp.text}
                        </span>
                        <span style={{ fontSize: 9, fontWeight: 700, color: typeColor[resp.type], background: `${typeColor[resp.type]}15`, border: `1px solid ${typeColor[resp.type]}30`, borderRadius: 4, padding: "2px 6px", whiteSpace: "nowrap", flexShrink: 0, marginTop: 2 }}>
                          {typeLabel[resp.type]}
                        </span>
                      </div>
                    </div>

                    
                    {!isLast && <div style={{ height: 1, background: "rgba(30,41,59,0.5)", margin: "2px 0" }} />}
                  </div>
                );
              })}

              
              <div style={{ marginTop: 4, padding: "6px 10px", background: "rgba(220,38,38,0.06)", border: "1px solid rgba(220,38,38,0.2)", borderRadius: 6, display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 5, height: 5, borderRadius: "50%", background: C.red, display: "inline-block" }} />
                <span style={{ fontSize: 10, color: C.red, fontWeight: 600, fontFamily: "ui-monospace,monospace" }}>
                  IP {ip} — FINGERPRINTED & BLACKLISTED — {events.length} trap exchanges logged
                </span>
              </div>
            </div>

          </div>
        ))}
      </div>
    </Card>
  );
}

function ThreatProfileModal({ profile, logs, onClose, onBlock, blacklist }) {
  if (!profile) return null;

  const ip          = profile.source;
  const isBlocked   = blacklist.includes(ip);
  const ipLogs      = logs.filter(l => l.source === ip).slice(-10).reverse();
  const actor       = THREAT_ACTORS.find(a => a.match({ country: profile.level === "CRITICAL" ? "Russia" : "", features: [profile.count * 100, 0, profile.count * 500, 0, 0, 0, 0.08, 0, 1, 0], attack_type: (profile.attack_types || [])[0] || "" }, null));
  const stage       = getKillChainStage((profile.attack_types || [])[0] || "");
  const nextStage   = stage ? getNextStage(stage) : null;
  const tools       = profile.scanners || [];

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(2,6,23,0.85)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}
      onClick={onClose}>
      <div style={{ background: "#0a1628", border: `1px solid ${C.border}`, borderRadius: 16, width: "100%", maxWidth: 640, maxHeight: "85vh", overflowY: "auto", position: "relative" }}
        onClick={e => e.stopPropagation()}>

       
        <div style={{ padding: "16px 20px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: levelColor(profile.level), boxShadow: `0 0 8px ${levelColor(profile.level)}` }} />
            <span style={{ fontSize: 13, fontWeight: 700, color: C.textPrimary, letterSpacing: "0.04em" }}>THREAT PROFILE</span>
            <span style={{ fontSize: 10, fontWeight: 600, color: levelColor(profile.level), background: `${levelColor(profile.level)}15`, border: `1px solid ${levelColor(profile.level)}40`, borderRadius: 5, padding: "2px 7px" }}>
              {profile.level}
            </span>
          </div>
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: C.textDim, fontSize: 18, cursor: "pointer", lineHeight: 1 }}>✕</button>
        </div>

        <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 16 }}>

          
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {[
              ["IP Address",    ip,                              "ui-monospace,monospace", C.textPrimary],
              ["Threat Score",  profile.threat_score,           null, C.red],
              ["Total Hits",    profile.count,                  null, C.orange],
              ["Avg Risk",      `${profile.avg_risk}%`,         null, riskColor(profile.avg_risk)],
              ["Status",        isBlocked ? "BLOCKED" : profile.is_active ? "ACTIVE NOW" : "Inactive", null, isBlocked ? C.red : profile.is_active ? C.green : C.textMuted],
              ["Attack Types",  (profile.attack_types || []).join(", ") || "—", null, C.textSecondary],
            ].map(([label, value, ff, color]) => (
              <div key={label} style={{ background: C.cardBg2, borderRadius: 8, padding: "10px 14px" }}>
                <div style={{ fontSize: 10, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 13, fontWeight: 600, color, fontFamily: ff || "inherit", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(value)}</div>
              </div>
            ))}
          </div>

          
          {tools.length > 0 && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Tools Detected</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {tools.map(t => (
                  <span key={t} style={{ fontSize: 11, fontWeight: 600, color: C.red, background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: 6, padding: "3px 10px" }}>⚠ {t}</span>
                ))}
              </div>
            </div>
          )}

          {stage && (
            <div style={{ padding: "12px 14px", background: "rgba(251,191,36,0.06)", border: `1px solid rgba(251,191,36,0.2)`, borderRadius: 10 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.yellow, letterSpacing: "0.08em", marginBottom: 8 }}>MITRE ATT&CK KILL CHAIN</div>
              <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                {["Reconnaissance","Exploitation","C2 Channel","Exfiltration","Impact"].map((s, i) => {
                  const isActive = s === stage;
                  const isPast   = ["Reconnaissance","Exploitation","C2 Channel","Exfiltration","Impact"].indexOf(s) < ["Reconnaissance","Exploitation","C2 Channel","Exfiltration","Impact"].indexOf(stage);
                  return (
                    <React.Fragment key={s}>
                      <span style={{ fontSize: 9, fontWeight: 600, padding: "2px 7px", borderRadius: 4,
                        color: isActive ? "#020617" : isPast ? C.yellow : C.textDim,
                        background: isActive ? C.yellow : isPast ? "rgba(251,191,36,0.15)" : "transparent",
                        border: `1px solid ${isActive ? C.yellow : isPast ? "rgba(251,191,36,0.3)" : C.border}` }}>
                        {s}
                      </span>
                      {i < 4 && <span style={{ fontSize: 9, color: C.textDim }}>→</span>}
                    </React.Fragment>
                  );
                })}
              </div>
              {nextStage && <div style={{ fontSize: 10, color: C.textMuted, marginTop: 6 }}>Next likely: <span style={{ color: C.red, fontWeight: 600 }}>{nextStage}</span></div>}
            </div>
          )}

          
          {actor && (
            <div style={{ padding: "12px 14px", background: `${actor.color}0d`, border: `1px solid ${actor.color}40`, borderRadius: 10, display: "flex", alignItems: "flex-start", gap: 10 }}>
              <span style={{ fontSize: 18, flexShrink: 0 }}>{actor.flag}</span>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: actor.color, marginBottom: 4 }}>THREAT ACTOR: {actor.name}</div>
                <div style={{ fontSize: 11, color: C.textMuted }}>{actor.desc}</div>
              </div>
            </div>
          )}

          
          {ipLogs.length > 0 && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Attack History</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {ipLogs.map((l, i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "70px 1fr 60px", alignItems: "center", gap: 8, padding: "6px 10px", background: C.cardBg2, borderRadius: 6 }}>
                    <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 10, color: C.textDim }}>{formatTs(l.timestamp)}</span>
                    <span style={{ fontSize: 11, color: C.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{l.attack_type || "—"}</span>
                    <span style={{ fontSize: 11, fontWeight: 700, color: riskColor(l.risk || 0), textAlign: "right" }}>risk={l.risk || 0}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

         
          <div style={{ display: "flex", gap: 10, paddingTop: 4 }}>
            <button onClick={() => { onBlock(ip); onClose(); }} disabled={isBlocked}
              style={{ flex: 1, padding: "10px", borderRadius: 8, border: `1px solid ${isBlocked ? C.border : C.redDeep}`, color: isBlocked ? C.textDim : C.red, background: "transparent", cursor: isBlocked ? "default" : "pointer", fontSize: 13, fontWeight: 600 }}>
              {isBlocked ? "Already Blocked" : "Block IP"}
            </button>
            <button onClick={onClose}
              style={{ flex: 1, padding: "10px", borderRadius: 8, border: `1px solid ${C.border}`, color: C.textSecondary, background: "transparent", cursor: "pointer", fontSize: 13 }}>
              Close
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}

function ZeroTrustModal({ ip, onClose }) {
  const [data, setData] = React.useState(null);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    if (!ip) return;
    fetch(`http://127.0.0.1:8000/trust-score/${ip}`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [ip]);

  if (!ip) return null;

  const verdictColor = {
    TRUSTED:    C.green,
    MONITOR:    C.blue,
    SUSPICIOUS: C.yellow,
    DENY:       C.red,
  };

  const factorColor = (v) => v < 0 ? C.red : C.green;

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(2,6,23,0.9)", zIndex: 2000,
      display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}
      onClick={onClose}>
      <div style={{ background: "#0a1628", border: `1px solid ${C.border}`, borderRadius: 16,
        width: "100%", maxWidth: 500, position: "relative" }}
        onClick={e => e.stopPropagation()}>

        
        <div style={{ padding: "16px 20px", borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 16 }}>🛡</span>
            <span style={{ fontSize: 13, fontWeight: 700, color: C.textPrimary, letterSpacing: "0.04em" }}>ZERO TRUST SCORE CARD</span>
          </div>
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: C.textDim, fontSize: 18, cursor: "pointer" }}>✕</button>
        </div>

        <div style={{ padding: "16px 20px" }}>
          {loading ? (
            <div style={{ padding: "2rem", textAlign: "center", color: C.textDim, fontSize: 13 }}>Analyzing...</div>
          ) : !data ? (
            <div style={{ padding: "2rem", textAlign: "center", color: C.textDim, fontSize: 13 }}>No data available</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

              
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 15, fontWeight: 700, color: C.textPrimary }}>{data.ip}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: verdictColor[data.verdict] || C.textMuted,
                  background: `${verdictColor[data.verdict]}15`, border: `1px solid ${verdictColor[data.verdict]}40`,
                  borderRadius: 8, padding: "4px 12px", letterSpacing: "0.06em" }}>
                  {data.verdict}
                </span>
              </div>

              
              <div style={{ display: "flex", alignItems: "center", gap: 20, padding: "12px 16px",
                background: C.cardBg2, borderRadius: 10, border: `1px solid ${C.border}` }}>
                <div style={{ position: "relative", width: 80, height: 80, flexShrink: 0 }}>
                  <svg viewBox="0 0 80 80" width="80" height="80">
                    <circle cx="40" cy="40" r="32" fill="none" stroke={C.border} strokeWidth="8" />
                    <circle cx="40" cy="40" r="32" fill="none"
                      stroke={verdictColor[data.verdict] || C.blue}
                      strokeWidth="8"
                      strokeDasharray={`${(data.final_score / 100) * 201} 201`}
                      strokeLinecap="round"
                      transform="rotate(-90 40 40)"
                    />
                    <text x="40" y="44" textAnchor="middle" fill={verdictColor[data.verdict]} fontSize="16" fontWeight="700">{data.final_score}</text>
                  </svg>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 10, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>Trust Breakdown</div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                    <span style={{ color: C.textMuted }}>Base Score</span>
                    <span style={{ color: C.green, fontWeight: 600 }}>100</span>
                  </div>
                  {(data.factors || []).map((f, i) => (
                    <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 3 }}>
                      <span style={{ color: C.textMuted }}>{f.factor}</span>
                      <span style={{ color: factorColor(f.value), fontWeight: 600 }}>{f.value > 0 ? `+${f.value}` : f.value}</span>
                    </div>
                  ))}
                  <div style={{ height: 1, background: C.border, margin: "6px 0" }} />
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, fontWeight: 700 }}>
                    <span style={{ color: C.textSecondary }}>Final Score</span>
                    <span style={{ color: verdictColor[data.verdict] }}>{data.final_score}/100</span>
                  </div>
                </div>
              </div>

             
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 2 }}>
                  Factor Analysis
                </div>
                {(data.factors || []).map((f, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "7px 10px",
                    background: f.value < 0 ? "rgba(248,113,113,0.06)" : "rgba(34,197,94,0.06)",
                    border: `1px solid ${f.value < 0 ? "rgba(248,113,113,0.2)" : "rgba(34,197,94,0.2)"}`,
                    borderRadius: 7 }}>
                    <span style={{ fontSize: 12 }}>{f.value < 0 ? "⚠" : "✓"}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 11, fontWeight: 600, color: factorColor(f.value) }}>{f.factor}</div>
                      <div style={{ fontSize: 10, color: C.textDim }}>{f.reason}</div>
                    </div>
                    <span style={{ fontSize: 13, fontWeight: 700, color: factorColor(f.value), minWidth: 30, textAlign: "right" }}>
                      {f.value > 0 ? `+${f.value}` : f.value}
                    </span>
                  </div>
                ))}
                {(data.factors || []).length === 0 && (
                  <div style={{ fontSize: 12, color: C.textDim, padding: "8px 10px" }}>No risk factors detected — IP appears clean</div>
                )}
              </div>

             
              <div style={{ display: "flex", gap: 12, fontSize: 11 }}>
                <div style={{ flex: 1, padding: "8px 12px", background: C.cardBg2, borderRadius: 7, border: `1px solid ${C.border}` }}>
                  <div style={{ color: C.textDim, marginBottom: 3 }}>Country</div>
                  <div style={{ color: C.textSecondary, fontWeight: 600 }}>{data.geo?.country || "Unknown"}</div>
                </div>
                <div style={{ flex: 1, padding: "8px 12px", background: C.cardBg2, borderRadius: 7, border: `1px solid ${C.border}` }}>
                  <div style={{ color: C.textDim, marginBottom: 3 }}>ISP</div>
                  <div style={{ color: C.textSecondary, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{data.geo?.isp || "Unknown"}</div>
                </div>
                <div style={{ flex: 1, padding: "8px 12px", background: C.cardBg2, borderRadius: 7, border: `1px solid ${C.border}` }}>
                  <div style={{ color: C.textDim, marginBottom: 3 }}>Status</div>
                  <div style={{ color: data.blacklisted ? C.red : C.green, fontWeight: 600 }}>{data.blacklisted ? "Blacklisted" : "Active"}</div>
                </div>
              </div>

              <button onClick={onClose} style={{ padding: "10px", borderRadius: 8, border: `1px solid ${C.border}`,
                color: C.textSecondary, background: "transparent", cursor: "pointer", fontSize: 13 }}>
                Close
              </button>

            </div>
          )}
        </div>
      </div>
    </div>
  );
}


export default function HoneypotPanel() {
  const [logs, setLogs]           = useState([]);
  const [profiles, setProfiles]   = useState([]);
  const [sessions, setSessions]   = useState([]);
  const [blacklist, setBlacklist] = useState([]);
  const [trapStats, setTrapStats] = useState([]);
  const [expandedLog, setExpandedLog] = useState(null);
  const [selectedAttacker, setSelectedAttacker] = useState(null);
  const [zeroTrustIP, setZeroTrustIP]           = useState(null);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [r1, r2] = await Promise.all([
          fetch(`${BASE_URL}/honeypot/logs`),
          fetch(`${BASE_URL}/honeypot/blacklist`),
        ]);
        const d1 = await r1.json(), d2 = await r2.json();
        setLogs((d1.logs || []).slice().reverse());
        setProfiles(d1.profiles || []);
        setSessions(d1.sessions || []);
        setBlacklist(d2.blocked_ips || []);
        const rawStats = d1.trap_stats || {};
        setTrapStats(Object.entries(rawStats).map(([name, hits]) => ({ name, hits })).sort((a,b) => b.hits - a.hits));
      } catch (err) { console.error("Honeypot fetch failed:", err); }
    };
    fetchAll();
    const id = setInterval(fetchAll, 3000);
    return () => clearInterval(id);
  }, []);

  const topAttackers = [...profiles].sort((a, b) => b.count - a.count).slice(0, 6);
  const highRisk     = logs.filter(l => (l.risk || 0) >= 70).length;
  const flowStatus   = deriveFlowStatus(logs);

  const blockIP = async (ip) => {
    try {
      await fetch(`${BASE_URL}/honeypot/block`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip }) });
      setBlacklist(prev => [...new Set([...prev, ip])]);
    } catch (err) { console.error("Block failed:", err); }
  };

  return (
    <>
      <style>{`
        @keyframes hp-pulse       { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes af-slide       { from{transform:translateX(-100%)} to{transform:translateX(300%)} }
        @keyframes af-flash       { from{transform:translateX(-100%)} to{transform:translateX(300%)} }
        @keyframes af-ping-green  { 0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,.5)}  60%{box-shadow:0 0 0 7px rgba(34,197,94,0)} }
        @keyframes af-ping-yellow { 0%,100%{box-shadow:0 0 0 0 rgba(251,191,36,.5)} 60%{box-shadow:0 0 0 7px rgba(251,191,36,0)} }
        @keyframes af-ping-red    { 0%,100%{box-shadow:0 0 0 0 rgba(248,113,113,.6)} 50%{box-shadow:0 0 0 9px rgba(248,113,113,0)} }
        @keyframes af-bg-attack   { 0%,100%{opacity:0} 50%{opacity:1} }
        .af-track-slide  { animation: af-slide 1.4s linear infinite; }
        .af-track-flash  { animation: af-flash 0.45s linear infinite; }
        .af-pulse-green  { animation: af-ping-green  2s ease-in-out infinite; }
        .af-pulse-yellow { animation: af-ping-yellow 1.4s ease-in-out infinite; }
        .af-pulse-red    { animation: af-ping-red    0.65s ease-in-out infinite; }
        .af-bg-attack    { animation: af-bg-attack   0.7s ease-in-out infinite; }
        .hp-row:hover    { background: rgba(255,255,255,0.025) !important; }
        .hp-atk:hover    { background: rgba(255,255,255,0.04)  !important; }
        .hp-sess:hover   { border-color: #334155 !important; }
        .hp-block-btn:hover:not(:disabled) { background: rgba(220,38,38,0.14) !important; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
      `}</style>

      <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

        
        {zeroTrustIP && <ZeroTrustModal ip={zeroTrustIP} onClose={() => setZeroTrustIP(null)} />}

        
        {selectedAttacker && (
          <ThreatProfileModal
            profile={selectedAttacker}
            logs={logs}
            blacklist={blacklist}
            onClose={() => setSelectedAttacker(null)}
            onBlock={(ip) => { blockIP(ip); setSelectedAttacker(null); }}
          />
        )}

       
        <AttackFlow status={flowStatus} />

        
        {trapStats.length > 0 && (
          <Card>
            <CardHeader
              left={<SectionLabel>Trap Activity</SectionLabel>}
              right={<span style={{ fontSize: 12, color: C.textMuted }}>{trapStats.reduce((s,t) => s + t.hits, 0)} total hits</span>}
            />
            <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 10 }}>
              {trapStats.map((t, i) => {
                const maxHits = trapStats[0]?.hits || 1;
                const pct     = Math.round((t.hits / maxHits) * 100);
                const colors  = [C.red, C.orange, C.yellow, C.blue, C.green, C.purple];
                const col     = colors[i % colors.length];
                return (
                  <div key={t.name} style={{ display: "grid", gridTemplateColumns: "180px 1fr 48px", alignItems: "center", gap: 12 }}>
                    <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 12, color: C.textSecondary, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {t.name}
                    </span>
                    <div style={{ height: 6, borderRadius: 99, background: C.border, overflow: "hidden" }}>
                      <div style={{ width: `${pct}%`, height: "100%", background: col, borderRadius: 99, transition: "width 0.5s ease" }} />
                    </div>
                    <span style={{ fontSize: 12, fontWeight: 700, color: col, textAlign: "right" }}>{t.hits}</span>
                  </div>
                );
              })}
            </div>
          </Card>
        )}

        
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14 }}>
          <MetricCard label="Total Events"    value={logs.length}      sub="All time" />
          <MetricCard label="Active Sessions" value={sessions.length}  sub="Live attackers"
            valueColor={sessions.length > 0 ? C.blue : C.textPrimary}
            accentBorder={sessions.length > 0 ? C.blueBorder : undefined} />
          <MetricCard label="High Risk"       value={highRisk}         sub="Risk ≥ 70"
            valueColor={highRisk > 0 ? C.red : C.textPrimary}
            accentBorder={highRisk > 0 ? C.redBorder : undefined} />
          <MetricCard label="Blocked IPs"     value={blacklist.length} sub="Blacklisted"
            valueColor={blacklist.length > 0 ? C.yellow : C.textPrimary}
            accentBorder={blacklist.length > 0 ? C.yellowBorder : undefined} />
        </div>

        {profiles.length > 0 && <IntentClassifierPanel profiles={profiles} logs={logs} />}

        
        {profiles.length > 0 && <AttackerDNAPanel profiles={profiles} logs={logs} />}

        
        <div style={{ display: "grid", gridTemplateColumns: "1fr 380px", gap: 20 }}>
          <Card>
            <CardHeader left={<SectionLabel>Activity Timeline</SectionLabel>} right={<LiveBadge />} />
            <div style={{ padding: "16px 20px" }}>
              <TimelineCanvas logs={logs} />
              <div style={{ display: "flex", gap: 20, marginTop: 10 }}>
                {[["#22c55e","Low"],["#f59e0b","Medium"],["#ef4444","High"]].map(([col,lbl]) => (
                  <div key={lbl} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: C.textMuted }}>
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: col, display: "inline-block" }} />{lbl}
                  </div>
                ))}
                <span style={{ marginLeft: "auto", fontSize: 11, color: C.textDim }}>Last 5 min</span>
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader
              left={<SectionLabel>Top Attackers</SectionLabel>}
              right={topAttackers.length > 0 ? <div style={{ display: "flex", alignItems: "center", gap: 8 }}><span style={{ fontSize: 10, color: C.textDim }}>Click to profile</span><span style={{ fontSize: 12, color: C.textMuted }}>{topAttackers.length} IPs</span></div> : null}
            />
            <div style={{ padding: "12px 14px" }}>
              {topAttackers.length === 0 ? (
                <div style={{ padding: "2rem", textAlign: "center", fontSize: 13, color: C.textDim }}>No attackers detected</div>
              ) : (
                <>
                  <div style={{ display: "grid", gridTemplateColumns: "24px 1fr 52px 76px", padding: "0 8px 8px", gap: 6, fontSize: 10, color: C.textDim, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", borderBottom: `1px solid ${C.border}`, marginBottom: 4 }}>
                    <span>#</span><span>IP Address</span><span style={{ textAlign: "center" }}>Hits</span><span style={{ textAlign: "right" }}>Level</span>
                  </div>
                  {topAttackers.map((p, i) => (
                    <div key={i} className="hp-atk" onClick={() => setSelectedAttacker(p)} style={{ display: "grid", gridTemplateColumns: "24px 1fr 52px 76px", alignItems: "center", padding: "8px", borderRadius: 8, gap: 6, transition: "background 0.15s", cursor: "pointer" }}>
                      <span style={{ fontSize: 11, color: C.textDim }}>{i + 1}</span>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, overflow: "hidden" }}>
                        {p.is_active && <LiveDot />}
                        <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 12, color: p.is_suspicious ? C.red : C.textSecondary, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.source}</span>
                        {p.is_suspicious && <StatusBadge variant="red">Risk</StatusBadge>}
                      </div>
                      <span style={{ textAlign: "center", fontSize: 13, color: C.textPrimary, fontWeight: 700 }}>{p.count}</span>
                      <span style={{ textAlign: "right", fontSize: 11, fontWeight: 600, color: levelColor(p.level) }}>{p.level}</span>
                    </div>
                  ))}
                </>
              )}
            </div>
          </Card>
        </div>

       
        <Card>
          <CardHeader
            left={<SectionLabel>Attack Origins</SectionLabel>}
            right={
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, display: "inline-block", boxShadow: `0 0 5px ${C.green}`, animation: "hp-pulse 1.5s infinite" }} />
                <LiveBadge />
              </div>
            }
          />
          <div style={{ padding: 16, height: 380 }}>
            <HoneypotMap logs={logs} />
          </div>
        </Card>

        
        <ConversationLog logs={logs} />

       
        <Card>
          <CardHeader
            left={<SectionLabel>Attack Sessions</SectionLabel>}
            right={sessions.length > 0 ? <span style={{ fontSize: 12, color: C.textMuted }}>{sessions.length} active</span> : null}
          />
          <div style={{ padding: 16 }}>
            {sessions.length === 0 ? (
              <div style={{ padding: "2rem", textAlign: "center", fontSize: 13, color: C.textDim }}>No session data</div>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 14 }}>
                {sessions.map((s, i) => {
                  const blocked = blacklist.includes(s.source);
                  const score = Math.round(s.count * 5 + s.avg_risk);
                  return (
                    <div key={i} className="hp-sess" style={{ background: C.cardBg2, border: `1px solid ${C.border}`, borderRadius: 12, padding: 16, transition: "border-color 0.2s" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, paddingBottom: 10, borderBottom: `1px solid ${C.border}` }}>
                        <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 13, fontWeight: 600, color: C.textPrimary }}>{s.source}</span>
                        {blocked ? <StatusBadge variant="red">Blocked</StatusBadge> : <StatusBadge variant="gray">Active</StatusBadge>}
                      </div>
                      {[["Attacks", s.count, null], ["Avg Risk", s.avg_risk, riskColor(s.avg_risk)], ["Pattern", s.pattern || "—", C.textMuted], ["Threat Score", score, C.red]].map(([lbl, val, col]) => (
                        <div key={lbl} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "5px 0", fontSize: 13 }}>
                          <span style={{ color: C.textMuted }}>{lbl}</span>
                          <span style={{ color: col || C.textSecondary, fontWeight: col ? 600 : 400 }}>{val}</span>
                        </div>
                      ))}
                      <div style={{ marginTop: 14, textAlign: "right" }}>
                        <button className="hp-block-btn" onClick={() => blockIP(s.source)} disabled={blocked} style={{ fontSize: 11, fontWeight: 600, padding: "5px 14px", borderRadius: 7, cursor: blocked ? "default" : "pointer", border: `1px solid ${blocked ? C.border : C.redDeep}`, color: blocked ? C.textDim : C.red, background: "transparent", transition: "background 0.15s", letterSpacing: "0.04em" }}>
                          {blocked ? "Blocked" : "Block IP"}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </Card>

        
        <Card>
          <CardHeader
            left={<SectionLabel>Honeypot Logs</SectionLabel>}
            right={
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 10, color: C.textMuted }}>Click row to inspect</span>
                <span style={{ fontSize: 12, color: C.textMuted }}>{logs.length} events</span>
              </div>
            }
          />
          <div style={{ maxHeight: 400, overflowY: "auto" }}>
            
            <div style={{ display: "grid", gridTemplateColumns: "100px 1fr 1.6fr 60px 90px 28px", padding: "10px 20px", borderBottom: `1px solid ${C.border}`, gap: 8 }}>
              {["Time","IP Address","Attack Type","Risk","Status",""].map((h, i) => (
                <span key={i} style={{ fontSize: 10, fontWeight: 600, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.06em", textAlign: i >= 3 ? "right" : "left" }}>{h}</span>
              ))}
            </div>

            {logs.length === 0 ? (
              <div style={{ padding: "2rem", textAlign: "center", fontSize: 13, color: C.textDim }}>No activity</div>
            ) : logs.slice(0, 80).map((log, i) => {
              const r        = log.risk || 0;
              const isOpen   = expandedLog === i;
              const hasFp    = !!log.fingerprint;

              return (
                <div key={i} style={{ borderBottom: `1px solid rgba(30,41,59,0.6)` }}>
                  
                  <div
                    className="hp-row"
                    onClick={() => setExpandedLog(isOpen ? null : i)}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "100px 1fr 1.6fr 60px 90px 28px",
                      alignItems: "center",
                      padding: "10px 20px",
                      gap: 8,
                      cursor: "pointer",
                      transition: "background 0.15s",
                      background: isOpen ? "rgba(255,255,255,0.03)" : undefined,
                    }}
                  >
                    <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 11, color: C.textDim }}>{formatTs(log.timestamp)}</span>
                    <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 12, color: C.textSecondary, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{log.source}</span>
                    <span style={{ fontSize: 13, color: C.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "flex", alignItems: "center", gap: 6 }}>
                      {log.attack_type}
                      {log.is_deception && <StatusBadge variant="yellow">Deception</StatusBadge>}
                      {log.fingerprint?.scanner && <StatusBadge variant="red">Scanner</StatusBadge>}
                      {log.escalation_stage && (
                        <span style={{
                          fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4,
                          color: log.escalation_stage >= 4 ? "#f87171" : log.escalation_stage === 3 ? "#fb923c" : log.escalation_stage === 2 ? "#fbbf24" : "#22c55e",
                          background: log.escalation_stage >= 4 ? "rgba(248,113,113,0.1)" : "rgba(251,191,36,0.08)",
                          border: `1px solid ${log.escalation_stage >= 4 ? "rgba(248,113,113,0.3)" : "rgba(251,191,36,0.2)"}`,
                          whiteSpace: "nowrap",
                        }}>
                          {log.escalation_stage >= 4 ? " TERMINATED" : `Stage ${log.escalation_stage} — ${log.escalation_info?.stage || ""}`}
                        </span>
                      )}
                    </span>
                    <span style={{ textAlign: "right", fontWeight: 700, fontSize: 13, color: riskColor(r) }}>{r}</span>
                    <div style={{ textAlign: "right" }}><StatusBadge variant={r >= 70 ? "red" : r >= 40 ? "yellow" : "green"}>{riskLabel(r)}</StatusBadge></div>
                    
                    <div style={{ display: "flex", alignItems: "center", gap: 6, justifyContent: "flex-end" }}>
                      <span onClick={(e) => { e.stopPropagation(); setZeroTrustIP(log.source); }}
                        style={{ fontSize: 9, fontWeight: 600, color: C.blue, background: C.blueBg,
                          border: `1px solid ${C.blueBorder}`, borderRadius: 4, padding: "2px 5px",
                          cursor: "pointer", whiteSpace: "nowrap" }}>
                        🛡 Trust
                      </span>
                      <span style={{ fontSize: 10, color: C.textMuted, transition: "transform 0.2s", display: "inline-block", transform: isOpen ? "rotate(180deg)" : "rotate(0deg)" }}>▼</span>
                    </div>
                  </div>

                  {/* Fingerprint panel */}
                  {isOpen && (
                    <FingerprintPanel fp={log.fingerprint} log={log} />
                  )}
                </div>
              );
            })}
          </div>
        </Card>

        
        <Card>
          <CardHeader
            left={<SectionLabel>Blacklisted IPs</SectionLabel>}
            right={blacklist.length > 0 ? <StatusBadge variant="red">{blacklist.length} blocked</StatusBadge> : null}
          />
          <div style={{ padding: 16 }}>
            {blacklist.length === 0 ? (
              <div style={{ padding: "1.5rem", textAlign: "center", fontSize: 13, color: C.textDim }}>No blocked IPs</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8, maxWidth: 440 }}>
                {blacklist.map((ip, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: 8 }}>
                    <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 13, color: C.textSecondary }}>{ip}</span>
                    <StatusBadge variant="red">Blocked</StatusBadge>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>

      </div>
    </>
  );
}
