"use client";

import { useEffect, useRef, useState } from "react";
import { getAlerts } from "../lib/api";

const C = {
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
  yellow:        "#fbbf24",
  yellowBg:      "rgba(251,191,36,0.08)",
  yellowBorder:  "rgba(251,191,36,0.2)",
  red:           "#f87171",
  redBg:         "rgba(220,38,38,0.10)",
  redBorder:     "rgba(220,38,38,0.25)",
  blue:          "#3b82f6",
  blueBg:        "rgba(59,130,246,0.08)",
  blueBorder:    "rgba(59,130,246,0.2)",
};

function riskColor(r) {
  if (r > 70) return C.red;
  if (r > 40) return C.yellow;
  return C.green;
}


function formatTime(ts) {
  if (!ts) return "—";
  try {
    
    const fixed = typeof ts === "string" ? ts.replace(" ", "T") : ts;
    const d = new Date(fixed);
    if (isNaN(d.getTime())) return ts.slice(11, 19) || "—"; 
    return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  } catch {
    return "—";
  }
}

function ActionBadge({ action }) {
  const map = {
    BLOCK:     { color: C.red,    bg: C.redBg,    border: C.redBorder },
    CHALLENGE: { color: C.yellow, bg: C.yellowBg, border: C.yellowBorder },
    ALLOW:     { color: C.green,  bg: C.greenBg,  border: C.greenBorder },
  };
  const s = map[action] || { color: C.textSecondary, bg: "rgba(148,163,184,0.08)", border: "rgba(148,163,184,0.18)" };
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: "2px 8px",
      borderRadius: 6, whiteSpace: "nowrap", letterSpacing: "0.05em",
      color: s.color, background: s.bg, border: `1px solid ${s.border}`,
    }}>
      {action}
    </span>
  );
}

function RiskBar({ risk }) {
  const color = riskColor(risk);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <span style={{ fontSize: 12, fontWeight: 700, color, minWidth: 32, textAlign: "right" }}>
        {Math.round(risk)}%
      </span>
      <div style={{ width: 48, height: 4, borderRadius: 99, background: C.border, overflow: "hidden", flexShrink: 0 }}>
        <div style={{ width: `${Math.min(risk, 100)}%`, height: "100%", background: color, borderRadius: 99, transition: "width 0.4s ease" }} />
      </div>
    </div>
  );
}

export default function AlertsPanel() {
  const [alerts, setAlerts]       = useState([]);
  const [latestTime, setLatestTime] = useState(null);
  const [newRow, setNewRow]        = useState(null);
  const tableRef = useRef(null);

  useEffect(() => {
    const fetchAlerts = async () => {
      const data = await getAlerts();
      if (data.length > 0) {
        if (data[0].timestamp !== latestTime) {
          setNewRow(data[0].timestamp);
          setTimeout(() => setNewRow(null), 1800);
        }
        setLatestTime(data[0].timestamp);
      }
      setAlerts(data);
    };
    fetchAlerts();
    const id = setInterval(fetchAlerts, 3000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (tableRef.current) tableRef.current.scrollTop = 0;
  }, [alerts]);

  const blocked    = alerts.filter(a => a.action === "BLOCK").length;
  const challenged = alerts.filter(a => a.action === "CHALLENGE").length;
  const allowed    = alerts.filter(a => a.action === "ALLOW").length;

  return (
    <>
      <style>{`
        @keyframes ap-flash { 0%,100%{background:rgba(220,38,38,0.0)} 30%{background:rgba(220,38,38,0.12)} }
        .ap-new { animation: ap-flash 1.8s ease-out forwards; }
        .ap-row:hover { background: rgba(255,255,255,0.025) !important; }
        .ap-scroll::-webkit-scrollbar       { width: 4px; }
        .ap-scroll::-webkit-scrollbar-track { background: transparent; }
        .ap-scroll::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
      `}</style>

      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

        
        <div style={{ display: "flex", gap: 10 }}>
          {[
            { label: "Blocked",    value: blocked,    color: C.red,    bg: C.redBg,    border: C.redBorder },
            { label: "Challenged", value: challenged, color: C.yellow, bg: C.yellowBg, border: C.yellowBorder },
            { label: "Allowed",    value: allowed,    color: C.green,  bg: C.greenBg,  border: C.greenBorder },
            { label: "Total",      value: alerts.length, color: C.blue, bg: C.blueBg,  border: C.blueBorder },
          ].map(({ label, value, color, bg, border }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 14px", background: bg, border: `1px solid ${border}`, borderRadius: 8 }}>
              <span style={{ fontSize: 15, fontWeight: 700, color }}>{value}</span>
              <span style={{ fontSize: 11, color, opacity: 0.8, fontWeight: 500, letterSpacing: "0.04em" }}>{label}</span>
            </div>
          ))}
        </div>

        
        <div ref={tableRef} className="ap-scroll" style={{ maxHeight: 320, overflowY: "auto", borderRadius: 10, border: `1px solid ${C.border}` }}>

          
          <div style={{
            display: "grid",
            gridTemplateColumns: "140px 120px 1fr 130px 90px 100px",
            padding: "10px 16px",
            background: C.cardBg2,
            borderBottom: `1px solid ${C.border}`,
            position: "sticky", top: 0, zIndex: 1,
            gap: 8,
          }}>
            {["Source IP", "Protocol", "Attack Type", "Risk", "Action", "Time"].map((h, i) => (
              <span key={h} style={{
                fontSize: 10, fontWeight: 600, color: C.textDim,
                textTransform: "uppercase", letterSpacing: "0.06em",
                textAlign: i >= 2 ? "right" : "left",
              }}>{h}</span>
            ))}
          </div>

          
          {alerts.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", fontSize: 13, color: C.textDim }}>
              No alert data
            </div>
          ) : (
            alerts.slice(0, 50).map((a, i) => {
              const isNew = a.timestamp === newRow;
              return (
                <div
                  key={i}
                  className={`ap-row${isNew ? " ap-new" : ""}`}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "140px 120px 1fr 130px 90px 100px",
                    alignItems: "center",
                    padding: "9px 16px",
                    borderBottom: `1px solid rgba(30,41,59,0.6)`,
                    gap: 8,
                    transition: "background 0.15s",
                  }}
                >
                  
                  <span style={{
                    fontFamily: "ui-monospace,monospace", fontSize: 11,
                    color: C.textSecondary,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>
                    {a.source || "—"}
                  </span>

                  =
                  <span style={{
                    fontFamily: "ui-monospace,monospace", fontSize: 11,
                    color: C.textDim,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>
                    {a.protocol}
                  </span>

                  
                  <span style={{
                    fontSize: 12, color: C.textMuted,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>
                    {a.attack_type}
                  </span>

                 
                  <div style={{ display: "flex", justifyContent: "flex-end" }}>
                    <RiskBar risk={a.risk} />
                  </div>

                  
                  <div style={{ textAlign: "right" }}>
                    <ActionBadge action={a.action} />
                  </div>

                  
                  <span style={{
                    fontFamily: "ui-monospace,monospace", fontSize: 11,
                    color: C.textDim, textAlign: "right", whiteSpace: "nowrap",
                  }}>
                    {formatTime(a.timestamp)}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </>
  );
}
