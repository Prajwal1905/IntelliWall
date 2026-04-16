"use client";

import { useEffect, useState } from "react";

const C = {
  pageBg:      "#020617",
  cardBg:      "#0a1628",
  cardBg2:     "#0f172a",
  border:      "#1e293b",
  textPrimary: "#ffffff",
  textSecondary:"#94a3b8",
  textMuted:   "#64748b",
  textDim:     "#475569",
  green:       "#22c55e",  greenBg:  "rgba(34,197,94,0.08)",   greenBorder:  "rgba(34,197,94,0.2)",
  blue:        "#60a5fa",  blueBg:   "rgba(96,165,250,0.08)",  blueBorder:   "rgba(96,165,250,0.2)",
  red:         "#f87171",  redBg:    "rgba(248,113,113,0.08)", redBorder:    "rgba(248,113,113,0.2)",
  yellow:      "#fbbf24",  yellowBg: "rgba(251,191,36,0.08)",  yellowBorder: "rgba(251,191,36,0.2)",
  cyan:        "#22d3ee",
  purple:      "#c084fc",
};

function formatTs(ts) {
  if (!ts) return "—";
  try {
    return new Date(ts.replace(" ", "T")).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  } catch { return "—"; }
}

export default function FederatedPanel() {
  const [data, setData] = useState(null);

  useEffect(() => {
    const fetch_ = async () => {
      try {
        const res  = await fetch("http://127.0.0.1:8000/federated/nodes");
        const json = await res.json();
        setData(json);
      } catch {}
    };
    fetch_();
    const id = setInterval(fetch_, 3000);
    return () => clearInterval(id);
  }, []);

  if (!data) return null;

  const nodes   = data.nodes || [];
  const threats = data.shared_threats || [];
  const latest  = threats[threats.length - 1];

  return (
    <>
      <style>{`
        @keyframes fed-pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes fed-slide { from{opacity:0;transform:translateY(-6px)} to{opacity:1;transform:translateY(0)} }
        .fed-row:hover { background: rgba(255,255,255,0.025) !important; }
      `}</style>

      <div style={{ background: C.cardBg, border: `1px solid ${C.border}`, borderRadius: 14, overflow: "hidden" }}>
=
        <div style={{ padding: "14px 20px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 16 }}>🌐</span>
            <p style={{ fontSize: 13, fontWeight: 600, color: C.textSecondary, textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
              Federated Threat Network
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 11, color: C.green, background: C.greenBg, border: `1px solid ${C.greenBorder}`, borderRadius: 6, padding: "2px 8px", fontWeight: 500 }}>
              {nodes.filter(n => n.status === "online").length} Nodes Online
            </span>
            <span style={{ fontSize: 11, color: C.blue, background: C.blueBg, border: `1px solid ${C.blueBorder}`, borderRadius: 6, padding: "2px 8px", fontWeight: 500 }}>
              {data.total_shared || 0} Threats Shared
            </span>
          </div>
        </div>

        <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>

          <div style={{ fontSize: 11, color: C.textDim, padding: "8px 12px", background: "rgba(96,165,250,0.04)", border: `1px solid ${C.blueBorder}`, borderRadius: 8, lineHeight: 1.6 }}>
            When IntelliWall blocks a high-risk attacker, threat intel is instantly shared to all federated nodes.
            Every node pre-blocks the IP — attacker is stopped globally before reaching other deployments.
          </div>

          
          <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
            {nodes.map((node, i) => (
              <div key={node.id} style={{
                background: i === 0 ? "rgba(34,197,94,0.06)" : C.cardBg2,
                border: `1px solid ${i === 0 ? C.greenBorder : C.border}`,
                borderRadius: 10, padding: "12px 14px",
                position: "relative",
              }}>
               
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, display: "inline-block", boxShadow: `0 0 5px ${C.green}`, animation: "fed-pulse 2s infinite" }} />
                  <span style={{ fontSize: 9, color: C.green, fontWeight: 600, letterSpacing: "0.04em" }}>ONLINE</span>
                  {i === 0 && <span style={{ fontSize: 8, color: C.blue, fontWeight: 700, marginLeft: "auto", background: C.blueBg, border: `1px solid ${C.blueBorder}`, borderRadius: 3, padding: "1px 4px" }}>PRIMARY</span>}
                </div>

                <div style={{ fontSize: 12, fontWeight: 700, color: C.textPrimary, marginBottom: 2 }}>{node.name}</div>
                <div style={{ fontSize: 10, color: C.textDim, marginBottom: 10 }}>{node.location}</div>

                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10 }}>
                    <span style={{ color: C.textDim }}>Shared</span>
                    <span style={{ color: C.green, fontWeight: 600 }}>{node.threats_shared}</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10 }}>
                    <span style={{ color: C.textDim }}>Received</span>
                    <span style={{ color: C.blue, fontWeight: 600 }}>{node.threats_received}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>

         
          {latest && (
            <div style={{ padding: "12px 16px", background: "rgba(34,197,94,0.06)", border: `1px solid ${C.greenBorder}`, borderRadius: 10, animation: "fed-slide 0.4s ease-out" }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.green, letterSpacing: "0.08em", marginBottom: 8 }}>
                 LATEST THREAT SHARED
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 13, fontWeight: 700, color: C.textPrimary }}>{latest.source_ip}</span>
                <span style={{ fontSize: 11, color: C.red, background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: 5, padding: "2px 8px" }}>risk {latest.risk}</span>
                <span style={{ fontSize: 11, color: C.textMuted }}>{latest.country}</span>
                <span style={{ fontSize: 11, color: C.textDim }}>{latest.attack_type}</span>
                <span style={{ marginLeft: "auto", fontSize: 10, color: C.textDim }}>{formatTs(latest.timestamp)}</span>
              </div>
              <div style={{ marginTop: 8, fontSize: 11, color: C.textMuted }}>
                Shared from <span style={{ color: C.green, fontWeight: 600 }}>{latest.shared_from}</span> →
                pre-blocked on <span style={{ color: C.blue, fontWeight: 600 }}>{latest.shared_to?.join(", ")}</span>
                <span style={{ color: C.yellow, fontWeight: 600 }}> ({latest.pre_blocked} nodes protected)</span>
              </div>
            </div>
          )}

          
          {threats.length > 0 && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>
                Threat Intel Feed
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 0, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
                {/* Table header */}
                <div style={{ display: "grid", gridTemplateColumns: "80px 130px 60px 1fr 100px", padding: "8px 14px", background: "rgba(0,0,0,0.2)", gap: 8 }}>
                  {["Time","IP","Risk","Shared To","Attack"].map((h, i) => (
                    <span key={h} style={{ fontSize: 9, fontWeight: 700, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</span>
                  ))}
                </div>
                {[...threats].reverse().slice(0, 8).map((t, i) => (
                  <div key={i} className="fed-row" style={{ display: "grid", gridTemplateColumns: "80px 130px 60px 1fr 100px", padding: "8px 14px", borderTop: `1px solid rgba(30,41,59,0.5)`, gap: 8, alignItems: "center", transition: "background 0.15s" }}>
                    <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 10, color: C.textDim }}>{formatTs(t.timestamp)}</span>
                    <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 11, color: C.textSecondary }}>{t.source_ip}</span>
                    <span style={{ fontSize: 11, fontWeight: 700, color: t.risk >= 70 ? C.red : C.yellow }}>{t.risk}</span>
                    <span style={{ fontSize: 10, color: C.blue, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {t.shared_to?.join(", ")}
                    </span>
                    <span style={{ fontSize: 10, color: C.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.attack_type}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {threats.length === 0 && (
            <div style={{ padding: "1.5rem", textAlign: "center", fontSize: 13, color: C.textDim }}>
              Waiting for high-risk threats to share...
            </div>
          )}

        </div>
      </div>
    </>
  );
}
