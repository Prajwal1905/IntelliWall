"use client";

const C = {
  cardBg2:  "#0f172a",
  border:   "#1e293b",
  textPrimary:   "#ffffff",
  textSecondary: "#94a3b8",
  textMuted:     "#64748b",
  textDim:       "#475569",
  green:    "#22c55e",
  greenBg:  "rgba(34,197,94,0.08)",
  greenBorder: "rgba(34,197,94,0.2)",
  red:      "#f87171",
  redBg:    "rgba(248,113,113,0.08)",
  redBorder:"rgba(248,113,113,0.2)",
  yellow:   "#fbbf24",
  yellowBg: "rgba(251,191,36,0.08)",
  yellowBorder: "rgba(251,191,36,0.2)",
  blue:     "#60a5fa",
  blueBg:   "rgba(96,165,250,0.08)",
  blueBorder: "rgba(96,165,250,0.2)",
  orange:   "#fb923c",
  orangeBg: "rgba(251,146,60,0.08)",
  orangeBorder: "rgba(251,146,60,0.2)",
};

function getRiskStyle(risk) {
  if (risk >= 70) return { color: C.red,    bg: C.redBg,    border: C.redBorder,    label: "Critical" };
  if (risk >= 40) return { color: C.yellow, bg: C.yellowBg, border: C.yellowBorder, label: "Elevated" };
  return               { color: C.green,  bg: C.greenBg,  border: C.greenBorder,  label: "Normal"   };
}

function RiskArc({ risk }) {
  const clamp = Math.min(Math.max(risk, 0), 100);
  const r = 22, cx = 28, cy = 28;
  const circ = 2 * Math.PI * r;
  const dash = (clamp / 100) * circ * 0.75; // 270° arc
  const gap  = circ;
  const style = getRiskStyle(clamp);

  return (
    <svg width="56" height="56" viewBox="0 0 56 56">
      {/* Track */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.border} strokeWidth="4"
        strokeDasharray={`${circ * 0.75} ${circ}`}
        strokeDashoffset={0}
        strokeLinecap="round"
        transform="rotate(135 28 28)"
      />
      {/* Fill */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={style.color} strokeWidth="4"
        strokeDasharray={`${dash} ${gap}`}
        strokeDashoffset={0}
        strokeLinecap="round"
        transform="rotate(135 28 28)"
        style={{ transition: "stroke-dasharray 0.6s ease" }}
      />
      {/* Value */}
      <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="middle"
        fill={style.color} fontSize="11" fontWeight="700" fontFamily="ui-sans-serif,system-ui">
        {clamp}%
      </text>
    </svg>
  );
}

function MiniBar({ value, max, color }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div style={{ width: "100%", height: 3, borderRadius: 99, background: C.border, overflow: "hidden", marginTop: 8 }}>
      <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 99, transition: "width 0.5s ease" }} />
    </div>
  );
}

export default function MetricsBar({ alerts = 0, blocked = 0, risk = 0, devices = 0 }) {
  const blockRate  = alerts > 0 ? Math.round((blocked / alerts) * 100) : 0;
  const riskStyle  = getRiskStyle(risk);

  const metrics = [
    {
      label:   "Total Alerts",
      value:   alerts,
      sub:     "All events",
      color:   C.blue,
      bg:      C.blueBg,
      border:  C.blueBorder,
      icon:    "◈",
      bar:     null,
    },
    {
      label:   "Blocked",
      value:   blocked,
      sub:     `${blockRate}% block rate`,
      color:   C.red,
      bg:      C.redBg,
      border:  C.redBorder,
      icon:    "⊘",
      bar:     { value: blocked, max: alerts, color: C.red },
    },
    {
      label:   "Active Devices",
      value:   devices,
      sub:     "Live connections",
      color:   C.green,
      bg:      C.greenBg,
      border:  C.greenBorder,
      icon:    "◎",
      bar:     null,
    },
  ];

  return (
    <>
      <style>{`
        @keyframes mb-pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        .mb-pulse { animation: mb-pulse 1.8s ease-in-out infinite; }
        .mb-card:hover { border-color: #334155 !important; }
      `}</style>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 200px", gap: 14 }}>

        
        {metrics.map((m, i) => (
          <div key={i} className="mb-card" style={{
            background: C.cardBg2,
            border: `1px solid ${m.border}`,
            borderRadius: 12,
            padding: "16px 20px",
            display: "flex",
            alignItems: "center",
            gap: 14,
            transition: "border-color 0.2s",
          }}>
            
            <div style={{
              width: 42, height: 42, borderRadius: 10, flexShrink: 0,
              background: m.bg, border: `1px solid ${m.border}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18, color: m.color,
            }}>
              {m.icon}
            </div>

           
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 5 }}>
                {m.label}
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, color: m.color, lineHeight: 1 }}>
                {m.value.toLocaleString()}
              </div>
              <div style={{ fontSize: 11, color: C.textDim, marginTop: 4 }}>
                {m.sub}
              </div>
              {m.bar && <MiniBar {...m.bar} />}
            </div>
          </div>
        ))}

        
        <div className="mb-card" style={{
          background: C.cardBg2,
          border: `1px solid ${riskStyle.border}`,
          borderRadius: 12,
          padding: "16px 20px",
          display: "flex",
          alignItems: "center",
          gap: 14,
          transition: "border-color 0.2s",
        }}>
          <RiskArc risk={risk} />
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 5 }}>
              Risk Score
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              {risk >= 70 && <span className="mb-pulse" style={{ width: 6, height: 6, borderRadius: "50%", background: riskStyle.color, display: "inline-block" }} />}
              <span style={{
                fontSize: 11, fontWeight: 700, color: riskStyle.color,
                background: riskStyle.bg, border: `1px solid ${riskStyle.border}`,
                borderRadius: 6, padding: "2px 8px", letterSpacing: "0.05em",
              }}>
                {riskStyle.label}
              </span>
            </div>
            <div style={{ fontSize: 11, color: C.textDim, marginTop: 4 }}>
              System threat level
            </div>
          </div>
        </div>

      </div>
    </>
  );
}
