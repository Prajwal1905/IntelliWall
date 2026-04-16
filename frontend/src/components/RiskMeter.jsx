"use client";

const C = {
  cardBg2:  "#0f172a",
  border:   "#1e293b",
  textDim:  "#475569",
  textMuted:"#64748b",
  green:    "#22c55e",
  yellow:   "#fbbf24",
  orange:   "#fb923c",
  red:      "#f87171",
};

function getRiskConfig(risk) {
  if (risk >= 70) return { color: C.red,    label: "CRITICAL", status: "BLOCK",     trackColor: "rgba(248,113,113,0.12)" };
  if (risk >= 50) return { color: C.orange, label: "HIGH",     status: "HONEYPOT",  trackColor: "rgba(251,146,60,0.12)"  };
  if (risk >= 30) return { color: C.yellow, label: "ELEVATED", status: "CHALLENGE", trackColor: "rgba(251,191,36,0.12)"  };
  return               { color: C.green,  label: "NORMAL",   status: "SAFE",      trackColor: "rgba(34,197,94,0.12)"   };
}

export default function RiskMeter({ risk = 0 }) {
  const safeRisk = Math.max(0, Math.min(100, isNaN(risk) ? 0 : Math.round(risk)));
  const cfg      = getRiskConfig(safeRisk);

  const size   = 140;
  const cx     = size / 2;
  const cy     = size / 2;
  const R      = 52;
  const stroke = 8;
  const sweep  = 270; // degrees
  const startAngle = 135; // degrees from 3-o-clock

  function polarToCartesian(cx, cy, r, angleDeg) {
    const rad = ((angleDeg - 90) * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  }

  function arcPath(cx, cy, r, startDeg, endDeg) {
    const start   = polarToCartesian(cx, cy, r, endDeg);
    const end     = polarToCartesian(cx, cy, r, startDeg);
    const largeArc = endDeg - startDeg > 180 ? 1 : 0;
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 0 ${end.x} ${end.y}`;
  }

  const endAngle  = startAngle + sweep;
  const fillAngle = startAngle + (safeRisk / 100) * sweep;

  const trackPath = arcPath(cx, cy, R, startAngle, endAngle);
  const fillPath  = safeRisk > 0 ? arcPath(cx, cy, R, startAngle, fillAngle) : null;

  const ticks = [0, 25, 50, 75, 100].map(val => {
    const angle = startAngle + (val / 100) * sweep;
    const inner = polarToCartesian(cx, cy, R - stroke - 4, angle);
    const outer = polarToCartesian(cx, cy, R + stroke + 4, angle);
    return { inner, outer, val };
  });

  return (
    <>
      <style>{`
        @keyframes rm-fill { from { stroke-dashoffset: 1000; } }
        .rm-fill { animation: rm-fill 0.9s ease-out forwards; }
        @keyframes rm-pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
      `}</style>

      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12, width: "100%" }}>

        
        <div style={{ position: "relative", width: size, height: size }}>
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>

            
            <circle cx={cx} cy={cy} r={R + stroke + 6}
              fill="none" stroke={cfg.trackColor} strokeWidth={14} />

           
            <path d={trackPath} fill="none"
              stroke={C.border} strokeWidth={stroke}
              strokeLinecap="round" />

            
            {fillPath && (
              <path
                key={safeRisk}
                className="rm-fill"
                d={fillPath}
                fill="none"
                stroke={cfg.color}
                strokeWidth={stroke}
                strokeLinecap="round"
                style={{
                  filter: `drop-shadow(0 0 4px ${cfg.color}80)`,
                  transition: "stroke 0.4s ease",
                }}
              />
            )}

            
            {ticks.map(({ inner, outer, val }) => (
              <line key={val}
                x1={inner.x} y1={inner.y}
                x2={outer.x} y2={outer.y}
                stroke={val <= safeRisk ? cfg.color : C.border}
                strokeWidth={val === 0 || val === 100 ? 2 : 1}
                strokeLinecap="round"
                opacity={0.6}
              />
            ))}

           
            {safeRisk > 0 && (() => {
              const pt = polarToCartesian(cx, cy, R, fillAngle);
              return (
                <circle cx={pt.x} cy={pt.y} r={5}
                  fill={cfg.color}
                  stroke={C.cardBg2}
                  strokeWidth={2}
                  style={{ filter: `drop-shadow(0 0 6px ${cfg.color})` }}
                />
              );
            })()}

           
            <circle cx={cx} cy={cy} r={10}
              fill={C.cardBg2} stroke={C.border} strokeWidth={1} />
            <circle cx={cx} cy={cy} r={4}
              fill={cfg.color}
              style={{ filter: `drop-shadow(0 0 4px ${cfg.color})` }}
            />
          </svg>

          
          <div style={{
            position: "absolute", inset: 0,
            display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center",
            paddingTop: 8,
          }}>
            <span style={{
              fontSize: 26, fontWeight: 700,
              color: cfg.color, lineHeight: 1,
              transition: "color 0.4s",
              fontVariantNumeric: "tabular-nums",
            }}>
              {safeRisk}
            </span>
            <span style={{ fontSize: 10, color: C.textMuted, marginTop: 2 }}>/ 100</span>
          </div>
        </div>

        
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
          
          <div style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "4px 14px",
            background: `${cfg.color}14`,
            border: `1px solid ${cfg.color}40`,
            borderRadius: 20,
          }}>
            {safeRisk >= 70 && (
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: cfg.color, display: "inline-block", animation: "rm-pulse 0.8s ease-in-out infinite" }} />
            )}
            <span style={{ fontSize: 11, fontWeight: 700, color: cfg.color, letterSpacing: "0.08em" }}>
              {cfg.label}
            </span>
          </div>

         
          <span style={{ fontSize: 10, color: C.textDim, letterSpacing: "0.06em", fontWeight: 500 }}>
            ACTION: <span style={{ color: cfg.color }}>{cfg.status}</span>
          </span>
        </div>

        
        <div style={{ display: "flex", justifyContent: "space-between", width: "100%", padding: "0 4px" }}>
          {[
            { label: "SAFE",      color: C.green,  val: "0"   },
            { label: "CHALLENGE", color: C.yellow, val: "30"  },
            { label: "HONEYPOT",  color: C.orange, val: "50"  },
            { label: "BLOCK",     color: C.red,    val: "70"  },
          ].map(({ label, color, val }) => (
            <div key={label} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: color, display: "inline-block" }} />
              <span style={{ fontSize: 8, color: C.textDim, letterSpacing: "0.04em" }}>{label}</span>
              <span style={{ fontSize: 8, color: C.textDim }}>{val}</span>
            </div>
          ))}
        </div>

      </div>
    </>
  );
}
