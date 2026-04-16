"use client";

const C = {
  cardBg2:       "#0f172a",
  border:        "#1e293b",
  textPrimary:   "#ffffff",
  textSecondary: "#94a3b8",
  textMuted:     "#64748b",
  textDim:       "#475569",
  red:           "#f87171",
  redBg:         "rgba(220,38,38,0.10)",
  redBorder:     "rgba(220,38,38,0.25)",
  orange:        "#fb923c",
  orangeBg:      "rgba(251,146,60,0.08)",
  orangeBorder:  "rgba(251,146,60,0.2)",
  green:         "#22c55e",
  greenBg:       "rgba(34,197,94,0.08)",
  greenBorder:   "rgba(34,197,94,0.2)",
};

const RANK_COLORS = ["#f59e0b", "#94a3b8", "#b45309"];

export default function TopAttackers({ alerts }) {
  const attackMap = {};

  (alerts || []).forEach((a) => {
    if (!a.source || a.action === "ALLOW") return;
    if (!attackMap[a.source]) {
      attackMap[a.source] = { count: 0, action: a.action };
    }
    attackMap[a.source].count += 1;
  });

  const top = Object.entries(attackMap)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5);

  const maxCount = top.length > 0 ? top[0][1].count : 1;

  return (
    <>
      <style>{`
        @keyframes tp-pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
        .tp-row { transition: background 0.15s, border-color 0.15s; }
        .tp-row:hover { background: rgba(255,255,255,0.04) !important; border-color: #334155 !important; }
      `}</style>

      <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: 0 }}>

        {top.length === 0 ? (
          <div style={{
            flex: 1, display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center", gap: 8,
          }}>
            <div style={{
              width: 36, height: 36, borderRadius: "50%",
              background: "rgba(100,116,139,0.1)",
              border: `1px solid ${C.border}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 16,
            }}>
              ✓
            </div>
            <span style={{ fontSize: 13, color: C.textDim }}>No threats detected</span>
          </div>
        ) : (
          <>
            
            <div style={{
              display: "grid",
              gridTemplateColumns: "32px 1fr 52px 60px",
              padding: "0 12px 8px",
              gap: 8,
              borderBottom: `1px solid ${C.border}`,
              marginBottom: 8,
            }}>
              {["#", "IP Address", "Hits", "Action"].map((h, i) => (
                <span key={h} style={{
                  fontSize: 10, fontWeight: 600, color: C.textDim,
                  textTransform: "uppercase", letterSpacing: "0.06em",
                  textAlign: i === 2 || i === 3 ? "right" : i === 0 ? "center" : "left",
                }}>
                  {h}
                </span>
              ))}
            </div>

           
            <div style={{ display: "flex", flexDirection: "column", gap: 6, overflowY: "auto" }}>
              {top.map(([ip, data], i) => {
                const isBlocked = data.action === "BLOCK";
                const barPct = (data.count / maxCount) * 100;
                const rankColor = RANK_COLORS[i] || C.textDim;

                return (
                  <div
                    key={i}
                    className="tp-row"
                    style={{
                      background: C.cardBg2,
                      border: `1px solid ${C.border}`,
                      borderRadius: 10,
                      padding: "10px 12px",
                      display: "flex",
                      flexDirection: "column",
                      gap: 8,
                    }}
                  >
                    
                    <div style={{
                      display: "grid",
                      gridTemplateColumns: "32px 1fr 52px 60px",
                      alignItems: "center",
                      gap: 8,
                    }}>
                      
                      <div style={{
                        width: 22, height: 22, borderRadius: "50%",
                        background: i < 3 ? `${rankColor}18` : "rgba(71,85,105,0.2)",
                        border: `1px solid ${i < 3 ? `${rankColor}40` : C.border}`,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontSize: 11, fontWeight: 700, color: i < 3 ? rankColor : C.textDim,
                        margin: "0 auto",
                        flexShrink: 0,
                      }}>
                        {i + 1}
                      </div>

                      
                      <span style={{
                        fontFamily: "ui-monospace,monospace",
                        fontSize: 12, fontWeight: 500,
                        color: C.textSecondary,
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      }}>
                        {ip}
                      </span>

                      
                      <span style={{
                        textAlign: "right", fontSize: 13, fontWeight: 700,
                        color: isBlocked ? C.red : C.orange,
                      }}>
                        {data.count}
                      </span>

                      
                      <div style={{ textAlign: "right" }}>
                        <span style={{
                          fontSize: 10, fontWeight: 600,
                          padding: "2px 7px", borderRadius: 5,
                          letterSpacing: "0.04em",
                          color:       isBlocked ? C.red    : C.orange,
                          background:  isBlocked ? C.redBg  : C.orangeBg,
                          border: `1px solid ${isBlocked ? C.redBorder : C.orangeBorder}`,
                        }}>
                          {data.action}
                        </span>
                      </div>
                    </div>

                    
                    <div style={{
                      height: 3, borderRadius: 99,
                      background: "rgba(255,255,255,0.05)",
                      overflow: "hidden",
                    }}>
                      <div style={{
                        height: "100%",
                        width: `${barPct}%`,
                        borderRadius: 99,
                        background: isBlocked
                          ? "linear-gradient(90deg, #dc2626, #f87171)"
                          : "linear-gradient(90deg, #ea580c, #fb923c)",
                        transition: "width 0.5s ease",
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </>
  );
}
