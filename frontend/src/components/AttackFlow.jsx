"use client";

import { useEffect, useRef } from "react";

const C = {
  cardBg:      "#0a1628",
  cardBg2:     "#0f172a",
  border:      "#1e293b",
  textPrimary: "#ffffff",
  textSecondary: "#94a3b8",
  textMuted:   "#64748b",
  textDim:     "#475569",
  green:       "#22c55e",
  greenBg:     "rgba(34,197,94,0.08)",
  greenBorder: "rgba(34,197,94,0.2)",
  yellow:      "#fbbf24",
  yellowBg:    "rgba(251,191,36,0.08)",
  yellowBorder:"rgba(251,191,36,0.2)",
  red:         "#f87171",
  redBg:       "rgba(220,38,38,0.10)",
  redBorder:   "rgba(220,38,38,0.28)",
};


const STATUS_CONFIG = {
  safe: {
    color:       C.green,
    bg:          C.greenBg,
    border:      C.greenBorder,
    label:       "SECURE",
    sublabel:    "All traffic nominal",
    particleCount: 5,
    pulseClass:  "af-pulse-green",
  },
  suspicious: {
    color:       C.yellow,
    bg:          C.yellowBg,
    border:      C.yellowBorder,
    label:       "SUSPICIOUS",
    sublabel:    "Anomalous activity detected",
    particleCount: 7,
    pulseClass:  "af-pulse-yellow",
  },
  attack: {
    color:       C.red,
    bg:          C.redBg,
    border:      C.redBorder,
    label:       "UNDER ATTACK",
    sublabel:    "Malicious traffic blocked",
    particleCount: 9,
    pulseClass:  "af-pulse-red",
  },
};


function FlowNode({ label, sublabel, icon, accent, glow }) {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", gap: 6,
      minWidth: 64,
    }}>
      <div style={{
        width: 44, height: 44, borderRadius: 10,
        background: glow ? `${accent}18` : C.cardBg2,
        border: `1px solid ${glow ? accent : C.border}`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: 18,
        boxShadow: glow ? `0 0 12px ${accent}40` : "none",
        transition: "all 0.4s ease",
        flexShrink: 0,
      }}>
        {icon}
      </div>
      <div style={{ textAlign: "center" }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: glow ? accent : C.textSecondary, letterSpacing: "0.04em" }}>
          {label}
        </div>
        {sublabel && (
          <div style={{ fontSize: 10, color: C.textDim, marginTop: 2 }}>{sublabel}</div>
        )}
      </div>
    </div>
  );
}


function FlowPipe({ color, active, attack }) {
  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 6, position: "relative", minWidth: 40 }}>
      
      <div style={{
        width: "100%", height: 2, borderRadius: 99,
        background: C.border,
        position: "relative", overflow: "hidden",
      }}>
        
        {active && (
          <div
            className={attack ? "af-track-flash" : "af-track-slide"}
            style={{
              position: "absolute", top: 0, left: 0,
              height: "100%", width: "40%",
              background: color,
              borderRadius: 99,
              opacity: 0.8,
            }}
          />
        )}
      </div>
    </div>
  );
}


function ParticleCanvas({ status, color }) {
  const canvasRef = useRef(null);
  const animRef   = useRef(null);
  const particles = useRef([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const W = canvas.offsetWidth, H = canvas.offsetHeight;
    canvas.width  = W;
    canvas.height = H;
    const ctx = canvas.getContext("2d");
    const count = STATUS_CONFIG[status]?.particleCount || 5;

    // Spawn particles evenly spread across the track
    particles.current = Array.from({ length: count }, (_, i) => ({
      x: (W / count) * i,
      y: H / 2,
      speed: 0.6 + Math.random() * 0.8,
      radius: status === "attack" ? 3.5 : 2.5,
      opacity: 0.5 + Math.random() * 0.5,
      trail: [],
    }));

    const draw = () => {
      ctx.clearRect(0, 0, W, H);

      particles.current.forEach(p => {
        // Advance
        p.x += p.speed;
        if (p.x > W + 10) p.x = -10;

        // Trail
        p.trail.push({ x: p.x, y: p.y });
        if (p.trail.length > 10) p.trail.shift();

        // Draw trail
        p.trail.forEach((pt, i) => {
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, p.radius * 0.5, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.globalAlpha = (i / p.trail.length) * p.opacity * 0.4;
          ctx.fill();
        });

        // Draw head
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.globalAlpha = p.opacity;
        ctx.fill();
        ctx.globalAlpha = 1;
      });

      animRef.current = requestAnimationFrame(draw);
    };

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [status, color]);

  return (
    <canvas
      ref={canvasRef}
      style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }}
    />
  );
}

export default function AttackFlow({ status = "safe" }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.safe;

  const nodes = [
    { label: "Attacker",  sublabel: "External",  icon: "⚡", glow: status === "attack" },
    { label: "AI Engine", sublabel: "Analyzing", icon: "◈",  glow: true },
    { label: "Firewall",  sublabel: "Filtering", icon: "⬡",  glow: status !== "safe" },
    { label: "Network",   sublabel: "Protected", icon: "◎",  glow: status === "safe" },
  ];

  return (
    <>
      <style>{`
        @keyframes af-slide   { from{transform:translateX(-100%)} to{transform:translateX(300%)} }
        @keyframes af-flash   { 0%,100%{transform:translateX(-100%);opacity:1} 50%{opacity:0.6} to{transform:translateX(300%)} }
        @keyframes af-ping-g  { 0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,.5)} 60%{box-shadow:0 0 0 8px rgba(34,197,94,0)} }
        @keyframes af-ping-y  { 0%,100%{box-shadow:0 0 0 0 rgba(251,191,36,.5)} 60%{box-shadow:0 0 0 8px rgba(251,191,36,0)} }
        @keyframes af-ping-r  { 0%,100%{box-shadow:0 0 0 0 rgba(248,113,113,.6)} 50%{box-shadow:0 0 0 10px rgba(248,113,113,0)} }
        @keyframes af-bg-flash{ 0%,100%{opacity:0} 50%{opacity:1} }
        .af-track-slide { animation: af-slide 1.4s linear infinite; }
        .af-track-flash { animation: af-flash 0.5s linear infinite; }
        .af-pulse-green { animation: af-ping-g 2s ease-in-out infinite; }
        .af-pulse-yellow{ animation: af-ping-y 1.4s ease-in-out infinite; }
        .af-pulse-red   { animation: af-ping-r 0.7s ease-in-out infinite; }
        .af-bg-attack   { animation: af-bg-flash 0.7s ease-in-out infinite; }
      `}</style>

      <div style={{
        background: C.cardBg,
        border: `1px solid ${C.border}`,
        borderRadius: 14,
        overflow: "hidden",
        position: "relative",
      }}>

        
        {status === "attack" && (
          <div className="af-bg-attack" style={{
            position: "absolute", inset: 0,
            background: "rgba(220,38,38,0.04)",
            pointerEvents: "none", zIndex: 0,
          }} />
        )}

        
        <div style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          display: "flex", alignItems: "center", justifyContent: "space-between",
          position: "relative", zIndex: 1,
        }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: C.textSecondary, textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>
            Attack Flow
          </p>
          
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className={cfg.pulseClass} style={{
              width: 8, height: 8, borderRadius: "50%",
              background: cfg.color, display: "inline-block", flexShrink: 0,
            }} />
            <span style={{
              fontSize: 11, fontWeight: 700, color: cfg.color,
              background: cfg.bg, border: `1px solid ${cfg.border}`,
              borderRadius: 6, padding: "2px 10px", letterSpacing: "0.06em",
            }}>
              {cfg.label}
            </span>
          </div>
        </div>

        
        <div style={{ padding: "28px 24px 20px", position: "relative", zIndex: 1 }}>

          
          <div style={{ display: "flex", alignItems: "center", gap: 0 }}>
            {nodes.map((n, i) => (
              <>
                <FlowNode key={`n${i}`} {...n} accent={cfg.color} />
                {i < nodes.length - 1 && (
                  <div key={`p${i}`} style={{ flex: 1, height: 32, position: "relative", display: "flex", alignItems: "center" }}>
                    
                    <div style={{ position: "absolute", left: 0, right: 0, top: "50%", transform: "translateY(-50%)", height: 2, borderRadius: 99, background: C.border, overflow: "hidden" }}>
                      <div
                        className={status === "attack" ? "af-track-flash" : "af-track-slide"}
                        style={{
                          position: "absolute", top: 0, left: 0, height: "100%", width: "35%",
                          background: cfg.color, borderRadius: 99, opacity: 0.75,
                        }}
                      />
                    </div>
                    
                    <ParticleCanvas status={status} color={cfg.color} />
                  </div>
                )}
              </>
            ))}
          </div>

          <div style={{
            marginTop: 24, padding: "12px 16px",
            background: cfg.bg, border: `1px solid ${cfg.border}`,
            borderRadius: 10,
            display: "flex", alignItems: "center", justifyContent: "space-between",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: cfg.color, display: "inline-block", flexShrink: 0,
              }} />
              <span style={{ fontSize: 13, fontWeight: 600, color: cfg.color }}>
                {cfg.sublabel}
              </span>
            </div>
            <span style={{ fontSize: 11, color: C.textMuted, fontFamily: "ui-monospace,monospace" }}>
              {new Date().toLocaleTimeString()}
            </span>
          </div>
        </div>
      </div>
    </>
  );
}
