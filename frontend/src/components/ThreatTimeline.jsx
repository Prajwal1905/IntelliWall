"use client";

import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, ReferenceLine, CartesianGrid,
} from "recharts";
import { useEffect, useState } from "react";

const C = {
  cardBg2:  "#0f172a",
  border:   "#1e293b",
  textPrimary:   "#ffffff",
  textSecondary: "#94a3b8",
  textMuted:     "#64748b",
  textDim:       "#475569",
  red:      "#f87171",
  redBg:    "rgba(248,113,113,0.08)",
  redBorder:"rgba(248,113,113,0.2)",
  orange:   "#fb923c",
  orangeBg: "rgba(251,146,60,0.08)",
  orangeBorder: "rgba(251,146,60,0.2)",
  purple:   "#c084fc",
  purpleBg: "rgba(192,132,252,0.08)",
  purpleBorder: "rgba(192,132,252,0.2)",
  blue:     "#60a5fa",
  blueBg:   "rgba(96,165,250,0.08)",
  blueBorder: "rgba(96,165,250,0.2)",
  green:    "#22c55e",
  greenBg:  "rgba(34,197,94,0.08)",
  greenBorder: "rgba(34,197,94,0.2)",
};


function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  const items = [
    { key: "blocked",   label: "Blocked",   color: C.red    },
    { key: "suspicious",label: "Challenge", color: C.orange },
    { key: "honeypot",  label: "Honeypot",  color: C.purple },
    { key: "total",     label: "Total",     color: C.blue   },
  ];
  return (
    <div style={{ background: C.cardBg2, border: `1px solid ${C.border}`, borderRadius: 10, padding: "10px 14px", minWidth: 160 }}>
      <div style={{ fontSize: 11, color: C.textMuted, marginBottom: 8, fontFamily: "ui-monospace,monospace" }}>{label}</div>
      {items.map(({ key, label: lbl, color }) => {
        const entry = payload.find(p => p.dataKey === key);
        if (!entry) return null;
        return (
          <div key={key} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, padding: "2px 0" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: color, display: "inline-block" }} />
              <span style={{ fontSize: 11, color: C.textSecondary }}>{lbl}</span>
            </div>
            <span style={{ fontSize: 11, fontWeight: 700, color }}>{entry.value}</span>
          </div>
        );
      })}
    </div>
  );
}

function TrendBadge({ direction }) {
  const map = {
    up:     { label: "Escalating", color: C.red,    bg: C.redBg,    border: C.redBorder,    arrow: "↑" },
    down:   { label: "Declining",  color: C.green,  bg: C.greenBg,  border: C.greenBorder,  arrow: "↓" },
    stable: { label: "Stable",     color: C.textMuted, bg: "rgba(100,116,139,0.08)", border: "rgba(100,116,139,0.2)", arrow: "→" },
  };
  const s = map[direction] || map.stable;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11, fontWeight: 600, color: s.color, background: s.bg, border: `1px solid ${s.border}`, borderRadius: 6, padding: "2px 8px", letterSpacing: "0.04em" }}>
      <span>{s.arrow}</span>{s.label}
    </span>
  );
}

function StatPill({ label, value, color, bg, border }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 3, padding: "8px 14px", background: bg, border: `1px solid ${border}`, borderRadius: 8 }}>
      <span style={{ fontSize: 16, fontWeight: 700, color, lineHeight: 1 }}>{value}</span>
      <span style={{ fontSize: 10, color, opacity: 0.75, fontWeight: 500, letterSpacing: "0.04em" }}>{label}</span>
    </div>
  );
}


export default function ThreatTimeline({ alerts }) {
  const [timelineData, setTimelineData]     = useState([]);
  const [trendDirection, setTrendDirection] = useState("stable");
  const [peakLoad, setPeakLoad]             = useState(0);
  const [attackVelocity, setAttackVelocity] = useState(0);
  const [dominantAttack, setDominantAttack] = useState("None");
  const [spikeThreshold, setSpikeThreshold] = useState(null);
  const [prediction, setPrediction]         = useState(null);

  useEffect(() => {
    if (!alerts || alerts.length === 0) return;

    
    const seen = new Set();
    const uniqueAlerts = alerts.filter(a => {
      const key = `${a.source}_${a.action}_${a.timestamp}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    const timeBuckets = {};
    const attackFreq  = {};
    let totalAttackEvents = 0;

    uniqueAlerts.forEach(a => {
      if (a.action === "ALLOW") return;
      totalAttackEvents++;

      const atk = a.attack_type || "Unknown";
      attackFreq[atk] = (attackFreq[atk] || 0) + 1;

      const timeKey = new Date(a.timestamp || Date.now())
        .toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

      if (!timeBuckets[timeKey]) timeBuckets[timeKey] = { blocked: 0, suspicious: 0, honeypot: 0 };
      const weight = ((a.risk || 50) / 100) * 2;

      if (a.action === "BLOCK")     timeBuckets[timeKey].blocked   += weight;
      if (a.action === "CHALLENGE") timeBuckets[timeKey].suspicious += weight;
      if (a.action === "HONEYPOT")  timeBuckets[timeKey].honeypot  += weight;
    });

    const formatted = Object.entries(timeBuckets)
      .map(([time, v]) => ({
        time,
        blocked:    +v.blocked.toFixed(2),
        suspicious: +v.suspicious.toFixed(2),
        honeypot:   +v.honeypot.toFixed(2),
        total:      +(v.blocked + v.suspicious + v.honeypot).toFixed(2),
      }))
      .sort((a, b) => a.time.localeCompare(b.time));

    setTimelineData(prev => {
      const merged = [...prev, ...formatted];
      const deduped = [];
      const s = new Set();
      for (let i = merged.length - 1; i >= 0; i--) {
        if (!s.has(merged[i].time)) { deduped.unshift(merged[i]); s.add(merged[i].time); }
      }
      return deduped.slice(-24);
    });

    
    if (formatted.length >= 2) {
      const last = formatted.at(-1).total, prev = formatted.at(-2).total;
      setTrendDirection(last > prev + 0.1 ? "up" : last < prev - 0.1 ? "down" : "stable");
    }

    
    const maxVal = Math.max(...formatted.map(d => d.total), 0);
    setPeakLoad(maxVal.toFixed(1));
    setAttackVelocity((totalAttackEvents / 60).toFixed(2));

    const topAtk = Object.entries(attackFreq).sort((a, b) => b[1] - a[1])[0];
    setDominantAttack(topAtk ? topAtk[0] : "None");

    
    const totals = formatted.map(d => d.total);
    if (totals.length > 1) {
      const mean  = totals.reduce((s, v) => s + v, 0) / totals.length;
      const stddev = Math.sqrt(totals.reduce((s, v) => s + (v - mean) ** 2, 0) / totals.length);
      setSpikeThreshold(+(mean + 1.5 * stddev).toFixed(2));
    }

    
    if (formatted.length >= 3) {
      const last2 = formatted.slice(-3).map(d => d.total);
      const delta = (last2[2] - last2[0]) / 2;
      const next  = Math.max(0, +(last2[2] + delta).toFixed(2));
      setPrediction({ time: "Predicted", total: next, blocked: 0, suspicious: 0, honeypot: 0, isPrediction: true });
    }
  }, [alerts]);

  const chartData   = prediction ? [...timelineData, prediction] : timelineData;
  const isSpike     = spikeThreshold !== null && timelineData.some(d => d.total > spikeThreshold);
  const latestTotal = timelineData.at(-1)?.total ?? 0;

  const SERIES = [
    { key: "blocked",    label: "Blocked",   color: "#f87171", fillId: "fillBlocked"   },
    { key: "suspicious", label: "Challenge", color: "#fb923c", fillId: "fillSuspicious" },
    { key: "honeypot",   label: "Honeypot",  color: "#c084fc", fillId: "fillHoneypot"  },
    { key: "total",      label: "Total",     color: "#60a5fa", fillId: "fillTotal"     },
  ];

  return (
    <>
      <style>{`
        @keyframes tt-spike { 0%,100%{opacity:1} 50%{opacity:0.5} }
        .tt-spike-badge { animation: tt-spike 1s ease-in-out infinite; }
      `}</style>

      <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: 12 }}>

        
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
          <TrendBadge direction={trendDirection} />
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {isSpike && (
              <span className="tt-spike-badge" style={{ fontSize: 10, fontWeight: 700, color: C.red, background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: 6, padding: "2px 8px", letterSpacing: "0.04em" }}>
                SPIKE DETECTED
              </span>
            )}
            
            <div style={{ display: "flex", gap: 10 }}>
              {SERIES.map(({ key, label, color }) => (
                <div key={key} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 8, height: 3, borderRadius: 99, background: color, display: "inline-block" }} />
                  <span style={{ fontSize: 10, color: C.textDim }}>{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        
        <div style={{ display: "flex", gap: 10, flexShrink: 0 }}>
          <StatPill label="Peak load"   value={peakLoad}        color={C.red}    bg={C.redBg}    border={C.redBorder}    />
          <StatPill label="Rate /min"   value={attackVelocity}  color={C.orange} bg={C.orangeBg} border={C.orangeBorder} />
          <StatPill label="Live threat" value={latestTotal}     color={C.blue}   bg={C.blueBg}   border={C.blueBorder}   />
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 3, padding: "8px 14px", background: "rgba(100,116,139,0.06)", border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
            <span style={{ fontSize: 10, color: C.textDim, fontWeight: 500, letterSpacing: "0.04em" }}>TOP ATTACK</span>
            <span style={{ fontSize: 12, fontWeight: 600, color: C.textSecondary, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{dominantAttack}</span>
          </div>
          {prediction && (
            <StatPill label="Predicted"  value={prediction.total} color={C.purple} bg={C.purpleBg} border={C.purpleBorder} />
          )}
        </div>

        
        <div style={{ flex: 1, minHeight: 0 }}>
          {timelineData.length === 0 ? (
            <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 8 }}>
              <div style={{ width: 32, height: 32, borderRadius: "50%", background: "rgba(100,116,139,0.1)", border: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14 }}>◎</div>
              <span style={{ fontSize: 13, color: C.textDim }}>No threat data</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
                <defs>
                  {SERIES.map(({ key, color, fillId }) => (
                    <linearGradient key={fillId} id={fillId} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={color} stopOpacity={0.18} />
                      <stop offset="95%" stopColor={color} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>

                <CartesianGrid strokeDasharray="3 6" stroke="rgba(30,41,59,0.8)" vertical={false} />

                <XAxis
                  dataKey="time"
                  stroke={C.textDim}
                  tick={{ fill: C.textDim, fontSize: 10, fontFamily: "ui-monospace,monospace" }}
                  tickLine={false}
                  axisLine={{ stroke: C.border }}
                  interval="preserveStartEnd"
                />
                <YAxis
                  stroke={C.textDim}
                  tick={{ fill: C.textDim, fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                />

                <Tooltip content={<CustomTooltip />} cursor={{ stroke: C.border, strokeWidth: 1, strokeDasharray: "4 4" }} />

                
                {spikeThreshold !== null && (
                  <ReferenceLine
                    y={spikeThreshold}
                    stroke={C.red}
                    strokeDasharray="4 4"
                    strokeOpacity={0.5}
                    label={{ value: "Spike threshold", position: "insideTopRight", fill: C.red, fontSize: 9 }}
                  />
                )}

                
                {prediction && timelineData.length > 0 && (
                  <ReferenceLine
                    x="Predicted"
                    stroke={C.purple}
                    strokeDasharray="3 4"
                    strokeOpacity={0.4}
                    label={{ value: "Forecast", position: "insideTopLeft", fill: C.purple, fontSize: 9 }}
                  />
                )}

                {SERIES.map(({ key, color, fillId }) => (
                  <Area
                    key={key}
                    type="monotone"
                    dataKey={key}
                    stroke={color}
                    strokeWidth={key === "total" ? 1.5 : 1.5}
                    strokeDasharray={key === "total" ? "5 4" : undefined}
                    fill={`url(#${fillId})`}
                    dot={false}
                    activeDot={{ r: 4, fill: color, stroke: C.cardBg2, strokeWidth: 2 }}
                    connectNulls
                  />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </>
  );
}
