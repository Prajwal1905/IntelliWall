"use client";

import { useEffect, useState } from "react";

const C = {
  pageBg:  "#020617",
  cardBg:  "#0a1628",
  cardBg2: "#0f172a",
  border:  "#1e293b",
  textPrimary:   "#ffffff",
  textSecondary: "#94a3b8",
  textMuted:     "#64748b",
  textDim:       "#475569",
  green:   "#22c55e",  greenBg: "rgba(34,197,94,0.08)",   greenBorder: "rgba(34,197,94,0.2)",
  blue:    "#60a5fa",  blueBg:  "rgba(96,165,250,0.08)",  blueBorder:  "rgba(96,165,250,0.2)",
  red:     "#f87171",  redBg:   "rgba(248,113,113,0.08)", redBorder:   "rgba(248,113,113,0.2)",
  yellow:  "#fbbf24",  yellowBg:"rgba(251,191,36,0.08)",  yellowBorder:"rgba(251,191,36,0.2)",
  orange:  "#fb923c",  orangeBg:"rgba(251,146,60,0.08)",  orangeBorder:"rgba(251,146,60,0.2)",
  purple:  "#c084fc",  purpleBg:"rgba(192,132,252,0.08)", purpleBorder:"rgba(192,132,252,0.2)",
};

function Card({ children, style = {} }) {
  return (
    <div style={{ background: C.cardBg, border: `1px solid ${C.border}`, borderRadius: 14, overflow: "hidden", ...style }}>
      {children}
    </div>
  );
}

function CardHeader({ title, badge }) {
  return (
    <div style={{ padding: "14px 20px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <p style={{ fontSize: 13, fontWeight: 600, color: C.textSecondary, textTransform: "uppercase", letterSpacing: "0.08em", margin: 0 }}>{title}</p>
      {badge && <span style={{ fontSize: 11, color: badge.color, background: badge.bg, border: `1px solid ${badge.border}`, borderRadius: 6, padding: "2px 8px", fontWeight: 500 }}>{badge.label}</span>}
    </div>
  );
}

function StatCard({ label, value, color, bg, border, sub }) {
  return (
    <div style={{ background: C.cardBg2, border: `1px solid ${border || C.border}`, borderRadius: 12, padding: "18px 22px" }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 10 }}>{label}</div>
      <div style={{ fontSize: 30, fontWeight: 700, color: color || C.textPrimary, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: C.textDim, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function BarRow({ label, count, max, color }) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 40px", alignItems: "center", gap: 12, padding: "7px 0" }}>
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
          <span style={{ fontSize: 12, color: C.textSecondary, fontFamily: "ui-monospace,monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 200 }}>{label}</span>
        </div>
        <div style={{ height: 5, borderRadius: 99, background: C.border, overflow: "hidden" }}>
          <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 99, transition: "width 0.6s ease" }} />
        </div>
      </div>
      <span style={{ fontSize: 13, fontWeight: 700, color, textAlign: "right" }}>{count}</span>
    </div>
  );
}

function RiskDonut({ dist }) {
  const total = Object.values(dist).reduce((s, v) => s + v, 0) || 1;
  const segments = [
    { key: "critical", color: C.red,    label: "Critical" },
    { key: "high",     color: C.orange, label: "High"     },
    { key: "medium",   color: C.yellow, label: "Medium"   },
    { key: "low",      color: C.green,  label: "Low"      },
  ];

  let offset = 0;
  const R = 52, stroke = 14, circ = 2 * Math.PI * R;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
      <svg width={130} height={130} viewBox="0 0 130 130">
        <circle cx={65} cy={65} r={R} fill="none" stroke={C.border} strokeWidth={stroke} />
        {segments.map(({ key, color }) => {
          const val  = dist[key] || 0;
          const dash = (val / total) * circ;
          const el   = (
            <circle key={key} cx={65} cy={65} r={R} fill="none"
              stroke={color} strokeWidth={stroke}
              strokeDasharray={`${dash} ${circ}`}
              strokeDashoffset={-offset}
              transform="rotate(-90 65 65)"
              style={{ transition: "stroke-dasharray 0.6s ease" }}
            />
          );
          offset += dash;
          return el;
        })}
        <text x={65} y={61} textAnchor="middle" fill={C.textPrimary} fontSize={18} fontWeight={700}>{total}</text>
        <text x={65} y={77} textAnchor="middle" fill={C.textMuted} fontSize={10}>total</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {segments.map(({ key, color, label }) => (
          <div key={key} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: color, display: "inline-block", flexShrink: 0 }} />
            <span style={{ fontSize: 12, color: C.textSecondary }}>{label}</span>
            <span style={{ fontSize: 12, fontWeight: 700, color, marginLeft: "auto", minWidth: 30, textAlign: "right" }}>{dist[key] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ReportPage() {
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState("");

  const fetchReport = async () => {
    try {
      const res  = await fetch("http://127.0.0.1:8000/report");
      const data = await res.json();
      setReport(data);
      setLastRefresh(new Date().toLocaleTimeString());
    } catch (e) {
      console.error("Report fetch failed", e);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchReport();
    const id = setInterval(fetchReport, 10000);
    return () => clearInterval(id);
  }, []);

  if (loading) return (
    <div style={{ minHeight: "100vh", background: C.pageBg, display: "flex", alignItems: "center", justifyContent: "center", gap: 10, color: C.textMuted, fontSize: 14 }}>
      <div style={{ width: 16, height: 16, border: `2px solid ${C.border}`, borderTopColor: C.blue, borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
      Loading report...
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );

  if (!report) return (
    <div style={{ minHeight: "100vh", background: C.pageBg, display: "flex", alignItems: "center", justifyContent: "center", color: C.textMuted, fontSize: 14 }}>
      No report data available
    </div>
  );

  const s  = report.summary || {};
  const hp = report.honeypot || {};

  return (
    <div style={{ minHeight: "100vh", background: C.pageBg, display: "flex", justifyContent: "center" }}>
      <div style={{ width: "100%", maxWidth: 1400, padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>

        
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", paddingBottom: 16, borderBottom: `1px solid ${C.border}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, boxShadow: `0 0 6px ${C.green}` }} />
            <h1 style={{ fontSize: 18, fontWeight: 700, color: C.textPrimary, margin: 0, letterSpacing: "0.04em" }}>IntelliWall</h1>
            <span style={{ fontSize: 11, color: C.textDim, background: C.cardBg2, border: `1px solid ${C.border}`, borderRadius: 6, padding: "2px 8px" }}>
              THREAT INTEL REPORT
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 11, color: C.textDim }}>Updated {lastRefresh}</span>
            <button
              onClick={fetchReport}
              style={{ padding: "6px 14px", background: "transparent", border: `1px solid ${C.border}`, color: C.textMuted, borderRadius: 8, fontSize: 12, cursor: "pointer" }}
            >
              Refresh
            </button>
            <a href="/" style={{ padding: "6px 14px", background: "transparent", border: `1px solid ${C.blueBorder}`, color: C.blue, borderRadius: 8, fontSize: 12, cursor: "pointer", textDecoration: "none" }}>
              ← Dashboard
            </a>
          </div>
        </div>

        
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 14 }}>
          <StatCard label="Total Alerts"   value={s.total_alerts}    color={C.blue}   border={C.blueBorder}   sub="All time" />
          <StatCard label="Blocked"        value={s.blocked}         color={C.red}    border={C.redBorder}    sub="Auto-blocked" />
          <StatCard label="Honeypot Hits"  value={s.honeypot}        color={C.purple} border={C.purpleBorder} sub="Trap captures" />
          <StatCard label="Avg Risk Score" value={`${s.avg_risk}%`}  color={C.yellow} border={C.yellowBorder} sub={`Peak: ${s.max_risk}%`} />
          <StatCard label="Blocked IPs"    value={s.blocked_ips}     color={C.orange} border={C.orangeBorder} sub="Blacklisted" />
        </div>

        
        <div style={{ display: "grid", gridTemplateColumns: "300px 1fr 1fr", gap: 20 }}>

         
          <Card>
            <CardHeader title="Risk Distribution" />
            <div style={{ padding: "20px 24px" }}>
              <RiskDonut dist={report.risk_distribution || {}} />
            </div>
          </Card>

          
          <Card>
            <CardHeader title="Top Attack Countries" badge={{ label: `${report.top_countries?.length || 0} countries`, color: C.blue, bg: C.blueBg, border: C.blueBorder }} />
            <div style={{ padding: "12px 20px" }}>
              {(report.top_countries || []).map((c: any, i: number) => (
                <BarRow key={i} label={c.country} count={c.count} max={report.top_countries[0]?.count || 1} color={C.blue} />
              ))}
            </div>
          </Card>

         
          <Card>
            <CardHeader title="Top Attack Types" badge={{ label: `${report.top_attacks?.length || 0} types`, color: C.red, bg: C.redBg, border: C.redBorder }} />
            <div style={{ padding: "12px 20px" }}>
              {(report.top_attacks || []).map((a: any, i: number) => (
                <BarRow key={i} label={a.type} count={a.count} max={report.top_attacks[0]?.count || 1} color={C.red} />
              ))}
            </div>
          </Card>
        </div>

       
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 20 }}>

          
          <Card>
            <CardHeader title="Top Attacker IPs" />
            <div style={{ padding: "12px 20px" }}>
              {(report.top_ips || []).length === 0 ? (
                <div style={{ padding: "1.5rem", textAlign: "center", fontSize: 13, color: C.textDim }}>No data</div>
              ) : (report.top_ips || []).map((ip: any, i: number) => (
                <BarRow key={i} label={ip.ip} count={ip.count} max={report.top_ips[0]?.count || 1} color={C.orange} />
              ))}
            </div>
          </Card>

          
          <Card>
            <CardHeader title="Top Threat ISPs" />
            <div style={{ padding: "12px 20px" }}>
              {(report.top_isps || []).length === 0 ? (
                <div style={{ padding: "1.5rem", textAlign: "center", fontSize: 13, color: C.textDim }}>No data</div>
              ) : (report.top_isps || []).map((isp: any, i: number) => (
                <BarRow key={i} label={isp.isp} count={isp.count} max={report.top_isps[0]?.count || 1} color={C.yellow} />
              ))}
            </div>
          </Card>

         
          <Card>
            <CardHeader title="Honeypot Summary" badge={{ label: `${hp.total_events || 0} events`, color: C.purple, bg: C.purpleBg, border: C.purpleBorder }} />
            <div style={{ padding: "12px 20px" }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.textDim, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>Top Traps Hit</div>
              {(hp.top_traps || []).slice(0, 4).map((t: any, i: number) => (
                <BarRow key={i} label={t.trap} count={t.hits} max={hp.top_traps?.[0]?.hits || 1} color={C.purple} />
              ))}
            </div>
          </Card>
        </div>

        
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>

          
          <Card>
            <CardHeader title="Detected Scanners" badge={{ label: "Fingerprinted", color: C.red, bg: C.redBg, border: C.redBorder }} />
            <div style={{ padding: "12px 20px" }}>
              {(hp.top_scanners || []).length === 0 ? (
                <div style={{ padding: "1.5rem", textAlign: "center", fontSize: 13, color: C.textDim }}>No scanners detected yet</div>
              ) : (hp.top_scanners || []).map((s: any, i: number) => (
                <BarRow key={i} label={s.scanner} count={s.count} max={hp.top_scanners[0]?.count || 1} color={C.red} />
              ))}
            </div>
          </Card>

          
          <Card>
            <CardHeader title="Honeypot Attack Origins" />
            <div style={{ padding: "12px 20px" }}>
              {(hp.top_countries || []).length === 0 ? (
                <div style={{ padding: "1.5rem", textAlign: "center", fontSize: 13, color: C.textDim }}>No geo data yet</div>
              ) : (hp.top_countries || []).map((c: any, i: number) => (
                <BarRow key={i} label={c.country} count={c.count} max={hp.top_countries[0]?.count || 1} color={C.purple} />
              ))}
            </div>
          </Card>
        </div>

        
        <div style={{ paddingTop: 16, borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 11, color: C.textDim }}>IntelliWall Threat Intelligence Report · Generated {report.generated_at?.slice(0, 19)}</span>
          <div style={{ display: "flex", gap: 16, fontSize: 11, color: C.textDim }}>
            <span>Proxy detected: <span style={{ color: C.yellow }}>{s.proxy_detected}</span></span>
            <span>Hosting network: <span style={{ color: C.orange }}>{s.hosting_detected}</span></span>
            <span>Challenge issued: <span style={{ color: C.blue }}>{s.challenge}</span></span>
          </div>
        </div>

      </div>
    </div>
  );
}
