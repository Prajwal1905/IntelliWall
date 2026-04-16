"use client";

import { useEffect, useState, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";
import * as d3 from "d3-force";

const C = {
  pageBg: "#020617",
  cardBg2: "#0f172a",
  border: "#1e293b",
  textSecondary: "#94a3b8",
  textMuted: "#64748b",
  textDim: "#475569",
  
  firewall: "#3b82f6", // blue
  server: "#22c55e", // green
  safe: "#06b6d4", // cyan
  blocked: "#f87171", // red
  challenge: "#fb923c", // orange
  honeypot: "#c084fc", // purple
  
  linkSafe: "rgba(6,182,212,0.35)",
  linkBlocked: "rgba(248,113,113,0.7)",
  linkChallenge: "rgba(251,146,60,0.6)",
  linkHoneypot: "rgba(192,132,252,0.6)",
  linkServer: "rgba(34,197,94,0.4)",
};

const NODE_TYPES = [
  { key: "firewall", color: C.firewall, label: "Firewall" },
  { key: "server", color: C.server, label: "Server" },
  { key: "safe", color: C.safe, label: "Safe" },
  { key: "blocked", color: C.blocked, label: "Blocked" },
  { key: "challenge", color: C.challenge, label: "Challenge" },
  { key: "honeypot", color: C.honeypot, label: "Honeypot" },
];

const FIREWALL_ID = "Firewall";
const SERVER_ID = "Main Server";
const SAFE_ID = "Safe Traffic";

function getNodeStyle(node, blacklist) {
  if (node.isFirewall)
    return { color: C.firewall, radius: 14, glow: C.firewall };
  if (node.isServer) return { color: C.server, radius: 12, glow: C.server };
  if (node.isSafeCluster) return { color: C.safe, radius: 10, glow: C.safe };
  if (blacklist.includes(node.id))
    return { color: C.blocked, radius: 5, glow: C.blocked, dim: true };
  if (node.isBlocked) return { color: C.blocked, radius: 7, glow: C.blocked };
  if (node.isHoneypot)
    return { color: C.honeypot, radius: 7, glow: C.honeypot };
  if (node.isChallenge)
    return { color: C.challenge, radius: 6, glow: C.challenge };
  return { color: C.safe, radius: 5, glow: C.safe };
}

function getLinkColor(link) {
  if (link.isBlocked) return C.linkBlocked;
  if (link.isHoneypot) return C.linkHoneypot;
  if (link.isChallenge) return C.linkChallenge;
  if (link.isServer) return C.linkServer;
  return C.linkSafe;
}

export default function NetworkGraph() {
  const [graph, setGraph] = useState({ nodes: [], links: [] });
  const [alerts, setAlerts] = useState([]);
  const [blacklist, setBlacklist] = useState([]);
  const [hoverNode, setHoverNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [size, setSize] = useState({ w: 800, h: 400 });
  const fgRef = useRef(null);
  const containerRef = useRef(null);
  const initRef = useRef(false);
  const tickRef = useRef(0);


  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) return;
        const [r1, r2] = await Promise.all([
          fetch("http://127.0.0.1:8000/alerts", {
            headers: { Authorization: `Bearer ${token}` },
          }),
          fetch("http://127.0.0.1:8000/honeypot/blacklist"),
        ]);
        const d1 = await r1.json();
        const d2 = await r2.json();
        setAlerts(Array.isArray(d1) ? d1 : []);
        setBlacklist(d2.blocked_ips || []);
      } catch (e) {
        console.error(e);
      }
    };
    fetchData();
    const id = setInterval(fetchData, 2000);
    return () => clearInterval(id);
  }, []);

  
  useEffect(() => {
    const nodesMap = new Map();
    const links = [];
    const attackMap = {};

    (Array.isArray(alerts) ? alerts : []).forEach((a) => {
      if (!a.source) return;
      const action = (a.action || "").toUpperCase().trim();
      if (!attackMap[a.source])
        attackMap[a.source] = { count: 0, maxRisk: 0, action };
      attackMap[a.source].count++;
      attackMap[a.source].maxRisk = Math.max(
        attackMap[a.source].maxRisk,
        a.risk || 0,
      );
      attackMap[a.source].action = action;
    });

    const safeCount = alerts.filter(
      (a) => (a.action || "").toUpperCase() === "ALLOW",
    ).length;
    const attackCount = new Set(
      alerts
        .filter((a) => {
          const act = (a.action || "").toUpperCase();
          return act === "BLOCK" || act === "CHALLENGE" || act === "HONEYPOT";
        })
        .map((a) => a.source),
    ).size;

    // Core nodes
    nodesMap.set(FIREWALL_ID, {
      id: FIREWALL_ID,
      label: FIREWALL_ID,
      sublabel: `${attackCount} threats`,
      isFirewall: true,
      fx: 0,
      fy: 0,
    });
    nodesMap.set(SERVER_ID, {
      id: SERVER_ID,
      label: SERVER_ID,
      sublabel: "protected",
      isServer: true,
      fx: 220,
      fy: 0,
    });
    nodesMap.set(SAFE_ID, {
      id: SAFE_ID,
      label: "Safe",
      sublabel: `${safeCount} conns`,
      isSafeCluster: true,
      fx: -180,
      fy: -80,
    });

    links.push({ source: SAFE_ID, target: FIREWALL_ID, isSafe: true });
    links.push({ source: FIREWALL_ID, target: SERVER_ID, isServer: true });

    let bi = 0,
      ci = 0,
      hi = 0;

    Object.entries(attackMap)
      .filter(([ip, d]) => !blacklist.includes(ip) && d.maxRisk >= 30)
      .forEach(([ip, d]) => {
        const attackType =
          alerts.find((a) => a.source === ip)?.attack_type || "Unknown";
        const isBlocked = d.action === "BLOCK";
        const isChallenge = d.action === "CHALLENGE";
        const isHoneypot = d.action === "HONEYPOT";

        let col, row, baseX;
        if (isBlocked) {
          col = bi % 3;
          row = Math.floor(bi / 3);
          baseX = -300;
          bi++;
        } else if (isHoneypot) {
          col = hi % 3;
          row = Math.floor(hi / 3);
          baseX = -40;
          hi++;
        } else if (isChallenge) {
          col = ci % 3;
          row = Math.floor(ci / 3);
          baseX = 300;
          ci++;
        } else {
          col = 0;
          row = 0;
          baseX = -300;
        }

        nodesMap.set(ip, {
          id: ip,
          label: ip,
          sublabel: `${d.count} hits · risk ${d.maxRisk}`,
          risk: d.maxRisk,
          attackType,
          isBlocked,
          isChallenge,
          isHoneypot,
          fx: baseX + col * 110,
          fy: 130 + row * 90,
        });

        links.push({
          source: ip,
          target: FIREWALL_ID,
          isAttack: true,
          isBlocked,
          isChallenge,
          isHoneypot,
        });
      });

    setGraph({ nodes: [...nodesMap.values()], links });
  }, [alerts, blacklist]);


  useEffect(() => {
    const update = () => {
      if (containerRef.current) {
        setSize({
          w: containerRef.current.clientWidth,
          h: containerRef.current.clientHeight,
        });
      }
    };
    update();
    const ro = new ResizeObserver(update);
    if (containerRef.current) ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

 
  useEffect(() => {
    if (fgRef.current && graph.nodes.length) {
      setTimeout(() => {
        fgRef.current?.zoomToFit(400, 80);
      }, 400);
    }
  }, [graph]);

  if (typeof window === "undefined") return null;

  const stats = {
    blocked: graph.nodes.filter((n) => n.isBlocked).length,
    challenge: graph.nodes.filter((n) => n.isChallenge).length,
    honeypot: graph.nodes.filter((n) => n.isHoneypot).length,
  };

  return (
    <>
      <style>{`
        .ng-legend-dot { width:8px;height:8px;border-radius:50%;flex-shrink:0; }
        .ng-stat { display:flex;align-items:center;gap:6px;padding:4px 10px;border-radius:6px; }
      `}</style>

      <div
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          gap: 0,
        }}
      >
        
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "8px 4px 10px",
            flexShrink: 0,
            flexWrap: "wrap",
            gap: 8,
          }}
        >
          
          <div style={{ display: "flex", gap: 8 }}>
            {[
              {
                label: "Blocked",
                val: stats.blocked,
                color: C.blocked,
                bg: "rgba(248,113,113,0.08)",
                border: "rgba(248,113,113,0.2)",
              },
              {
                label: "Challenge",
                val: stats.challenge,
                color: C.challenge,
                bg: "rgba(251,146,60,0.08)",
                border: "rgba(251,146,60,0.2)",
              },
              {
                label: "Honeypot",
                val: stats.honeypot,
                color: C.honeypot,
                bg: "rgba(192,132,252,0.08)",
                border: "rgba(192,132,252,0.2)",
              },
            ].map(({ label, val, color, bg, border }) => (
              <div
                key={label}
                className="ng-stat"
                style={{ background: bg, border: `1px solid ${border}` }}
              >
                <span style={{ fontSize: 14, fontWeight: 700, color }}>
                  {val}
                </span>
                <span
                  style={{
                    fontSize: 10,
                    color,
                    opacity: 0.8,
                    fontWeight: 500,
                    letterSpacing: "0.04em",
                  }}
                >
                  {label}
                </span>
              </div>
            ))}
          </div>

          
          <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
            {NODE_TYPES.map(({ key, color, label }) => (
              <div
                key={key}
                style={{ display: "flex", alignItems: "center", gap: 5 }}
              >
                <span
                  className="ng-legend-dot"
                  style={{ background: color, boxShadow: `0 0 5px ${color}60` }}
                />
                <span
                  style={{
                    fontSize: 10,
                    color: C.textDim,
                    letterSpacing: "0.04em",
                  }}
                >
                  {label}
                </span>
              </div>
            ))}
          </div>
        </div>

        
        <div
          ref={containerRef}
          style={{
            flex: 1,
            background: C.pageBg,
            borderRadius: 10,
            overflow: "hidden",
            position: "relative",
            border: `1px solid ${C.border}`,
          }}
        >
          
          {selectedNode &&
            !selectedNode.isFirewall &&
            !selectedNode.isServer &&
            !selectedNode.isSafeCluster && (
              <div
                style={{
                  position: "absolute",
                  top: 12,
                  right: 12,
                  zIndex: 10,
                  background: C.cardBg2,
                  border: `1px solid ${C.border}`,
                  borderRadius: 10,
                  padding: "12px 16px",
                  minWidth: 180,
                  pointerEvents: "none",
                }}
              >
                <div
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: C.textSecondary,
                    letterSpacing: "0.06em",
                    textTransform: "uppercase",
                    marginBottom: 8,
                  }}
                >
                  Node Info
                </div>
                {[
                  ["IP", selectedNode.id],
                  ["Attack", selectedNode.attackType || "—"],
                  [
                    "Risk",
                    selectedNode.risk != null ? `${selectedNode.risk}%` : "—",
                  ],
                  [
                    "Status",
                    selectedNode.isBlocked
                      ? "Blocked"
                      : selectedNode.isHoneypot
                        ? "Honeypot"
                        : selectedNode.isChallenge
                          ? "Challenge"
                          : "—",
                  ],
                ].map(([k, v]) => (
                  <div
                    key={k}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      gap: 12,
                      padding: "3px 0",
                      fontSize: 12,
                    }}
                  >
                    <span style={{ color: C.textMuted }}>{k}</span>
                    <span
                      style={{
                        color: C.textSecondary,
                        fontFamily: "ui-monospace,monospace",
                        fontSize: 11,
                      }}
                    >
                      {v}
                    </span>
                  </div>
                ))}
                <div style={{ marginTop: 8, fontSize: 10, color: C.textDim }}>
                  Click elsewhere to dismiss
                </div>
              </div>
            )}

          {graph.nodes.length > 0 && (
            <ForceGraph2D
              ref={fgRef}
              width={size.w}
              height={size.h}
              graphData={graph}
              nodeId="id"
              linkSource="source"
              linkTarget="target"
              backgroundColor={C.pageBg}
              d3AlphaDecay={0.03}
              d3VelocityDecay={0.3}
              cooldownTicks={0}
              warmupTicks={50}
              enableNodeDrag={true}
              enablePanInteraction={true}
              enableZoomInteraction={true}
              style={{ position: "absolute", top: 0, left: 0 }}
              d3Force={(fg) => {
                fg.d3Force("charge").strength(-200);
                fg.d3Force("link").distance(160);
                fg.d3Force("collision", d3.forceCollide(28));
                fg.d3Force("center", null);
              }}
              onNodeHover={(node) => setHoverNode(node)}
              onNodeClick={(node) =>
                setSelectedNode((prev) => (prev?.id === node?.id ? null : node))
              }
              linkColor={(link) => getLinkColor(link)}
              linkWidth={(link) => (link.isAttack ? 1.5 : 1)}
              linkDirectionalParticles={(link) => (link.isAttack ? 3 : 0)}
              linkDirectionalParticleSpeed={0.005}
              linkDirectionalParticleWidth={(link) => (link.isBlocked ? 3 : 2)}
              linkDirectionalParticleColor={(link) => getLinkColor(link)}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const x = node.x || 0;
                const y = node.y || 0;
                const style = getNodeStyle(node, blacklist);
                const isHovered = hoverNode?.id === node.id;
                const isSelected = selectedNode?.id === node.id;
                const isDim = style.dim;

                ctx.save();
                if (isDim) ctx.globalAlpha = 0.3;

                // Glow ring
                if (!isDim) {
                  ctx.beginPath();
                  ctx.arc(x, y, style.radius + 4, 0, 2 * Math.PI);
                  ctx.fillStyle = `${style.glow}22`;
                  ctx.fill();
                }

                // Hover / selected outer ring
                if (isHovered || isSelected) {
                  ctx.beginPath();
                  ctx.arc(x, y, style.radius + 5, 0, 2 * Math.PI);
                  ctx.strokeStyle = isSelected ? "#ffffff" : `${style.color}99`;
                  ctx.lineWidth = isSelected ? 1.5 : 1;
                  ctx.stroke();
                }

                // Main circle
                ctx.beginPath();
                ctx.arc(x, y, style.radius, 0, 2 * Math.PI);
                ctx.fillStyle = style.color;
                ctx.shadowColor = style.glow;
                ctx.shadowBlur = isHovered ? 20 : 10;
                ctx.fill();
                ctx.shadowBlur = 0;

                
                if (style.radius >= 10) {
                  ctx.beginPath();
                  ctx.arc(
                    x - style.radius * 0.3,
                    y - style.radius * 0.3,
                    style.radius * 0.25,
                    0,
                    2 * Math.PI,
                  );
                  ctx.fillStyle = "rgba(255,255,255,0.3)";
                  ctx.fill();
                }

                // Label
                const fontSize = node.isFirewall || node.isServer ? 11 : 10;
                ctx.font = `${node.isFirewall || node.isServer ? 600 : 400} ${fontSize}px ui-sans-serif,system-ui,sans-serif`;
                ctx.textAlign = "center";

                // Label background pill
                const labelText = node.label || node.id;
                const textW = ctx.measureText(labelText).width;
                const lx = x,
                  ly = y + style.radius + 14;
                ctx.fillStyle = "rgba(2,6,23,0.75)";
                ctx.beginPath();
                ctx.roundRect(lx - textW / 2 - 5, ly - 9, textW + 10, 13, 3);
                ctx.fill();

                ctx.fillStyle = node.isFirewall
                  ? "#93c5fd"
                  : node.isServer
                    ? "#86efac"
                    : node.isSafeCluster
                      ? "#67e8f9"
                      : "#cbd5e1";
                ctx.fillText(labelText, lx, ly);

                
                if (
                  node.sublabel &&
                  (node.isFirewall || node.isServer || node.isSafeCluster)
                ) {
                  ctx.font = `400 9px ui-sans-serif,system-ui,sans-serif`;
                  ctx.fillStyle = C.textDim;
                  ctx.fillText(node.sublabel, lx, ly + 12);
                }

                ctx.restore();
              }}
            />
          )}

          
          {graph.nodes.length === 0 && (
            <div
              style={{
                position: "absolute",
                inset: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexDirection: "column",
                gap: 8,
              }}
            >
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: "50%",
                  background: "rgba(100,116,139,0.1)",
                  border: `1px solid ${C.border}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 16,
                }}
              >
                ◎
              </div>
              <span style={{ fontSize: 13, color: C.textDim }}>
                Waiting for traffic data
              </span>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
