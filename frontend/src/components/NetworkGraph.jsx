"use client";

import { useEffect, useState, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";
import * as d3 from "d3-force";

function NetworkGraph() {
  const [graph, setGraph] = useState({ nodes: [], links: [] });
  const [alerts, setAlerts] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [size, setSize] = useState({ w: 800, h: 400 });
  const fgRef = useRef(null);
  const FIREWALL = "Firewall";
  const SERVER = "Main Server";
  const SAFE_NODE = "Safe Traffic";
  const [hoverNode, setHoverNode] = useState(null);
  const [blacklist, setBlacklist] = useState([]);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const token = localStorage.getItem("token");

        if (!token) return;

        const res = await fetch("http://127.0.0.1:8000/alerts", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        const data = await res.json();

        // ✅ ensure array
        setAlerts(Array.isArray(data) ? data : []);
        const bl = await fetch("http://127.0.0.1:8000/honeypot/blacklist");
        const blData = await bl.json();
        setBlacklist(blData.blocked_ips || []);
      } catch (e) {
        console.error(e);
      }
    };

    fetchAlerts();
    const i = setInterval(fetchAlerts, 2000);
    return () => clearInterval(i);
  }, []);

  useEffect(() => {
    const nodesMap = new Map();
    const links = [];

    const attackMap = {};

    (Array.isArray(alerts) ? alerts : []).forEach((a) => {
      if (!a.source) return;

      const action = (a.action || "").toUpperCase().trim();

      if (!attackMap[a.source]) {
        attackMap[a.source] = {
          count: 0,
          maxRisk: 0,
          action: action,
        };
      }

      attackMap[a.source].count += 1;
      attackMap[a.source].maxRisk = Math.max(
        attackMap[a.source].maxRisk,
        a.risk || 0,
      );
      attackMap[a.source].action = action;
    });

    const safe = alerts.filter(
      (a) => (a.action || "").toUpperCase().trim() === "ALLOW",
    );

    const uniqueAttackIPs = new Set(
      alerts
        .filter((a) => {
          const act = (a.action || "").toUpperCase().trim();
          return act === "BLOCK" || act === "CHALLENGE" || act === "HONEYPOT";
        })
        .map((a) => a.source),
    );

    const attackCount = uniqueAttackIPs.size;

    //  FIREWALL
    nodesMap.set(FIREWALL, {
      id: FIREWALL,
      label: `${FIREWALL} (${attackCount})`,
      isFirewall: true,
      fx: 0,
      fy: 0,
    });

    //  SERVER
    nodesMap.set(SERVER, {
      id: SERVER,
      isServer: true,
      fx: 260,
      fy: 0,
    });
    const SAFE_CLUSTER = "Safe Cluster";

    nodesMap.set(SAFE_CLUSTER, {
      id: SAFE_CLUSTER,
      label: `Safe (${safe.length})`,
      isSafeCluster: true,
      fx: -220,
      fy: -120,
    });

    links.push({ source: SAFE_CLUSTER, target: FIREWALL });
    let blockIndex = 0;
    let honeypotIndex = 0;
    let challengeIndex = 0;
    Object.entries(attackMap)
      .filter(([ip, data]) => {
        if (blacklist.includes(ip)) return false; // 🚨 REMOVE BLOCKED
        return data.maxRisk >= 30;
      })
      .forEach(([ip, data], i) => {
        const attackType =
          alerts.find((a) => a.source === ip)?.attack_type || "Unknown";

        const isBlocked = data.action === "BLOCK";
        const isChallenge = data.action === "CHALLENGE";
        const isHoneypot = data.action === "HONEYPOT";
        const baseX = isBlocked ? -400 : isHoneypot ? 0 : 400;
        let idx;

        if (isBlocked) {
          idx = blockIndex++;
        } else if (isHoneypot) {
          idx = honeypotIndex++;
        } else if (isChallenge) {
          idx = challengeIndex++;
        }

        const total = isBlocked
          ? blockIndex
          : isHoneypot
            ? honeypotIndex
            : challengeIndex;

        const start = Math.PI / 6; // avoid straight horizontal line
        const end = Math.PI - Math.PI / 6;

        const angle = start + (idx / (total || 1)) * (end - start);
        const spacingX = 160;
        const spacingY = 120;

        const col = idx % 3;
        const row = Math.floor(idx / 3);
        nodesMap.set(ip, {
          id: ip,
          label: `${ip} (${data.count})`,
          risk: data.maxRisk,
          attackType,
          isBlocked,
          isBlacklisted: blacklist.includes(ip),
          isChallenge,
          isHoneypot,
          fx: baseX + col * spacingX,
          fy: 120 + row * spacingY,
        });
        links.push({
          source: ip,
          target: FIREWALL,
          isAttack: true,
          isBlocked,
          isBlacklisted: blacklist.includes(ip),
          isChallenge,
          isHoneypot,
        });
      });

    //  Firewall → Server
    links.push({ source: FIREWALL, target: SERVER });

    const newGraph = {
      nodes: [...nodesMap.values()],
      links,
    };

    setGraph(newGraph);
  }, [alerts, blacklist]);

  // Resize
  useEffect(() => {
    const el = document.getElementById("graph-container");
    if (el) {
      setSize({
        w: el.clientWidth,
        h: el.clientHeight,
      });
    }
  }, []);

  const initialized = useRef(false);

  useEffect(() => {
    if (fgRef.current && !initialized.current) {
      fgRef.current.zoomToFit(400, 80);
      initialized.current = true;
    }
  }, []);

  if (typeof window === "undefined") return null;
  if (!graph.nodes.length) return null;

  return (
    <div
      id="graph-container"
      className="w-full h-full bg-[#020617] relative overflow-hidden"
      style={{ height: "100%", width: "100%", position: "relative" }}
    >
      <ForceGraph2D
        ref={fgRef}
        width={size.w}
        height={size.h}
        graphData={graph}
        nodeId="id"
        linkSource="source"
        linkTarget="target"
        d3AlphaDecay={0.03}
        d3VelocityDecay={0.3}
        cooldownTicks={0}
        enableNodeDrag={true}
        enablePanInteraction={true}
        enableZoomInteraction={true}
        warmupTicks={50}
        style={{ position: "absolute", top: 0, left: 0 }}
        d3Force={(fg) => {
          fg.d3Force("charge").strength(-300);
          fg.d3Force("link").distance(280);
          fg.d3Force("collision", d3.forceCollide(30));
        }}
        onNodeHover={(node) => setHoverNode(node)}
        linkColor={(link) => {
          if (link.isBlacklisted) return "rgba(255,0,0,0.3)";
          if (link.isBlocked) return "#ff0000";
          if (link.isHoneypot) return "#ff00ff";
          if (link.isChallenge) return "#f97316";
          return "#00ff9c";
        }}
        linkWidth={(link) => (link.isAttack ? 4 : 2)}
        linkDirectionalParticles={(link) => (link.isAttack ? 4 : 0)}
        linkDirectionalParticleSpeed={0.004}
        linkDirectionalParticleWidth={4}
        nodeCanvasObject={(node, ctx) => {
          const x = node.x || 0;
          const y = node.y || 0;
          const time = Date.now();
          const pulse = (Math.sin(time / 200) + 1) * 2;

          let color = "#00ff9c";
          let size = 6;

          if (node.isFirewall) {
            color = "#22c55e";
            size = 16;
          } else if (node.isServer) {
            color = "#3b82f6";
            size = 12;
          } else if (node.isSafeCluster) {
            color = "#00ff9c";
            size = 12;
          } else if (node.isBlacklisted) {
            color = "#ff0000";
            size = 6;
            ctx.globalAlpha = 0.25;
          } else if (node.isBlocked) {
            color = "#ff0000";
            size = 6;
          } else if (node.isHoneypot) {
            color = "#ff00ff";
            size = 7;
            ctx.shadowColor = "#ff00ff";
            ctx.shadowBlur = 12;
          } else if (node.isChallenge) {
            color = "#f97316";
            size = 6;
          }

          ctx.beginPath();
          const finalSize = size;

          ctx.arc(x, y, finalSize, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          if (node.isBlocked) {
            ctx.shadowColor = "#ff0000";
            ctx.shadowBlur = 15;
          } else if (node.isChallenge) {
            ctx.shadowColor = "#f97316";
            ctx.shadowBlur = 10;
          } else if (!node.isHoneypot) {
            ctx.shadowBlur = 0;
          }
          ctx.fill();
          if (hoverNode?.id === node.id) {
            ctx.strokeStyle = "#ffffff";
            ctx.lineWidth = 2;
            ctx.stroke();
          }

          ctx.font = "10px sans-serif";
          ctx.fillStyle = "#fff";
          const label = node.isBlacklisted
            ? `${node.label || node.id} (BLOCKED)`
            : node.label || node.id;

          ctx.fillText(label, x + 10, y - 10);
          ctx.globalAlpha = 1;
        }}
      />
    </div>
  );
}

export default NetworkGraph;

"use client";

import { useEffect, useState, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";

function NetworkGraph() {
  const [graph, setGraph] = useState({ nodes: [], links: [] });
  const [alerts, setAlerts] = useState([]);
  const fgRef = useRef(null);

  useEffect(() => {
    const fetchData = async () => {
      const res = await fetch("http://localhost:8000/alerts");
      const data = await res.json();
      setAlerts(data || []);
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const nodes = [{ id: "Firewall" }];
    const links = [];

    alerts.slice(0, 15).forEach((a) => {
      if (!a.source) return;

      nodes.push({
        id: a.source,
        risk: a.risk,
        action: a.action,
      });

      links.push({
        source: a.source,
        target: "Firewall",
      });
    });

    setGraph({ nodes, links });
  }, [alerts]);

  if (!graph.nodes.length) return null;

  return (
    <div className="w-full h-[350px] bg-gray-900 rounded">
      <ForceGraph2D
        ref={fgRef}
        graphData={graph}
        nodeAutoColorBy="action"
        linkDirectionalParticles={2}
        linkDirectionalParticleSpeed={0.003}
      />
    </div>
  );
}

export default NetworkGraph;