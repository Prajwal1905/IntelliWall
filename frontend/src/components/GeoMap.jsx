"use client";

import { useState, useEffect, useRef } from "react";

const C = {
  pageBg: "#020617",
  cardBg2: "#0f172a",
  border: "#1e293b",
  textSecondary: "#94a3b8",
  textMuted: "#64748b",
  textDim: "#475569",
  green: "#22c55e",
  greenBg: "rgba(34,197,94,0.08)",
  greenBorder: "rgba(34,197,94,0.2)",
  red: "#f87171",
  redBg: "rgba(248,113,113,0.08)",
  redBorder: "rgba(248,113,113,0.2)",
  orange: "#fb923c",
  orangeBg: "rgba(251,146,60,0.08)",
  orangeBorder: "rgba(251,146,60,0.2)",
  purple: "#c084fc",
  purpleBg: "rgba(192,132,252,0.08)",
  purpleBorder: "rgba(192,132,252,0.2)",
};

const ACTION_STYLE = {
  BLOCK: {
    color: "#f87171",
    border: "rgba(248,113,113,0.25)",
    bg: "rgba(248,113,113,0.1)",
  },
  CHALLENGE: {
    color: "#fb923c",
    border: "rgba(251,146,60,0.25)",
    bg: "rgba(251,146,60,0.1)",
  },
  HONEYPOT: {
    color: "#c084fc",
    border: "rgba(192,132,252,0.25)",
    bg: "rgba(192,132,252,0.1)",
  },
  ALLOW: {
    color: "#22c55e",
    border: "rgba(34,197,94,0.25)",
    bg: "rgba(34,197,94,0.1)",
  },
};

function getActionStyle(action) {
  return ACTION_STYLE[action] || ACTION_STYLE.ALLOW;
}
function getMarkerColor(action) {
  return (ACTION_STYLE[action] || ACTION_STYLE.ALLOW).color;
}

const SERVER_LOCATION = [19.033, 73.0297];
const LEGEND = [
  { label: "Blocked", color: "#f87171" },
  { label: "Challenge", color: "#fb923c" },
  { label: "Honeypot", color: "#c084fc" },
  { label: "Allowed", color: "#22c55e" },
];

export default function GeoMap({ alerts = [] }) {
  const [leaflet, setLeaflet] = useState(null);
  const [blacklist, setBlacklist] = useState([]);
  const [selected, setSelected] = useState(null);
  const mapRef = useRef(null);

  useEffect(() => {
    import("react-leaflet").then((mod) => setLeaflet(mod));
  }, []);

  useEffect(() => {
    const fetchBL = async () => {
      try {
        const res = await fetch("http://localhost:8000/honeypot/blacklist");
        const data = await res.json();
        setBlacklist(data.blocked_ips || []);
      } catch (e) {
        console.error(e);
      }
    };
    fetchBL();
    const id = setInterval(fetchBL, 3000);
    return () => clearInterval(id);
  }, []);

  if (!leaflet)
    return (
      <div
        style={{
          width: "100%",
          height: "100%",
          background: C.pageBg,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
        }}
      >
        <div
          style={{
            width: 14,
            height: 14,
            border: `2px solid ${C.border}`,
            borderTopColor: C.green,
            borderRadius: "50%",
            animation: "spin 0.8s linear infinite",
          }}
        />
        <span style={{ fontSize: 12, color: C.textDim }}>Loading map...</span>
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );

  const { MapContainer, TileLayer, CircleMarker, Popup, Polyline } = leaflet;

  // ── BUILD CLUSTER MAP ──
  const locationMap = {};
  (Array.isArray(alerts) ? alerts : [])
    .filter((a) => a.lat != null && a.lon != null && a.lat !== 0 && a.lon !== 0)
    .forEach((a) => {
      const key = `${a.lat.toFixed(2)}_${a.lon.toFixed(2)}`;
      if (!locationMap[key]) {
        locationMap[key] = {
          lat: a.lat,
          lon: a.lon,
          count: 0,
          maxRisk: 0,
          action: a.action,
          country: a.country,
          isp: a.isp,
          sources: [],
          isBlacklisted: false,
        };
      }
      locationMap[key].isBlacklisted =
        locationMap[key].isBlacklisted || blacklist.includes(a.source);
      locationMap[key].count++;
      locationMap[key].maxRisk = Math.max(
        locationMap[key].maxRisk,
        a.risk || 0,
      );
      locationMap[key].sources.push(a.source);
      if (a.action === "BLOCK") locationMap[key].action = "BLOCK";
      else if (a.action === "HONEYPOT" && locationMap[key].action !== "BLOCK")
        locationMap[key].action = "HONEYPOT";
      else if (
        a.action === "CHALLENGE" &&
        !["BLOCK", "HONEYPOT"].includes(locationMap[key].action)
      )
        locationMap[key].action = "CHALLENGE";
    });

  const clustered = Object.values(locationMap);
  const attackPoints = clustered.filter((a) => a.action !== "ALLOW");

  const stats = {
    blocked: clustered.filter((a) => a.action === "BLOCK").length,
    challenge: clustered.filter((a) => a.action === "CHALLENGE").length,
    honeypot: clustered.filter((a) => a.action === "HONEYPOT").length,
    countries: new Set(clustered.map((a) => a.country).filter(Boolean)).size,
  };

  return (
    <>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        .leaflet-container { font-family: ui-sans-serif, system-ui, sans-serif !important; }
        .leaflet-popup-content-wrapper {
          background: #0f172a !important;
          border: 1px solid #1e293b !important;
          border-radius: 10px !important;
          box-shadow: 0 4px 24px rgba(0,0,0,0.5) !important;
          padding: 0 !important;
          color: #94a3b8 !important;
        }
        .leaflet-popup-content { margin: 0 !important; padding: 0 !important; }
        .leaflet-popup-tip-container { display: none !important; }
        .leaflet-popup-close-button { color: #475569 !important; top: 8px !important; right: 8px !important; font-size: 16px !important; }
        .leaflet-popup-close-button:hover { color: #94a3b8 !important; }
        .leaflet-control-zoom { border: 1px solid #1e293b !important; border-radius: 8px !important; overflow: hidden; }
        .leaflet-control-zoom a { background: #0f172a !important; color: #94a3b8 !important; border-bottom: 1px solid #1e293b !important; }
        .leaflet-control-zoom a:hover { background: #1e293b !important; color: #fff !important; }
        .leaflet-control-attribution { background: rgba(2,6,23,0.7) !important; color: #334155 !important; font-size: 9px !important; }
        .leaflet-control-attribution a { color: #475569 !important; }
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
            gap: 8,
            flexWrap: "wrap",
          }}
        >
          <div style={{ display: "flex", gap: 8 }}>
            {[
              {
                label: "Blocked",
                val: stats.blocked,
                ...C,
                color: "#f87171",
                bg: C.redBg,
                border: C.redBorder,
              },
              {
                label: "Challenge",
                val: stats.challenge,
                color: "#fb923c",
                bg: C.orangeBg,
                border: C.orangeBorder,
              },
              {
                label: "Honeypot",
                val: stats.honeypot,
                color: "#c084fc",
                bg: C.purpleBg,
                border: C.purpleBorder,
              },
              {
                label: "Countries",
                val: stats.countries,
                color: C.green,
                bg: C.greenBg,
                border: C.greenBorder,
              },
            ].map(({ label, val, color, bg, border }) => (
              <div
                key={label}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "4px 10px",
                  background: bg,
                  border: `1px solid ${border}`,
                  borderRadius: 6,
                }}
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

         
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            {LEGEND.map(({ label, color }) => (
              <div
                key={label}
                style={{ display: "flex", alignItems: "center", gap: 5 }}
              >
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: color,
                    display: "inline-block",
                    boxShadow: `0 0 5px ${color}80`,
                    flexShrink: 0,
                  }}
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
            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span
                style={{
                  width: 16,
                  height: 2,
                  background: `repeating-linear-gradient(90deg, #64748b 0, #64748b 4px, transparent 4px, transparent 8px)`,
                  display: "inline-block",
                }}
              />
              <span style={{ fontSize: 10, color: C.textDim }}>
                Attack path
              </span>
            </div>
          </div>
        </div>

       
        <div
          style={{
            flex: 1,
            borderRadius: 10,
            overflow: "hidden",
            border: `1px solid ${C.border}`,
            position: "relative",
          }}
        >
          <MapContainer
            center={[20, 0]}
            zoom={2}
            scrollWheelZoom={true}
            style={{ height: "100%", width: "100%", background: C.pageBg }}
            ref={mapRef}
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://www.openstreetmap.org">OSM</a> &copy; <a href="https://carto.com">CARTO</a>'
            />

            
            {attackPoints.map((a, i) => (
              <Polyline
                key={`line-${i}`}
                positions={[[a.lat, a.lon], SERVER_LOCATION]}
                pathOptions={{
                  color: getMarkerColor(a.action),
                  weight: 1,
                  opacity: a.isBlacklisted ? 0.1 : 0.35,
                  dashArray: "5 7",
                }}
              />
            ))}

            {clustered.map((a, i) => {
              const color = getMarkerColor(a.action);
              const intensity = a.count + a.maxRisk / 20;
              const radius = Math.min(18, 5 + intensity * 0.8);
              const opacity = a.isBlacklisted
                ? 0.15
                : Math.min(0.9, 0.35 + intensity / 12);

              return (
                <div key={`mk-${i}`}>
                  
                  <CircleMarker
                    center={[a.lat, a.lon]}
                    radius={radius * 2}
                    pathOptions={{
                      color: "transparent",
                      fillColor: color,
                      fillOpacity: 0.06,
                    }}
                  />
                  
                  <CircleMarker
                    center={[a.lat, a.lon]}
                    radius={radius}
                    pathOptions={{
                      color,
                      weight: 1,
                      fillColor: color,
                      fillOpacity: opacity,
                    }}
                    eventHandlers={{ click: () => setSelected(a) }}
                  >
                    <Popup>
                      <div style={{ padding: "12px 14px", minWidth: 180 }}>
                        
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            marginBottom: 10,
                            paddingBottom: 8,
                            borderBottom: `1px solid ${C.border}`,
                          }}
                        >
                          <span
                            style={{
                              fontSize: 11,
                              fontWeight: 700,
                              color: "#e2e8f0",
                              letterSpacing: "0.04em",
                            }}
                          >
                            {a.country || "Unknown"}
                          </span>
                          <span
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              padding: "2px 7px",
                              borderRadius: 5,
                              color: getActionStyle(a.action).color,
                              background: getActionStyle(a.action).bg,
                              border: `1px solid ${getActionStyle(a.action).border}`,
                            }}
                          >
                            {a.action}
                          </span>
                        </div>
                        {[
                          ["ISP", a.isp || "—"],
                          ["Risk", `${a.maxRisk}%`],
                          ["Attacks", a.count],
                          ["Sources", a.sources.length],
                        ].map(([k, v]) => (
                          <div
                            key={k}
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              padding: "3px 0",
                              fontSize: 11,
                            }}
                          >
                            <span style={{ color: C.textMuted }}>{k}</span>
                            <span
                              style={{
                                color: "#cbd5e1",
                                fontFamily: "ui-monospace,monospace",
                                fontSize: 10,
                              }}
                            >
                              {v}
                            </span>
                          </div>
                        ))}
                      </div>
                    </Popup>
                  </CircleMarker>
                </div>
              );
            })}

            
            <CircleMarker
              center={SERVER_LOCATION}
              radius={32}
              pathOptions={{
                color: C.green,
                fillColor: C.green,
                fillOpacity: 0.04,
                weight: 0,
              }}
            />
            <CircleMarker
              center={SERVER_LOCATION}
              radius={20}
              pathOptions={{
                color: C.green,
                fillColor: C.green,
                fillOpacity: 0.08,
                weight: 0,
              }}
            />
            
            <CircleMarker
              center={SERVER_LOCATION}
              radius={11}
              pathOptions={{
                color: C.green,
                fillColor: "#022c22",
                fillOpacity: 1,
                weight: 1.5,
              }}
            />
            
            <CircleMarker
              center={SERVER_LOCATION}
              radius={7}
              pathOptions={{
                color: "transparent",
                fillColor: C.green,
                fillOpacity: 1,
              }}
            >
              <Popup>
                <div style={{ padding: "12px 14px" }}>
                  <div
                    style={{
                      fontSize: 11,
                      fontWeight: 700,
                      color: C.green,
                      marginBottom: 4,
                    }}
                  >
                    Protected Server
                  </div>
                  <div style={{ fontSize: 11, color: C.textMuted }}>
                    Mumbai, India
                  </div>
                  <div style={{ fontSize: 10, color: C.textDim, marginTop: 4 }}>
                    19.033°N 73.029°E
                  </div>
                </div>
              </Popup>
            </CircleMarker>
          </MapContainer>

          
          <div
            style={{
              position: "absolute",
              bottom: 12,
              right: 12,
              zIndex: 1000,
              background: "rgba(2,6,23,0.8)",
              border: `1px solid ${C.border}`,
              borderRadius: 8,
              padding: "6px 10px",
              display: "flex",
              alignItems: "center",
              gap: 6,
              pointerEvents: "none",
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: C.green,
                boxShadow: `0 0 6px ${C.green}`,
                display: "inline-block",
              }}
            />
            <span
              style={{ fontSize: 11, color: C.textSecondary, fontWeight: 500 }}
            >
              Protected server — Mumbai
            </span>
          </div>
        </div>
      </div>
    </>
  );
}
