"use client";

import { useState, useEffect } from "react";

const C = {
  pageBg:   "#020617",
  cardBg2:  "#0f172a",
  border:   "#1e293b",
  textSecondary: "#94a3b8",
  textMuted:     "#64748b",
  textDim:       "#475569",
  purple:   "#c084fc",
  purpleBg: "rgba(192,132,252,0.08)",
  purpleBorder: "rgba(192,132,252,0.2)",
  red:      "#f87171",
  redBg:    "rgba(248,113,113,0.08)",
  redBorder:"rgba(248,113,113,0.2)",
  yellow:   "#fbbf24",
  yellowBg: "rgba(251,191,36,0.08)",
  yellowBorder: "rgba(251,191,36,0.2)",
  green:    "#22c55e",
  greenBg:  "rgba(34,197,94,0.08)",
  greenBorder: "rgba(34,197,94,0.2)",
};

function riskColor(r) {
  if (r >= 70) return { color: C.red,    bg: C.redBg,    border: C.redBorder    };
  if (r >= 40) return { color: C.yellow, bg: C.yellowBg, border: C.yellowBorder };
  return             { color: C.purple, bg: C.purpleBg, border: C.purpleBorder };
}

export default function HoneypotMap({ logs = [] }) {
  const [leaflet, setLeaflet] = useState(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    import("react-leaflet").then(mod => setLeaflet(mod));
  }, []);

  const valid = logs.filter(l => l.lat && l.lon && l.lat !== 0 && l.lon !== 0);

  
  const locationMap = {};
  valid.forEach(l => {
    const key = `${(+l.lat).toFixed(2)}_${(+l.lon).toFixed(2)}`;
    if (!locationMap[key]) {
      locationMap[key] = { lat: l.lat, lon: l.lon, count: 0, maxRisk: 0, sources: [], attackTypes: new Set() };
    }
    locationMap[key].count++;
    locationMap[key].maxRisk = Math.max(locationMap[key].maxRisk, l.risk || 0);
    locationMap[key].sources.push(l.source);
    if (l.attack_type) locationMap[key].attackTypes.add(l.attack_type);
  });
  const clustered = Object.values(locationMap);

  
  const stats = {
    total:    valid.length,
    critical: valid.filter(l => (l.risk || 0) >= 70).length,
    countries: new Set(valid.map(l => l.country).filter(Boolean)).size,
  };

  if (!leaflet) return (
    <div style={{ width: "100%", height: "100%", background: C.pageBg, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, borderRadius: 10, border: `1px solid ${C.border}` }}>
      <div style={{ width: 14, height: 14, border: `2px solid ${C.border}`, borderTopColor: C.purple, borderRadius: "50%", animation: "hm-spin 0.8s linear infinite" }} />
      <span style={{ fontSize: 12, color: C.textDim }}>Loading map...</span>
      <style>{`@keyframes hm-spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );

  const { MapContainer, TileLayer, CircleMarker, Popup } = leaflet;

  return (
    <>
      <style>{`
        @keyframes hm-spin { to { transform: rotate(360deg); } }
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
        .leaflet-popup-close-button { color: #475569 !important; top: 8px !important; right: 8px !important; }
        .leaflet-control-zoom { border: 1px solid #1e293b !important; border-radius: 8px !important; overflow: hidden; }
        .leaflet-control-zoom a { background: #0f172a !important; color: #94a3b8 !important; border-bottom: 1px solid #1e293b !important; }
        .leaflet-control-zoom a:hover { background: #1e293b !important; color: #fff !important; }
        .leaflet-control-attribution { background: rgba(2,6,23,0.7) !important; color: #334155 !important; font-size: 9px !important; }
        .leaflet-control-attribution a { color: #475569 !important; }
      `}</style>

      <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: 0 }}>

        
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 4px 10px", flexShrink: 0, gap: 8 }}>
          <div style={{ display: "flex", gap: 8 }}>
            {[
              { label: "Honeypot hits", val: stats.total,    color: C.purple, bg: C.purpleBg, border: C.purpleBorder },
              { label: "Critical",      val: stats.critical, color: C.red,    bg: C.redBg,    border: C.redBorder    },
              { label: "Countries",     val: stats.countries,color: C.yellow, bg: C.yellowBg, border: C.yellowBorder },
            ].map(({ label, val, color, bg, border }) => (
              <div key={label} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", background: bg, border: `1px solid ${border}`, borderRadius: 6 }}>
                <span style={{ fontSize: 14, fontWeight: 700, color }}>{val}</span>
                <span style={{ fontSize: 10, color, opacity: 0.8, fontWeight: 500, letterSpacing: "0.04em" }}>{label}</span>
              </div>
            ))}
          </div>

          
          <div style={{ display: "flex", gap: 12 }}>
            {[
              { label: "Low",      color: C.purple },
              { label: "Medium",   color: C.yellow },
              { label: "Critical", color: C.red    },
            ].map(({ label, color }) => (
              <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, boxShadow: `0 0 5px ${color}80`, display: "inline-block", flexShrink: 0 }} />
                <span style={{ fontSize: 10, color: C.textDim }}>{label}</span>
              </div>
            ))}
          </div>
        </div>

        
        <div style={{ flex: 1, borderRadius: 10, overflow: "hidden", border: `1px solid ${C.border}`, position: "relative" }}>
          <MapContainer
            center={[20, 0]}
            zoom={2}
            scrollWheelZoom={true}
            style={{ height: "100%", width: "100%", background: C.pageBg }}
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://www.openstreetmap.org">OSM</a> &copy; <a href="https://carto.com">CARTO</a>'
            />

            {clustered.map((a, i) => {
              const s      = riskColor(a.maxRisk);
              const radius = Math.min(18, 5 + a.count * 1.5 + a.maxRisk / 20);
              const topType = [...a.attackTypes][0] || "Unknown";

              return (
                <div key={i}>
                 
                  <CircleMarker
                    center={[a.lat, a.lon]}
                    radius={radius * 2.2}
                    pathOptions={{ color: "transparent", fillColor: s.color, fillOpacity: 0.07, weight: 0 }}
                  />
                  
                  <CircleMarker
                    center={[a.lat, a.lon]}
                    radius={radius}
                    pathOptions={{ color: s.color, weight: 1, fillColor: s.color, fillOpacity: 0.75 }}
                  >
                    <Popup>
                      <div style={{ padding: "12px 14px", minWidth: 190 }}>
                        
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10, paddingBottom: 8, borderBottom: `1px solid ${C.border}` }}>
                          <span style={{ fontSize: 11, fontWeight: 700, color: "#e2e8f0", letterSpacing: "0.04em", fontFamily: "ui-monospace,monospace" }}>
                            {a.sources[0] || "Unknown"}
                          </span>
                          <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 5, color: s.color, background: s.bg, border: `1px solid ${s.border}` }}>
                            Risk {a.maxRisk}
                          </span>
                        </div>
                        {[
                          ["Attack type", topType],
                          ["Total hits",  a.count],
                          ["Unique IPs",  a.sources.length],
                          ["Location",    `${a.lat.toFixed(2)}°, ${a.lon.toFixed(2)}°`],
                        ].map(([k, v]) => (
                          <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "3px 0", fontSize: 11 }}>
                            <span style={{ color: C.textMuted }}>{k}</span>
                            <span style={{ color: "#cbd5e1", fontFamily: "ui-monospace,monospace", fontSize: 10 }}>{v}</span>
                          </div>
                        ))}
                      </div>
                    </Popup>
                  </CircleMarker>
                </div>
              );
            })}

           
            {clustered.length === 0 && (
              <div style={{ position: "absolute", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}>
                <div style={{ background: "rgba(2,6,23,0.85)", border: `1px solid ${C.border}`, borderRadius: 10, padding: "12px 20px", display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 13, color: C.textDim }}>No honeypot geo data</span>
                </div>
              </div>
            )}
          </MapContainer>

          
          {stats.total > 0 && (
            <div style={{ position: "absolute", bottom: 12, left: 12, zIndex: 1000, background: "rgba(2,6,23,0.85)", border: `1px solid ${C.purpleBorder}`, borderRadius: 8, padding: "5px 10px", display: "flex", alignItems: "center", gap: 6, pointerEvents: "none" }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.purple, boxShadow: `0 0 6px ${C.purple}`, display: "inline-block" }} />
              <span style={{ fontSize: 11, color: C.purple, fontWeight: 500 }}>{stats.total} honeypot events</span>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
