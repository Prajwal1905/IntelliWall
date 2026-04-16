"use client";
import { useState } from "react";

const C = {
  pageBg:  "#020617",
  cardBg:  "#0a1628",
  cardBg2: "#0f172a",
  border:  "#1e293b",
  border2: "#334155",
  textPrimary:   "#ffffff",
  textSecondary: "#94a3b8",
  textMuted:     "#64748b",
  textDim:       "#475569",
  blue:    "#3b82f6",
  blueBg:  "rgba(59,130,246,0.08)",
  blueBorder: "rgba(59,130,246,0.25)",
  green:   "#22c55e",
  red:     "#f87171",
  redBg:   "rgba(220,38,38,0.10)",
  redBorder: "rgba(220,38,38,0.25)",
};

export default function LoginPage() {
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState("");
  const [focusEmail, setFocusEmail]     = useState(false);
  const [focusPassword, setFocusPassword] = useState(false);

  const handleLogin = async () => {
    if (!email || !password) { setError("Please fill in all fields"); return; }
    setLoading(true);
    setError("");
    try {
      const res  = await fetch("http://127.0.0.1:8000/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (data.token) {
        localStorage.setItem("token", data.token);
        window.location.href = "/";
      } else {
        setError("Invalid credentials");
      }
    } catch {
      setError("Cannot connect to server");
    }
    setLoading(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleLogin();
  };

  return (
    <>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .login-input::placeholder { color: #475569; }
        .login-input:focus { border-color: #3b82f6 !important; outline: none; }
        .login-btn:hover:not(:disabled) { background: #2563eb !important; }
        .login-btn:active:not(:disabled) { transform: scale(0.99); }
      `}</style>

      <div style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: C.pageBg,
        position: "relative",
        overflow: "hidden",
      }}>

        
        <div style={{
          position: "absolute", inset: 0, pointerEvents: "none",
          backgroundImage: `linear-gradient(rgba(30,41,59,0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(30,41,59,0.4) 1px, transparent 1px)`,
          backgroundSize: "40px 40px",
          opacity: 0.4,
        }} />

       
        <div style={{
          background: C.cardBg,
          border: `1px solid ${C.border2}`,
          borderRadius: 20,
          padding: "44px 40px",
          width: "100%",
          maxWidth: 420,
          position: "relative",
          zIndex: 1,
          animation: "fadeIn 0.35s ease-out",
        }}>

          
          <div style={{ textAlign: "center", marginBottom: 36 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, marginBottom: 12 }}>
              <div style={{
                width: 10, height: 10, borderRadius: "50%",
                background: C.green, boxShadow: `0 0 8px ${C.green}`,
              }} />
              <h1 style={{ fontSize: 28, fontWeight: 700, color: C.textPrimary, margin: 0, letterSpacing: "0.04em" }}>
                IntelliWall
              </h1>
            </div>
            <p style={{ fontSize: 13, color: C.textMuted, margin: 0 }}>
              Next-Gen AI Firewall — Secure Access
            </p>
          </div>

          
          <div style={{ height: 1, background: C.border, marginBottom: 32 }} />

          
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

            
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", display: "block", marginBottom: 7 }}>
                Email
              </label>
              <input
                className="login-input"
                type="email"
                placeholder="admin@intelliwall.io"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={handleKeyDown}
                style={{
                  width: "100%", height: 46,
                  padding: "0 14px",
                  borderRadius: 10,
                  background: C.cardBg2,
                  color: C.textPrimary,
                  border: `1px solid ${focusEmail ? C.blue : C.border}`,
                  fontSize: 14,
                  boxSizing: "border-box",
                  transition: "border-color 0.2s",
                  fontFamily: "inherit",
                }}
                onFocus={() => setFocusEmail(true)}
                onBlur={() => setFocusEmail(false)}
              />
            </div>

            
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: C.textMuted, textTransform: "uppercase", letterSpacing: "0.07em", display: "block", marginBottom: 7 }}>
                Password
              </label>
              <input
                className="login-input"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={handleKeyDown}
                style={{
                  width: "100%", height: 46,
                  padding: "0 14px",
                  borderRadius: 10,
                  background: C.cardBg2,
                  color: C.textPrimary,
                  border: `1px solid ${focusPassword ? C.blue : C.border}`,
                  fontSize: 14,
                  boxSizing: "border-box",
                  transition: "border-color 0.2s",
                  fontFamily: "inherit",
                }}
                onFocus={() => setFocusPassword(true)}
                onBlur={() => setFocusPassword(false)}
              />
            </div>

            
            {error && (
              <div style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "10px 14px",
                background: C.redBg, border: `1px solid ${C.redBorder}`,
                borderRadius: 8, fontSize: 13, color: C.red,
              }}>
                <span style={{ fontSize: 14 }}>⚠</span>
                {error}
              </div>
            )}

           
            <button
              className="login-btn"
              onClick={handleLogin}
              disabled={loading}
              style={{
                width: "100%", height: 46,
                borderRadius: 10,
                background: loading ? "rgba(37,99,235,0.7)" : C.blue,
                color: "white",
                fontWeight: 600, fontSize: 14,
                border: "none",
                cursor: loading ? "not-allowed" : "pointer",
                transition: "background 0.2s, transform 0.1s",
                display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
                marginTop: 4,
                fontFamily: "inherit",
                letterSpacing: "0.02em",
              }}
            >
              {loading && (
                <span style={{
                  width: 14, height: 14,
                  border: "2px solid rgba(255,255,255,0.3)",
                  borderTopColor: "white",
                  borderRadius: "50%",
                  display: "inline-block",
                  animation: "spin 0.7s linear infinite",
                }} />
              )}
              {loading ? "Signing in..." : "Sign In"}
            </button>

          </div>

          
          <div style={{ marginTop: 32, paddingTop: 20, borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, color: C.textDim }}>IntelliWall v2.0</span>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, display: "inline-block", boxShadow: `0 0 5px ${C.green}` }} />
              <span style={{ fontSize: 11, color: C.textDim }}>System online</span>
            </div>
          </div>

        </div>
      </div>
    </>
  );
}
