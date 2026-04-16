const BASE_URL = "http://127.0.0.1:8000";

function getAuthHeaders() {
  const token = localStorage.getItem("token");

  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

function handleAuthError(res) {
  if (res.status === 401 || res.status === 403) {
    localStorage.removeItem("token");
    window.location.href = "/login";
    return true;
  }
  return false;
}

export async function analyzeTraffic(data) {
  try {
    const res = await fetch(`${BASE_URL}/analyze`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });

    if (!res.ok) throw new Error("Analyze failed");

    return await res.json();
  } catch {
    localStorage.removeItem("token");
    window.location.href = "/login";
    return [];
  }
}

export async function getAlerts() {
  try {
    const token = localStorage.getItem("token");
    if (!token) return [];

    const res = await fetch(`${BASE_URL}/alerts`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (handleAuthError(res)) return [];

    const data = await res.json();
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}


export async function getRisk() {
  try {
    const res = await fetch(`${BASE_URL}/risk`, {
      headers: getAuthHeaders(),
    });

    if (handleAuthError(res)) return 5;

    const data = await res.json();
    return data.risk || 5;
  } catch {
    localStorage.removeItem("token");
    window.location.href = "/login";
    return 5;
  }
}