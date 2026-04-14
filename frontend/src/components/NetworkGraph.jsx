"use client";

import { useEffect, useState } from "react";

function NetworkGraph() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const res = await fetch("http://localhost:8000/alerts");
      const data = await res.json();
      setAlerts(data || []);
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const nodes = alerts.map((a, i) => ({
    id: i,
    source: a.source,
    action: a.action,
  }));

  return (
    <div className="p-4 border rounded bg-gray-900 text-white">
      <h2 className="mb-2">Network Activity</h2>

      <ul className="text-sm space-y-1">
        {nodes.slice(0, 10).map((n) => (
          <li key={n.id}>
            {n.source} → {n.action}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default NetworkGraph;