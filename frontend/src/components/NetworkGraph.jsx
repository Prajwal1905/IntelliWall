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
  }, []);

  return (
    <div className="p-4 border rounded">
      <h2>Network Graph</h2>
      <p>Total Nodes: {alerts.length}</p>
    </div>
  );
}

export default NetworkGraph;