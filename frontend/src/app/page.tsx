"use client";

import { useEffect, useState } from "react";
import { getAlerts } from "../lib/api";

export default function Home() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const data = await getAlerts();
      setAlerts(data);
    };

    fetchData();
  }, []);

  return (
    <div>
      <h1>IntelliWall Dashboard</h1>

      <p>Total Alerts: {alerts.length}</p>
    </div>
  );
}