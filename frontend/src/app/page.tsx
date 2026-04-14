"use client";

import { useEffect, useState } from "react";
import { getAlerts } from "../lib/api";
import MetricsBar from "../components/MetricsBar";

export default function Home() {
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    const fetchData = async () => {
      const data = await getAlerts();
      setAlerts(data);
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const totalAlerts = alerts.length;
  const blocked = alerts.filter(a => a.action === "BLOCK").length;

  return (
    <div className="p-6">
      <h1 className="text-xl font-bold mb-4">IntelliWall Dashboard</h1>

      <MetricsBar alerts={totalAlerts} blocked={blocked} />
    </div>
  );
}