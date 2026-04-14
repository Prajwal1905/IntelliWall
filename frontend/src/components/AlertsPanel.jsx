"use client";

import { useEffect, useState } from "react";
import { getAlerts } from "../lib/api";

function AlertsPanel() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const data = await getAlerts();
      setAlerts(data);
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="p-4 border rounded">
      <h2 className="mb-2">Alerts</h2>

      <table className="w-full text-sm">
        <thead>
          <tr>
            <th>Attack</th>
            <th>Risk</th>
            <th>Action</th>
          </tr>
        </thead>

        <tbody>
          {alerts.slice(0, 10).map((a, i) => (
            <tr key={i}>
              <td>{a.attack_type}</td>
              <td>{Math.round(a.risk)}%</td>
              <td>{a.action}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default AlertsPanel;