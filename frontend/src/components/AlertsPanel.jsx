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
  }, []);

  return (
    <div>
      <h2>Alerts</h2>

      <ul>
        {alerts.slice(0, 5).map((a, i) => (
          <li key={i}>
            {a.attack_type} - {a.action}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default AlertsPanel;