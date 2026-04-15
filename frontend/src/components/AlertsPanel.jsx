
"use client";

import { useEffect, useRef, useState } from "react";
import { getAlerts } from "../lib/api";

function AlertsPanel() {
  const [alerts, setAlerts] = useState([]);
  const tableRef = useRef(null);

  useEffect(() => {
    const fetchData = async () => {
      const data = await getAlerts();
      setAlerts(data);
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (tableRef.current) {
      tableRef.current.scrollTop = 0;
    }
  }, [alerts]);

  const getRiskColor = (risk) => {
    if (risk > 70) return "text-red-400";
    if (risk > 40) return "text-yellow-400";
    return "text-green-400";
  };

  return (
    <div className="w-full h-[300px] flex flex-col">
      <h2 className="mb-2 font-semibold">Alerts</h2>

      <div
        ref={tableRef}
        className="flex-1 overflow-y-auto border rounded"
      >
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-gray-900 text-gray-400">
            <tr>
              <th className="px-2 py-1">Attack</th>
              <th className="px-2 py-1">Risk</th>
              <th className="px-2 py-1">Action</th>
            </tr>
          </thead>

          <tbody>
            {alerts.slice(0, 15).map((a, i) => (
              <tr key={i} className="border-b">
                <td className="px-2 py-1">{a.attack_type}</td>

                <td className={`px-2 py-1 ${getRiskColor(a.risk)}`}>
                  {Math.round(a.risk)}%
                </td>

                <td className="px-2 py-1">{a.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AlertsPanel;