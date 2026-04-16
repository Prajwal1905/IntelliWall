"use client";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

export default function HoneypotTimeline({ logs = [] }) {
  if (!logs || logs.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        No activity
      </div>
    );
  }

  const timeMap = {};

  logs.forEach((log) => {
    const t = log.timestamp.slice(11, 19); 

    if (!timeMap[t]) {
      timeMap[t] = {
        attacks: 0,
        totalRisk: 0,
        types: new Set(),
      };
    }

    timeMap[t].attacks += 1;
    timeMap[t].totalRisk += log.risk || 0;
    timeMap[t].types.add(log.attack_type);
  });

  const data = Object.entries(timeMap).map(([time, val]) => ({
    time,
    attacks: val.attacks,
    avgRisk: val.attacks ? val.totalRisk / val.attacks : 0,
    diversity: val.types.size,
  }));

  return (
    <div className="w-full h-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid stroke="#1f2937" strokeDasharray="3 3" />

          <XAxis dataKey="time" stroke="#9ca3af" />
          <YAxis stroke="#9ca3af" />

          <Tooltip
            contentStyle={{
              background: "#020617",
              border: "1px solid #1f2937",
            }}
          />

          
          <Line
            type="monotone"
            dataKey="attacks"
            stroke="#ff00ff"
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Attacks"
          />

          
          <Line
            type="monotone"
            dataKey="avgRisk"
            stroke="#ff3b3b"
            strokeWidth={2}
            dot={false}
            name="Avg Risk"
          />

          
          <Line
            type="monotone"
            dataKey="diversity"
            stroke="#22c55e"
            strokeWidth={2}
            dot={false}
            name="Types"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
