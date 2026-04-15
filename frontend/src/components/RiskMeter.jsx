

"use client";

import { motion } from "framer-motion";

function RiskMeter({ risk = 0 }) {
  const safeRisk = Math.max(0, Math.min(100, isNaN(risk) ? 0 : risk));

  const radius = 50;
  const stroke = 8;
  const normalizedRadius = radius - stroke * 0.5;
  const circumference = normalizedRadius * 2 * Math.PI;

  const strokeDashoffset =
    circumference - (safeRisk / 100) * circumference;

  const getColor = () => {
    if (safeRisk >= 70) return "#ff3b3b";
    if (safeRisk >= 40) return "#facc15";
    return "#22c55e";
  };

  const color = getColor();

  return (
    <div className="flex flex-col items-center justify-center">
      <svg height={radius * 2} width={radius * 2}>
        <circle
          stroke="#1f2937"
          fill="transparent"
          strokeWidth={stroke}
          r={normalizedRadius}
          cx={radius}
          cy={radius}
        />

        <motion.circle
          stroke={color}
          fill="transparent"
          strokeWidth={stroke}
          strokeDasharray={`${circumference} ${circumference}`}
          style={{
            strokeDashoffset,
            transform: "rotate(-90deg)",
            transformOrigin: "50% 50%",
          }}
          r={normalizedRadius}
          cx={radius}
          cy={radius}
          animate={{ strokeDashoffset }}
          transition={{ duration: 0.8 }}
        />
      </svg>

      <div className="mt-2 text-sm font-semibold" style={{ color }}>
        {safeRisk}%
      </div>
    </div>
  );
}

export default RiskMeter;