"use client";

function RiskMeter({ risk = 0 }) {
  const safeRisk = Math.max(0, Math.min(100, risk));

  return (
    <div className="w-full">
      <h3 className="mb-2">Risk Level</h3>

      <div className="w-full bg-gray-800 rounded h-4">
        <div
          className="bg-red-500 h-4 rounded"
          style={{ width: `${safeRisk}%` }}
        ></div>
      </div>

      <p className="mt-2">{safeRisk}%</p>
    </div>
  );
}

export default RiskMeter;