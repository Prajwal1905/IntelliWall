"use client";

function RiskMeter({ risk = 0 }) {
  return (
    <div>
      <h3>Risk Level</h3>
      <p>{risk}%</p>
    </div>
  );
}

export default RiskMeter;