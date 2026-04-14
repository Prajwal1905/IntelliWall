"use client";

function MetricsBar({ alerts = 0, blocked = 0 }) {
  return (
    <div className="flex gap-6">
      <div>
        <p>Total Alerts</p>
        <h2>{alerts}</h2>
      </div>

      <div>
        <p>Blocked</p>
        <h2>{blocked}</h2>
      </div>
    </div>
  );
}

export default MetricsBar;

