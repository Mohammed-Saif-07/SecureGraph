export function RiskGauge({ value }: { value: number }) {
  const degrees = Math.max(0, Math.min(100, value)) * 1.8 - 90;
  return (
    <div className="riskGauge">
      <h2>Organization Risk</h2>
      <div className="dial">
        <div className="needle" style={{ transform: `rotate(${degrees}deg)` }} />
        <div className="dialValue">{value}</div>
      </div>
      <p>Prioritized by exploit likelihood, graph reachability, and data impact.</p>
    </div>
  );
}
