type RiskGaugeProps = {
  value: number;
  title?: string;
  caption?: string;
};

export function RiskGauge({
  value,
  title = "Organization Risk",
  caption = "Prioritized by exploit likelihood, graph reachability, and data impact.",
}: RiskGaugeProps) {
  const degrees = Math.max(0, Math.min(100, value)) * 1.8 - 90;
  return (
    <div className="riskGauge">
      <h2>{title}</h2>
      <div className="dial">
        <div className="needle" style={{ transform: `rotate(${degrees}deg)` }} />
        <div className="dialValue">{value}</div>
      </div>
      <p>{caption}</p>
    </div>
  );
}
