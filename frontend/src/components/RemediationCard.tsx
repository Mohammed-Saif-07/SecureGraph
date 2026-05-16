import { Remediation } from "../api/client";

export function RemediationCard({ item }: { item: Remediation }) {
  return (
    <article className="remediation">
      <div>
        <h3>{item.package_name}</h3>
        <p>{item.current_version} {"->"} {item.fixed_version}</p>
      </div>
      <div>
        <strong>{item.risk_reduction}</strong>
        <span>risk ROI</span>
      </div>
    </article>
  );
}
