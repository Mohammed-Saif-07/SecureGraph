import { AttackPath } from "../api/client";

export function AttackPathList({ paths }: { paths: AttackPath[] }) {
  if (!paths.length) return <p className="muted">No graph paths yet. Run a scan or seed ingestion.</p>;
  return (
    <div className="pathList">
      {paths.map((path) => (
        <div className="pathItem" key={`${path.cve_id}-${path.package_name}-${path.service_name}`}>
          <div>
            <strong>{path.cve_id}</strong>
            <span>{path.package_name} {"->"} {path.service_name} {"->"} {path.data_name}</span>
          </div>
          <b>{path.risk_score}/10</b>
        </div>
      ))}
    </div>
  );
}
