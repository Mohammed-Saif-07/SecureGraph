import { useEffect, useMemo, useState } from "react";
import { Activity, Download, GitBranch, MessageSquare, Radar, ShieldAlert } from "lucide-react";
import { api, AttackPath, GraphLink, GraphNode, Remediation, Scan } from "./api/client";
import { GraphViewer } from "./components/GraphViewer";
import { RiskGauge } from "./components/RiskGauge";
import { AttackPathList } from "./components/AttackPath";
import { RemediationCard } from "./components/RemediationCard";
import "./styles.css";

type Tab = "dashboard" | "graph" | "query" | "scans" | "reports";

const demoNodes: GraphNode[] = [
  { id: "1", label: "CVE", name: "CVE-2023-32681", severity: "critical", risk: 0.92 },
  { id: "2", label: "Package", name: "requests", risk: 0.88 },
  { id: "3", label: "Service", name: "PaymentService", risk: 0.8 },
  { id: "4", label: "Server", name: "payment.prod.local" },
  { id: "5", label: "BusinessData", name: "PaymentDatabase" },
  { id: "6", label: "CVE", name: "CVE-2023-44487", severity: "high", risk: 0.82 },
  { id: "7", label: "Package", name: "aiohttp", risk: 0.78 }
];

const demoLinks: GraphLink[] = [
  { source: "1", target: "2", type: "AFFECTS" },
  { source: "2", target: "3", type: "USED_BY" },
  { source: "3", target: "4", type: "RUNS_ON" },
  { source: "4", target: "5", type: "STORES" },
  { source: "6", target: "7", type: "AFFECTS" },
  { source: "7", target: "3", type: "USED_BY" }
];

const demoPaths: AttackPath[] = [
  { cve_id: "CVE-2023-32681", package_name: "requests", service_name: "PaymentService", data_name: "PaymentDatabase", risk_score: 9.2, hops: 4 },
  { cve_id: "CVE-2023-44487", package_name: "aiohttp", service_name: "PaymentService", data_name: "PaymentDatabase", risk_score: 8.8, hops: 4 }
];

const demoRemediations: Remediation[] = [
  { package_name: "requests", current_version: "2.28.0", fixed_version: "2.31.0", cves: ["CVE-2023-32681"], services: ["PaymentService"], risk_reduction: 9.2 },
  { package_name: "aiohttp", current_version: "3.8.1", fixed_version: "3.9.0", cves: ["CVE-2023-44487"], services: ["PaymentService"], risk_reduction: 8.8 }
];

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [links, setLinks] = useState<GraphLink[]>([]);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [repoUrl, setRepoUrl] = useState("https://github.com/pallets/flask");
  const [question, setQuestion] = useState("Which 3 patches give me the biggest risk reduction?");
  const [answer, setAnswer] = useState("");
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("Demo graph loaded while backend starts.");

  async function refresh() {
    try {
      const [snapshot, attackPaths, remediationRows, scanRows] = await Promise.all([
        api.snapshot(),
        api.attackPaths(),
        api.remediations(),
        api.scans()
      ]);
      setNodes(snapshot.nodes);
      setLinks(snapshot.links);
      setPaths(attackPaths.paths);
      setRemediations(remediationRows.remediations);
      setScans(scanRows);
      setNotice("Live SecureGraph API connected.");
    } catch {
      setNodes(demoNodes);
      setLinks(demoLinks);
      setPaths(demoPaths);
      setRemediations(demoRemediations);
      setScans([]);
      setNotice("Using demo graph. Start Docker Compose for live scans and reports.");
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  const overallRisk = useMemo(() => {
    const top = paths[0]?.risk_score || 0;
    return Math.min(100, Math.round(top * 10));
  }, [paths]);

  async function submitScan() {
    setLoading(true);
    try {
      await api.scanRepo(repoUrl);
      setNotice("Scan queued. Results will appear in scan history when processing completes.");
      setTimeout(() => refresh(), 1800);
    } catch {
      setNotice("Scan could not be queued because the backend API is unavailable.");
    } finally {
      setLoading(false);
    }
  }

  async function askGraph() {
    setLoading(true);
    try {
      try {
        const response = await api.ask(question);
        setAnswer(response.answer);
        setNotice("Graph-grounded answer generated.");
      } catch {
        setAnswer("Based on the demo graph, update requests to 2.31.0 first. It breaks the highest-risk chain from CVE-2023-32681 through PaymentService to PaymentDatabase and removes the 9.2/10 PCI data path.");
        setNotice("Using local fallback answer because the LLM API is unavailable.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><ShieldAlert size={24} /> SecureGraph</div>
        <button className={tab === "dashboard" ? "active" : ""} onClick={() => setTab("dashboard")}><Radar size={18} /> Dashboard</button>
        <button className={tab === "graph" ? "active" : ""} onClick={() => setTab("graph")}><GitBranch size={18} /> Attack Graph</button>
        <button className={tab === "query" ? "active" : ""} onClick={() => setTab("query")}><MessageSquare size={18} /> Query</button>
        <button className={tab === "scans" ? "active" : ""} onClick={() => setTab("scans")}><Activity size={18} /> Scans</button>
        <button className={tab === "reports" ? "active" : ""} onClick={() => setTab("reports")}><Download size={18} /> Reports</button>
      </aside>

      <main>
        <header>
          <div>
            <h1>{tab === "dashboard" ? "Attack Surface Command Center" : tab.replace("-", " ")}</h1>
            <p>Graph-grounded vulnerability intelligence for packages, services, and business data.</p>
          </div>
          <a className="iconButton" href={api.reportUrl}><Download size={18} /> PDF</a>
        </header>
        {notice && <div className="notice">{notice}</div>}

        {tab === "dashboard" && (
          <section className="dashboard">
            <RiskGauge value={overallRisk} />
            <div className="panel">
              <h2>Highest Risk Paths</h2>
              <AttackPathList paths={paths.slice(0, 4)} />
            </div>
            <div className="panel">
              <h2>Patch ROI</h2>
              {remediations.slice(0, 3).map((item) => <RemediationCard key={item.package_name} item={item} />)}
            </div>
          </section>
        )}

        {tab === "graph" && <GraphViewer nodes={nodes} links={links} paths={paths} />}

        {tab === "query" && (
          <section className="query">
            <textarea value={question} onChange={(event) => setQuestion(event.target.value)} />
            <button className="primary" onClick={askGraph} disabled={loading}>Ask Graph</button>
            {answer && <pre className="answer">{answer}</pre>}
          </section>
        )}

        {tab === "scans" && (
          <section className="scans">
            <div className="scanBox">
              <input value={repoUrl} onChange={(event) => setRepoUrl(event.target.value)} />
              <button className="primary" onClick={submitScan} disabled={loading}>Scan Repo</button>
            </div>
            <div className="panel">
              <h2>Scan History</h2>
              {scans.map((scan) => (
                <div className="row" key={scan.id}>
                  <span>{scan.repo_url}</span>
                  <strong>{scan.status}</strong>
                  <span>{scan.results} findings</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {tab === "reports" && (
          <section className="reports">
            <div className="panel reportPanel">
              <h2>Executive PDF</h2>
              <p>Export a board-ready summary of top attack paths, blast radius, and patch order.</p>
              <a className="primary linkButton" href={api.reportUrl}>Download Report</a>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
