const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

export const api = {
  snapshot: () => request<{ nodes: GraphNode[]; links: GraphLink[] }>("/api/graph/snapshot"),
  attackPaths: () => request<{ paths: AttackPath[]; blast_radius: { affected_services: number; reachable_data_stores: number } }>("/api/graph/attack-paths?limit=10"),
  remediations: () => request<{ remediations: Remediation[] }>("/api/graph/remediations?limit=5"),
  ask: (question: string) => request<QueryAnswer>("/api/llm/query", { method: "POST", body: JSON.stringify({ question }) }),
  scanRepo: (repo_url: string) => request<{ scan_id: string; status: string }>("/api/scans/repo", { method: "POST", body: JSON.stringify({ repo_url }) }),
  scans: () => request<Scan[]>("/api/scans"),
  reportUrl: `${API_URL}/api/reports/pdf`
};

export type GraphNode = { id: string; label: string; name: string; severity?: string; risk?: number };
export type GraphLink = { source: string; target: string; type: string };
export type AttackPath = { cve_id: string; package_name: string; service_name: string; data_name: string; risk_score: number; hops: number };
export type Remediation = { package_name: string; current_version: string; fixed_version: string; services: string[]; cves: string[]; risk_reduction: number };
export type QueryAnswer = { answer: string; validation: { valid: boolean; unsupported_claims: string[] }; model: string };
export type Scan = { id: string; repo_url: string; status: string; started_at: string; completed_at?: string; results: number; message?: string | null };
