const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function authHeader(): Record<string, string> {
  const token = localStorage.getItem("securegraph_access_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...authHeader(),
      ...(options.headers || {})
    }
  });
  if (!response.ok) {
    const text = await response.text();
    let message = text;
    try {
      const parsed = JSON.parse(text);
      message = parsed.detail || text;
    } catch {
      message = text;
    }
    throw new Error(message || `Request failed with status ${response.status}`);
  }
  return response.json();
}

export const api = {
  register: (payload: AuthRequest) => request<AuthResponse>("/api/auth/register", { method: "POST", body: JSON.stringify(payload) }),
  login: (payload: LoginRequest) => request<AuthResponse>("/api/auth/login", { method: "POST", body: JSON.stringify(payload) }),
  me: () => request<{ user: User }>("/api/auth/me"),
  logout: () => request<{ status: string }>("/api/auth/logout", { method: "POST" }),
  snapshot: () => request<{ nodes: GraphNode[]; links: GraphLink[] }>("/api/graph/snapshot"),
  attackPaths: () => request<{ paths: AttackPath[]; blast_radius: { affected_services: number; reachable_data_stores: number } }>("/api/graph/attack-paths?limit=10"),
  remediations: () => request<{ remediations: Remediation[] }>("/api/graph/remediations?limit=5"),
  ask: (question: string, scope?: { service?: string; repo_url?: string }) =>
    request<QueryAnswer>("/api/llm/query", {
      method: "POST",
      body: JSON.stringify({ question, ...(scope || {}) })
    }),
  scanRepo: (repo_url: string) => request<{ scan_id: string; status: string }>("/api/scans/repo", { method: "POST", body: JSON.stringify({ repo_url }) }),
  scans: () => request<Scan[]>("/api/scans"),
  scanGraph: (scanId: string) => request<ScanGraph>(`/api/scans/${scanId}/graph`),
  reportUrl: `${BASE_URL}/api/reports/pdf`
};

export type GraphNode = { id: string; label: string; name: string; severity?: string; risk?: number };
export type GraphLink = { source: string; target: string; type: string };
export type AttackPath = { cve_id: string; package_name: string; service_name: string; data_name: string; risk_score: number; hops: number };
export type Remediation = { package_name: string; current_version: string; fixed_version: string; services: string[]; cves: string[]; risk_reduction: number };
export type QueryAnswer = { answer: string; validation: { valid: boolean; unsupported_claims: string[] }; model: string };
export type Scan = { id: string; repo_url: string; status: string; started_at: string; completed_at?: string; results: number; message?: string | null };
export type ScanGraph = { scan_id: string; repo_url: string; status: string; message?: string | null; nodes: GraphNode[]; links: GraphLink[]; paths: AttackPath[] };
export type User = { id: string; email: string; org_id: string; role: string };
export type AuthRequest = { email: string; password: string; organization: string };
export type LoginRequest = { email: string; password: string };
export type AuthResponse = { access_token: string; refresh_token: string; token_type: string; expires_in: number; user: User };
