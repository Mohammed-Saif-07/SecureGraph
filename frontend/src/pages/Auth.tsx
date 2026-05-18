import { useState, type FormEvent } from "react";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { api, User } from "../api/client";
import { Spinner } from "../components/Spinner";

type AuthMode = "login" | "register";

export function AuthPage({ onAuthenticated }: { onAuthenticated: (user: User) => void }) {
  const [mode, setMode] = useState<AuthMode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organization, setOrganization] = useState("SecureGraph Demo Org");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = mode === "register"
        ? await api.register({ email, password, organization })
        : await api.login({ email, password });
      localStorage.setItem("securegraph_access_token", response.access_token);
      localStorage.setItem("securegraph_refresh_token", response.refresh_token);
      onAuthenticated(response.user);
    } catch {
      setError(mode === "register" ? "Registration failed. Try a different email." : "Login failed. Check your email and password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="authPage">
      <div className="authPanel">
        <div className="authMark"><ShieldCheck size={28} /> SecureGraph</div>
        <h2>{mode === "login" ? "Sign in to your graph" : "Create your SecureGraph account"}</h2>
        <p>Keep scan history, reports, and graph intelligence tied to your organization.</p>
        <form onSubmit={submit} className="authForm">
          <label>
            Email
            <input value={email} onChange={(event) => setEmail(event.target.value)} type="email" autoComplete="email" required />
          </label>
          <label>
            Password
            <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={8} required />
          </label>
          {mode === "register" && (
            <label>
              Organization
              <input value={organization} onChange={(event) => setOrganization(event.target.value)} required />
            </label>
          )}
          {error && <div className="authError">{error}</div>}
          <button className="primary" disabled={loading}>
            {loading ? <Spinner text="Securing session..." /> : <><LockKeyhole size={18} /> {mode === "login" ? "Sign In" : "Create Account"}</>}
          </button>
        </form>
        <button className="authSwitch" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "Need an account? Register" : "Already have an account? Sign in"}
        </button>
      </div>
    </section>
  );
}
