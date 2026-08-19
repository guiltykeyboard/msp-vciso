import { FormEvent, useCallback, useEffect, useState } from "react";

type Row = Record<string, string | null>;
type Dashboard = {
  organization: { id: string; name: string };
  assessments: Row[];
  evidence: Row[];
  integrations: Row[];
  endpoints: Row[];
  audit: Row[];
};

const navigation = ["Overview", "Customers", "Assessments", "Evidence", "Integrations", "Endpoints", "Audit"];

function Status({ value }: { value: string | null }) {
  const label = value ?? "Not available";
  return <span className={`status status-${label.replaceAll("_", "-").toLowerCase()}`}>{label.replaceAll("_", " ")}</span>;
}

function Empty({ children }: { children: string }) {
  return <div className="empty">{children}</div>;
}

export function App() {
  const [active, setActive] = useState("Overview");
  const [organizationId, setOrganizationId] = useState(localStorage.getItem("watchtower.organization") ?? "");
  const [actorId, setActorId] = useState(localStorage.getItem("watchtower.actor") ?? "");
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!organizationId || !actorId) return;
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/v1/dashboard", { headers: { "X-Watchtower-Organization": organizationId, "X-Watchtower-Actor": actorId } });
      if (!response.ok) throw new Error(`Dashboard request failed (${response.status})`);
      setData(await response.json());
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Dashboard request failed");
    } finally { setLoading(false); }
  }, [actorId, organizationId]);

  useEffect(() => { void load(); }, [load]);

  function connect(event: FormEvent) {
    event.preventDefault();
    localStorage.setItem("watchtower.organization", organizationId);
    localStorage.setItem("watchtower.actor", actorId);
    void load();
  }

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">W</span>Watchtower</div>
      <nav aria-label="Primary navigation">{navigation.map((item) => <button key={item} className={active === item ? "selected" : ""} onClick={() => setActive(item)}><span aria-hidden="true" className="nav-dot">{item[0]}</span>{item}</button>)}</nav>
      <button className="collapse">‹ <span>Collapse</span></button>
    </aside>
    <main>
      <header className="topbar">
        <div><span className="label">Tenant</span><strong>{data?.organization.name ?? "Connect a tenant"}</strong></div>
        <button className="refresh" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>
        <div className="avatar">MS</div>
      </header>
      <section className="content">
        <div className="heading"><div><h1>Compliance operations</h1><p>Current evidence, assessment, integration, and endpoint activity.</p></div></div>
        {!data && <form className="connect" onSubmit={connect}><h2>Connect this browser</h2><p>Development identity headers are stored only in this browser. Production authentication will replace this form.</p><label>Organization ID<input value={organizationId} onChange={(event) => setOrganizationId(event.target.value)} required /></label><label>Actor ID<input value={actorId} onChange={(event) => setActorId(event.target.value)} required /></label><button type="submit">Load operations</button>{error && <p className="error">{error}</p>}</form>}
        {data && <>
          {error && <div className="error banner">{error}</div>}
          <section className="summary" aria-label="Operations summary">
            <div><span>Assessments</span><strong>{data.assessments.length}</strong><small>recent records</small></div>
            <div><span>Evidence queue</span><strong>{data.evidence.length}</strong><small>{data.evidence.filter((row) => row.scan_status !== "clean").length} unavailable</small></div>
            <div><span>Integrations</span><strong>{data.integrations.length}</strong><small>{data.integrations.filter((row) => row.status === "error").length} need attention</small></div>
            <div><span>Endpoints</span><strong>{data.endpoints.length}</strong><small>{data.endpoints.filter((row) => row.status !== "active").length} not active</small></div>
          </section>
          <div className="primary-grid">
            <section className="panel"><div className="panel-title"><h2>Assessment progress</h2><button onClick={() => setActive("Assessments")}>View assessments</button></div>{data.assessments.length ? <table><thead><tr><th>Assessment</th><th>Status</th><th>Updated</th></tr></thead><tbody>{data.assessments.map((row) => <tr key={row.id}><td>{row.name}</td><td><Status value={row.status} /></td><td>{new Date(row.updated_at!).toLocaleDateString()}</td></tr>)}</tbody></table> : <Empty>No assessments have been created.</Empty>}</section>
            <section className="panel"><div className="panel-title"><h2>Evidence review queue</h2><button onClick={() => setActive("Evidence")}>Review evidence</button></div>{data.evidence.length ? <table><thead><tr><th>Evidence</th><th>Sensitivity</th><th>State</th></tr></thead><tbody>{data.evidence.map((row) => <tr key={row.id}><td>{row.title}</td><td>{row.sensitivity}</td><td><Status value={row.scan_status} /></td></tr>)}</tbody></table> : <Empty>No evidence is waiting for review.</Empty>}</section>
          </div>
          <div className="secondary-grid">
            <section className="panel"><div className="panel-title"><h2>Integration health</h2></div>{data.integrations.length ? data.integrations.map((row) => <div className="line" key={row.id}><span>{row.display_name}</span><Status value={row.status} /></div>) : <Empty>No integrations configured.</Empty>}</section>
            <section className="panel"><div className="panel-title"><h2>Endpoint fleet status</h2></div>{data.endpoints.length ? data.endpoints.map((row) => <div className="line" key={row.id}><span><strong>{row.hostname}</strong><small>{row.platform}</small></span><Status value={row.status} /></div>) : <Empty>No endpoint collectors enrolled.</Empty>}</section>
            <section className="panel"><div className="panel-title"><h2>Recent audit activity</h2></div>{data.audit.length ? data.audit.map((row, index) => <div className="audit-line" key={`${row.target_id}-${index}`}><span className="timeline-dot" /><span><strong>{row.event_type?.replaceAll(".", " ")}</strong><small>{row.target_type}</small></span><time>{new Date(row.occurred_at!).toLocaleString()}</time></div>) : <Empty>No audit activity recorded.</Empty>}</section>
          </div>
        </>}
      </section>
    </main>
  </div>;
}
