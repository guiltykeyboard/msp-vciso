import { FormEvent, useCallback, useEffect, useState } from "react";

type Headers = Record<string, string>;
type Profile = { display_name: string; headline: string; overview: string; security_contact_email: string | null; primary_color: string; status: "draft" | "published" };
type Resource = { id: string; policy_document_id: string; title: string; summary: string; category: string; document_type: string; version: number; published_at: string };
type Domain = { id: string; hostname: string; status: string; tls_provider: string; certificate_status: string; verification_record_name: string; verification_record_value: string; cname_target: string | null; verified_at: string | null; activated_at: string | null };
type Policy = { id: string; title: string; document_type: string; current_version: number };
type Management = { profile: Profile | null; organization_slug: string; resources: Resource[]; domains: Domain[]; approved_policies: Policy[] };

const blankProfile: Profile = { display_name: "", headline: "Security and trust", overview: "", security_contact_email: null, primary_color: "#14532d", status: "draft" };

export function TrustCenter({ identityHeaders, role, tenantKey, announce }: { identityHeaders: () => Headers; role: string; tenantKey: string; announce: (message: string) => void }) {
  const [data, setData] = useState<Management | null>(null);
  const [profile, setProfile] = useState<Profile>(blankProfile);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [policyId, setPolicyId] = useState("");
  const [resourceTitle, setResourceTitle] = useState("");
  const [resourceSummary, setResourceSummary] = useState("");
  const [resourceCategory, setResourceCategory] = useState("assurance");
  const [hostname, setHostname] = useState("");
  const [tlsProvider, setTlsProvider] = useState("platform_managed");
  const canManage = ["customer_admin", "msp_admin"].includes(role);

  const load = useCallback(async () => {
    setError("");
    try {
      const response = await fetch("/v1/trust-center", { headers: identityHeaders() });
      if (!response.ok) throw new Error(`Trust center request failed (${response.status})`);
      const result = await response.json() as Management;
      setData(result);
      setProfile(result.profile ?? blankProfile);
    } catch (problem) { setError(problem instanceof Error ? problem.message : "Trust center request failed"); }
  }, [identityHeaders]);

  useEffect(() => { void load(); }, [load, tenantKey]);

  async function saveProfile(event: FormEvent) {
    event.preventDefault(); setSaving(true); setError("");
    try {
      const response = await fetch("/v1/trust-center", { method: "PUT", headers: { ...identityHeaders(), "Content-Type": "application/json" }, body: JSON.stringify(profile) });
      if (!response.ok) throw new Error(`Trust center save failed (${response.status})`);
      const result = await response.json() as Management; setData(result); setProfile(result.profile ?? blankProfile); announce(`${profile.status === "published" ? "Published" : "Saved draft"} trust center.`);
    } catch (problem) { setError(problem instanceof Error ? problem.message : "Trust center save failed"); }
    finally { setSaving(false); }
  }

  async function publishResource(event: FormEvent) {
    event.preventDefault(); setSaving(true); setError("");
    try {
      const response = await fetch("/v1/trust-center/resources", { method: "POST", headers: { ...identityHeaders(), "Content-Type": "application/json" }, body: JSON.stringify({ policy_document_id: policyId, public_title: resourceTitle, public_summary: resourceSummary, category: resourceCategory }) });
      if (!response.ok) throw new Error(`Resource publication failed (${response.status})`);
      setPolicyId(""); setResourceTitle(""); setResourceSummary(""); await load(); announce("Policy metadata published to the trust center.");
    } catch (problem) { setError(problem instanceof Error ? problem.message : "Resource publication failed"); }
    finally { setSaving(false); }
  }

  async function removeResource(id: string) {
    const response = await fetch(`/v1/trust-center/resources/${id}`, { method: "DELETE", headers: identityHeaders() });
    if (!response.ok) { setError(`Resource removal failed (${response.status})`); return; }
    await load(); announce("Resource removed from the public trust center.");
  }

  async function registerDomain(event: FormEvent) {
    event.preventDefault(); setSaving(true); setError("");
    try {
      const response = await fetch("/v1/trust-center/domains", { method: "POST", headers: { ...identityHeaders(), "Content-Type": "application/json" }, body: JSON.stringify({ hostname, tls_provider: tlsProvider }) });
      if (!response.ok) throw new Error(`Domain registration failed (${response.status})`);
      setHostname(""); await load(); announce("Custom domain registered. Add the displayed DNS records next.");
    } catch (problem) { setError(problem instanceof Error ? problem.message : "Domain registration failed"); }
    finally { setSaving(false); }
  }

  async function domainAction(id: string, action: "verify" | "activate" | "disable") {
    setSaving(true); setError("");
    try {
      const response = await fetch(`/v1/trust-center/domains/${id}:${action}`, { method: "POST", headers: identityHeaders() });
      if (!response.ok) { const body = await response.json().catch(() => null) as { detail?: string } | null; throw new Error(body?.detail ?? `Domain ${action} failed (${response.status})`); }
      await load(); announce(`Custom domain ${action === "verify" ? "verified" : action === "activate" ? "authorized for TLS provisioning" : "disabled"}.`);
    } catch (problem) { setError(problem instanceof Error ? problem.message : `Domain ${action} failed`); }
    finally { setSaving(false); }
  }

  if (!data) return <section className="panel"><p>{error || "Loading trust center…"}</p></section>;
  return <div className="trust-admin">
    {error && <div className="error banner" role="alert">{error}</div>}
    <section className="trust-admin-summary" aria-label="Trust center summary">
      <div><span>Publication</span><strong>{data.profile?.status ?? "not configured"}</strong></div><div><span>Public resources</span><strong>{data.resources.length}</strong></div><div><span>Custom domains</span><strong>{data.domains.filter((item) => item.status !== "disabled").length}</strong></div>
    </section>
    <section className="panel" aria-labelledby="trust-profile-heading"><div className="panel-title"><h2 id="trust-profile-heading">Public trust profile</h2>{data.profile?.status === "published" && <a className="table-action" href={`/trust/${data.organization_slug}`} target="_blank" rel="noreferrer">Open preview</a>}</div>
      {!canManage ? <p>This configuration is read-only for your tenant role.</p> : <form className="trust-profile-form" onSubmit={saveProfile}>
        <label>Public organization name<input value={profile.display_name} onChange={(event) => setProfile({ ...profile, display_name: event.target.value })} required /></label>
        <label>Headline<input value={profile.headline} onChange={(event) => setProfile({ ...profile, headline: event.target.value })} required /></label>
        <label className="trust-wide">Public overview<textarea rows={5} value={profile.overview} onChange={(event) => setProfile({ ...profile, overview: event.target.value })} required /></label>
        <label>Security contact <span className="optional">Optional</span><input type="email" value={profile.security_contact_email ?? ""} onChange={(event) => setProfile({ ...profile, security_contact_email: event.target.value || null })} /></label>
        <label>Accent color<input type="color" value={profile.primary_color} onChange={(event) => setProfile({ ...profile, primary_color: event.target.value })} /></label>
        <label>Publication state<select value={profile.status} onChange={(event) => setProfile({ ...profile, status: event.target.value as Profile["status"] })}><option value="draft">Draft — private</option><option value="published">Published — public</option></select></label>
        <button type="submit" disabled={saving}>{saving ? "Saving…" : "Save trust profile"}</button>
      </form>}
    </section>
    <div className="trust-admin-grid">
      <section className="panel" aria-labelledby="public-resources-heading"><div className="panel-title"><h2 id="public-resources-heading">Public resources</h2></div>
        <p className="form-note">Only the public title, summary, type, and pinned approved version are disclosed. Policy content and evidence remain private.</p>
        {data.resources.length ? <div className="trust-resource-list">{data.resources.map((resource) => <article key={resource.id}><span>{resource.category}</span><h3>{resource.title}</h3><p>{resource.summary}</p><small>{resource.document_type} · version {resource.version}</small>{canManage && <button type="button" className="danger-action" onClick={() => void removeResource(resource.id)}>Unpublish</button>}</article>)}</div> : <div className="empty">No policy metadata is public.</div>}
        {canManage && <form className="trust-resource-form" onSubmit={publishResource}><h3>Publish approved policy metadata</h3><label>Approved policy<select value={policyId} onChange={(event) => { const next = data.approved_policies.find((item) => item.id === event.target.value); setPolicyId(event.target.value); if (next) setResourceTitle(next.title); }} required><option value="" disabled>Select a policy</option>{data.approved_policies.map((item) => <option key={item.id} value={item.id}>{item.title} · v{item.current_version}</option>)}</select></label><label>Public title<input value={resourceTitle} onChange={(event) => setResourceTitle(event.target.value)} required /></label><label>Category<select value={resourceCategory} onChange={(event) => setResourceCategory(event.target.value)}><option value="assurance">Assurance</option><option value="compliance">Compliance</option><option value="policy">Policy</option><option value="privacy">Privacy</option></select></label><label>Public summary<textarea rows={4} value={resourceSummary} onChange={(event) => setResourceSummary(event.target.value)} required /></label><button type="submit" disabled={saving || !policyId}>Publish metadata</button></form>}
      </section>
      <section className="panel" aria-labelledby="trust-domains-heading"><div className="panel-title"><h2 id="trust-domains-heading">Custom domains &amp; TLS</h2></div>
        <p className="form-note">Ownership and routing are verified before the edge may request a managed certificate.</p>
        {data.domains.length ? <div className="trust-domain-list">{data.domains.map((domain) => <article key={domain.id}><div><h3>{domain.hostname}</h3><span className={`status status-${domain.status}`}>{domain.status}</span></div><dl><dt>Ownership TXT</dt><dd><code>{domain.verification_record_name}</code><code>{domain.verification_record_value}</code></dd><dt>Routing CNAME</dt><dd><code>{domain.cname_target ?? "Platform edge is not configured"}</code></dd><dt>TLS</dt><dd>{domain.tls_provider.replaceAll("_", " ")} · {domain.certificate_status.replaceAll("_", " ")}</dd></dl><div className="domain-actions">{domain.status === "pending" && <button type="button" onClick={() => void domainAction(domain.id, "verify")} disabled={saving}>Verify TXT</button>}{domain.status === "verified" && <button type="button" onClick={() => void domainAction(domain.id, "activate")} disabled={saving}>Verify CNAME &amp; enable TLS</button>}{domain.status !== "disabled" && <button type="button" className="danger-action" onClick={() => void domainAction(domain.id, "disable")} disabled={saving}>Disable</button>}</div></article>)}</div> : <div className="empty">No custom trust domains registered.</div>}
        {canManage && <form className="trust-domain-form" onSubmit={registerDomain}><h3>Register a domain</h3><label>Custom hostname<input value={hostname} onChange={(event) => setHostname(event.target.value)} placeholder="trust.customer.example" required /></label><label>TLS automation<select value={tlsProvider} onChange={(event) => setTlsProvider(event.target.value)}><option value="platform_managed">Platform managed</option><option value="azure_managed">Azure managed certificate</option><option value="caddy_acme">Caddy ACME / Let's Encrypt</option></select></label><button type="submit" disabled={saving}>Register domain</button></form>}
      </section>
    </div>
  </div>;
}
