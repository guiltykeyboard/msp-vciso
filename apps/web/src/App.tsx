import { FormEvent, useCallback, useEffect, useState } from "react";

import { PolicyLibrary } from "./PolicyLibrary";

type Row = Record<string, string | null>;
type Theme = "light" | "dark";
type Dashboard = {
  organization: { id: string; name: string };
  identity: { actor_id: string; role: string };
  assessments: Row[];
  evidence: Row[];
  integrations: Row[];
  endpoints: Row[];
  audit: Row[];
};
type AccessProfile = {
  id: string;
  name: string;
  description: string;
  permissions: string[];
};
type Invitation = {
  id: string;
  email: string;
  display_name: string | null;
  role: string;
  status: string;
  expires_at: string;
  created_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
};
type AuthorizedOrganization = {
  id: string;
  name: string;
  slug: string;
  role: string;
};

const navigation = ["Overview", "Customers", "Policies", "Assessments", "Evidence", "Integrations", "Endpoints", "Audit"];
const auditorNavigation = ["Overview", "Policies", "Assessments", "Evidence", "Audit"];

function Status({ value }: { value: string | null }) {
  const label = value ?? "Not available";
  return <span className={`status status-${label.replaceAll("_", "-").toLowerCase()}`}>{label.replaceAll("_", " ")}</span>;
}

function Empty({ children }: { children: string }) {
  return <div className="empty">{children}</div>;
}

export function App() {
  const [invitationToken, setInvitationToken] = useState(new URLSearchParams(window.location.hash.slice(1)).get("invite") ?? "");
  const [active, setActive] = useState("Overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [organizationId, setOrganizationId] = useState(window.localStorage.getItem("watchtower.organization") ?? "");
  const [actorId, setActorId] = useState(window.localStorage.getItem("watchtower.actor") ?? "");
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [theme, setTheme] = useState<Theme>("light");
  const [themeSaving, setThemeSaving] = useState(false);
  const [themeReady, setThemeReady] = useState(Boolean(invitationToken) || !organizationId || !actorId);
  const [announcement, setAnnouncement] = useState("");
  const [inviteeName, setInviteeName] = useState("");
  const [acceptingInvitation, setAcceptingInvitation] = useState(false);
  const [accessProfiles, setAccessProfiles] = useState<AccessProfile[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [accessLoading, setAccessLoading] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteDisplayName, setInviteDisplayName] = useState("");
  const [inviteRole, setInviteRole] = useState("control_owner");
  const [inviteExpiry, setInviteExpiry] = useState("7");
  const [createdInviteLink, setCreatedInviteLink] = useState("");
  const [authorizedOrganizations, setAuthorizedOrganizations] = useState<AuthorizedOrganization[]>([]);

  const identityHeaders = useCallback(() => ({
    "X-Watchtower-Organization": organizationId,
    "X-Watchtower-Actor": actorId,
  }), [actorId, organizationId]);

  const loadPreferences = useCallback(async () => {
    if (invitationToken || !organizationId || !actorId) return;
    setThemeReady(false);
    try {
      const response = await fetch("/v1/profile/preferences", { headers: identityHeaders() });
      if (!response.ok) throw new Error(`Profile request failed (${response.status})`);
      const preferences = await response.json() as { theme: Theme };
      setTheme(preferences.theme);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Profile request failed");
    } finally {
      setThemeReady(true);
    }
  }, [actorId, identityHeaders, invitationToken, organizationId]);

  const load = useCallback(async () => {
    if (invitationToken || !organizationId || !actorId) return;
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/v1/dashboard", { headers: identityHeaders() });
      if (!response.ok) throw new Error(`Dashboard request failed (${response.status})`);
      setData(await response.json());
      setAnnouncement("Dashboard data loaded.");
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Dashboard request failed");
    } finally { setLoading(false); }
  }, [actorId, identityHeaders, invitationToken, organizationId]);

  const loadAuthorizedOrganizations = useCallback(async () => {
    if (invitationToken || !organizationId || !actorId) return;
    try {
      const response = await fetch("/v1/me/organizations", { headers: identityHeaders() });
      if (!response.ok) throw new Error(`Tenant access request failed (${response.status})`);
      setAuthorizedOrganizations(await response.json());
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Tenant access request failed");
    }
  }, [actorId, identityHeaders, invitationToken, organizationId]);

  const loadClientAccess = useCallback(async () => {
    if (!data || !["customer_admin", "msp_admin"].includes(data.identity.role)) return;
    setAccessLoading(true);
    setError("");
    try {
      const [profilesResponse, invitationsResponse] = await Promise.all([
        fetch("/v1/access/roles", { headers: identityHeaders() }),
        fetch("/v1/invitations", { headers: identityHeaders() }),
      ]);
      if (!profilesResponse.ok || !invitationsResponse.ok) {
        throw new Error("Client access request failed");
      }
      setAccessProfiles(await profilesResponse.json());
      setInvitations(await invitationsResponse.json());
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Client access request failed");
    } finally {
      setAccessLoading(false);
    }
  }, [data, identityHeaders]);

  useEffect(() => {
    void load();
    void loadPreferences();
    void loadAuthorizedOrganizations();
  }, [load, loadAuthorizedOrganizations, loadPreferences]);
  useEffect(() => { if (active === "Customers") void loadClientAccess(); }, [active, loadClientAccess]);
  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);

  function connect(event: FormEvent) {
    event.preventDefault();
    window.localStorage.setItem("watchtower.organization", organizationId);
    window.localStorage.setItem("watchtower.actor", actorId);
    setThemeReady(false);
    void load();
    void loadPreferences();
  }

  function switchOrganization(nextOrganizationId: string) {
    if (nextOrganizationId === organizationId) return;
    const nextOrganization = authorizedOrganizations.find(
      (organization) => organization.id === nextOrganizationId,
    );
    window.localStorage.setItem("watchtower.organization", nextOrganizationId);
    setOrganizationId(nextOrganizationId);
    setData(null);
    setAccessProfiles([]);
    setInvitations([]);
    setCreatedInviteLink("");
    setActive("Overview");
    setAnnouncement(`Switching to ${nextOrganization?.name ?? "the selected tenant"}.`);
  }

  async function toggleTheme() {
    if (!organizationId || !actorId || themeSaving) return;
    const previousTheme = theme;
    const nextTheme: Theme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    setThemeSaving(true);
    setError("");
    try {
      const response = await fetch("/v1/profile/preferences", {
        method: "PUT",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ theme: nextTheme }),
      });
      if (!response.ok) throw new Error(`Theme update failed (${response.status})`);
      const preferences = await response.json() as { theme: Theme };
      setTheme(preferences.theme);
      setAnnouncement(`${preferences.theme === "dark" ? "Dark" : "Light"} mode saved to your profile.`);
    } catch (problem) {
      setTheme(previousTheme);
      setError(problem instanceof Error ? problem.message : "Theme update failed");
    } finally {
      setThemeSaving(false);
    }
  }

  async function acceptInvitation(event: FormEvent) {
    event.preventDefault();
    if (acceptingInvitation) return;
    setAcceptingInvitation(true);
    setError("");
    try {
      const response = await fetch("/v1/invitations:accept", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: invitationToken, display_name: inviteeName }),
      });
      if (!response.ok) throw new Error(response.status === 401 ? "This invitation is invalid, expired, or already used." : `Invitation acceptance failed (${response.status})`);
      const accepted = await response.json() as { organization_id: string; actor_id: string; organization_name: string };
      window.localStorage.setItem("watchtower.organization", accepted.organization_id);
      window.localStorage.setItem("watchtower.actor", accepted.actor_id);
      setOrganizationId(accepted.organization_id);
      setActorId(accepted.actor_id);
      setInvitationToken("");
      setThemeReady(false);
      window.history.replaceState({}, "", window.location.pathname);
      setAnnouncement(`Invitation accepted. Connected to ${accepted.organization_name}.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Invitation acceptance failed");
    } finally {
      setAcceptingInvitation(false);
    }
  }

  async function createInvitation(event: FormEvent) {
    event.preventDefault();
    setAccessLoading(true);
    setError("");
    setCreatedInviteLink("");
    try {
      const externalAuditor = inviteRole === "auditor";
      const response = await fetch(
        externalAuditor ? "/v1/invitations/external-auditor" : "/v1/invitations",
        {
        method: "POST",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(externalAuditor ? {
            email: inviteEmail,
            display_name: inviteDisplayName || null,
            expires_in_days: Number(inviteExpiry),
          } : {
            email: inviteEmail,
            display_name: inviteDisplayName || null,
            role: inviteRole,
            expires_in_days: Number(inviteExpiry),
          }),
        },
      );
      if (!response.ok) {
        const problem = await response.json() as { detail?: string };
        throw new Error(problem.detail ?? `Invitation request failed (${response.status})`);
      }
      const created = await response.json() as Invitation & { token: string };
      const link = `${window.location.origin}${window.location.pathname}#invite=${encodeURIComponent(created.token)}`;
      setCreatedInviteLink(link);
      setInvitations((current) => [created, ...current]);
      setInviteEmail("");
      setInviteDisplayName("");
      setAnnouncement(`${externalAuditor ? "External auditor" : "Client"} invitation created. The acceptance link is shown once.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Invitation request failed");
    } finally {
      setAccessLoading(false);
    }
  }

  async function copyInviteLink() {
    try {
      await navigator.clipboard.writeText(createdInviteLink);
      setAnnouncement("Invitation link copied to the clipboard.");
    } catch {
      setError("Clipboard access was unavailable. Select and copy the invitation link manually.");
    }
  }

  async function revokeInvitation(invitationId: string) {
    setAccessLoading(true);
    setError("");
    try {
      const response = await fetch(`/v1/invitations/${invitationId}`, {
        method: "DELETE",
        headers: identityHeaders(),
      });
      if (!response.ok) throw new Error(`Invitation revocation failed (${response.status})`);
      setInvitations((current) => current.map((invitation) => invitation.id === invitationId ? { ...invitation, status: "revoked", revoked_at: new Date().toISOString() } : invitation));
      setAnnouncement("Invitation revoked.");
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Invitation revocation failed");
    } finally {
      setAccessLoading(false);
    }
  }

  if (invitationToken) {
    return <main className="invitation-acceptance" id="main-content">
      <form className="connect" aria-labelledby="accept-invitation-heading" onSubmit={acceptInvitation}>
        <div className="brand invitation-brand"><span className="brand-mark">W</span><span>Watchtower</span></div>
        <h1 id="accept-invitation-heading">Accept client access</h1>
        <p>You were invited to a protected customer tenant. This link can be used only once and may expire.</p>
        <label>Display name<input value={inviteeName} onChange={(event) => setInviteeName(event.target.value)} autoComplete="name" required /></label>
        <button type="submit" disabled={acceptingInvitation}>{acceptingInvitation ? "Accepting…" : "Accept invitation"}</button>
        {error && <p className="error" role="alert">{error}</p>}
      </form>
    </main>;
  }

  const visibleNavigation = data?.identity.role === "auditor" ? auditorNavigation : navigation;

  return <div className={`shell${themeReady ? "" : " theme-loading"}${sidebarCollapsed ? " sidebar-collapsed" : ""}`}>
    <a
      className="skip-link"
      href="#main-content"
      onClick={() => document.getElementById("main-content")?.focus()}
    >
      Skip to main content
    </a>
    <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{announcement}</div>
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">W</span>Watchtower</div>
      <nav id="primary-navigation" aria-label="Primary navigation">{visibleNavigation.map((item) => <button type="button" key={item} className={active === item ? "selected" : ""} aria-current={active === item ? "page" : undefined} onClick={() => setActive(item)}><span aria-hidden="true" className="nav-dot">{item[0]}</span><span className="nav-label">{item}</span></button>)}</nav>
      <button type="button" className="collapse" aria-controls="primary-navigation" aria-expanded={!sidebarCollapsed} onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}><span className="collapse-icon" aria-hidden="true">{sidebarCollapsed ? "›" : "‹"}</span><span className="collapse-label">{sidebarCollapsed ? "Expand navigation" : "Collapse navigation"}</span></button>
    </aside>
    <main id="main-content" tabIndex={-1} aria-busy={loading || !themeReady}>
      <header className="topbar">
        <label className="tenant-context">
          <span className="label">Tenant</span>
          {authorizedOrganizations.length > 1 ? <select aria-label="Current tenant" value={organizationId} onChange={(event) => switchOrganization(event.target.value)}>{authorizedOrganizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}</select> : <strong>{data?.organization.name ?? "Connect a tenant"}</strong>}
        </label>
        <button type="button" className="refresh" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>
        <button
          className="theme-toggle"
          type="button"
          onClick={() => void toggleTheme()}
          disabled={!organizationId || !actorId || themeSaving}
          aria-label="Dark mode"
          aria-pressed={theme === "dark"}
          aria-describedby="theme-preference-description"
          title={theme === "dark" ? "Use light mode" : "Use dark mode"}
        >
          {theme === "dark" ? (
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41"/></svg>
          ) : (
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.4 15.5A8.5 8.5 0 0 1 8.5 3.6 8.5 8.5 0 1 0 20.4 15.5Z"/></svg>
          )}
        </button>
        <span id="theme-preference-description" className="sr-only">Your theme choice is saved to your user profile.</span>
        <div className="avatar" aria-hidden="true">MS</div>
      </header>
      <section className="content" aria-labelledby="operations-heading">
        <div className="heading"><div><h1 id="operations-heading">{active === "Customers" ? "Client access" : active === "Policies" ? "Policies & procedures" : "Compliance operations"}</h1><p>{active === "Customers" ? "Invite client personnel and external auditors with auditable tenant access profiles." : active === "Policies" ? "Versioned internal documents cross-referenced to controls and supporting evidence." : data?.identity.role === "auditor" ? "Read-only assessment, evidence, and audit activity for the selected tenant." : "Current evidence, assessment, integration, and endpoint activity."}</p></div></div>
        {!data && <form className="connect" aria-labelledby="connect-heading" aria-describedby="connect-help" onSubmit={connect}><h2 id="connect-heading">Connect this browser</h2><p id="connect-help">Development identity headers are stored only in this browser. Production authentication will replace this form.</p><label>Organization ID<input value={organizationId} onChange={(event) => setOrganizationId(event.target.value)} autoComplete="off" spellCheck={false} required /></label><label>Actor ID<input value={actorId} onChange={(event) => setActorId(event.target.value)} autoComplete="off" spellCheck={false} required /></label><button type="submit">Load operations</button>{error && <p className="error" role="alert">{error}</p>}</form>}
        {data && (active === "Customers" ? <>
          {error && <div className="error banner" role="alert">{error}</div>}
          {!['customer_admin', 'msp_admin'].includes(data.identity.role) ? <section className="panel access-notice" aria-labelledby="access-restricted-heading"><div className="panel-title"><h2 id="access-restricted-heading">Client access is restricted</h2></div><p>Only customer administrators and MSP administrators can invite or revoke client personnel.</p></section> : <div className="access-layout">
            <section className="panel" aria-labelledby="invite-client-heading">
              <div className="panel-title"><h2 id="invite-client-heading">Invite client personnel or an external auditor</h2></div>
              <form className="access-form" onSubmit={createInvitation} aria-describedby="invite-delivery-note">
                <label>Email address<input type="email" value={inviteEmail} onChange={(event) => setInviteEmail(event.target.value)} autoComplete="email" required /></label>
                <label>Display name <span className="optional">Optional</span><input value={inviteDisplayName} onChange={(event) => setInviteDisplayName(event.target.value)} autoComplete="name" /></label>
                <label>Access profile<select value={inviteRole} onChange={(event) => setInviteRole(event.target.value)}>{accessProfiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</select></label>
                {inviteRole === "auditor" && <p className="auditor-note">The auditor receives read-only access to this tenant. If the same email accepts auditor invitations from other customers, Watchtower reuses one identity while keeping each tenant membership separate.</p>}
                <label>Invitation expires<select value={inviteExpiry} onChange={(event) => setInviteExpiry(event.target.value)}><option value="1">In 1 day</option><option value="7">In 7 days</option><option value="14">In 14 days</option><option value="30">In 30 days</option></select></label>
                <p id="invite-delivery-note" className="form-note">Email delivery is not configured yet. The secure acceptance link is shown once so you can deliver it through an approved channel.</p>
                <button type="submit" disabled={accessLoading}>{accessLoading ? "Creating…" : "Create invitation"}</button>
              </form>
              {createdInviteLink && <div className="invite-link-result" role="region" aria-labelledby="invite-link-heading"><h3 id="invite-link-heading">Acceptance link</h3><p>Copy this link now. Watchtower does not retain the invitation secret.</p><div className="copy-row"><input aria-label="Tenant acceptance link" readOnly value={createdInviteLink} onFocus={(event) => event.currentTarget.select()} /><button type="button" onClick={() => void copyInviteLink()}>Copy link</button></div></div>}
            </section>
            <section className="panel" aria-labelledby="access-profile-heading">
              <div className="panel-title"><h2 id="access-profile-heading">Access profiles</h2></div>
              <div className="access-profiles">{accessProfiles.map((profile) => <article key={profile.id}><h3>{profile.name}</h3><p>{profile.description}</p><ul>{profile.permissions.map((permission) => <li key={permission}>{permission.replaceAll("_", " ")}</li>)}</ul></article>)}</div>
            </section>
            <section className="panel invitations-panel" aria-labelledby="pending-invitations-heading">
              <div className="panel-title"><h2 id="pending-invitations-heading">Invitation history</h2><button type="button" onClick={() => void loadClientAccess()} disabled={accessLoading}>Refresh</button></div>
              {invitations.length ? <div className="table-scroll" role="region" aria-label="Client invitation history" tabIndex={0}><table><caption className="sr-only">Client invitation history</caption><thead><tr><th scope="col">Person</th><th scope="col">Profile</th><th scope="col">Status</th><th scope="col">Expires</th><th scope="col">Action</th></tr></thead><tbody>{invitations.map((invitation) => <tr key={invitation.id}><td><strong>{invitation.display_name || invitation.email}</strong>{invitation.display_name && <small>{invitation.email}</small>}</td><td>{accessProfiles.find((profile) => profile.id === invitation.role)?.name ?? invitation.role.replaceAll("_", " ")}</td><td><Status value={invitation.status} /></td><td><time dateTime={invitation.expires_at}>{new Date(invitation.expires_at).toLocaleDateString()}</time></td><td>{invitation.status === "pending" ? <button type="button" className="danger-action" onClick={() => void revokeInvitation(invitation.id)} disabled={accessLoading}>Revoke</button> : "—"}</td></tr>)}</tbody></table></div> : <Empty>No client invitations have been created.</Empty>}
            </section>
          </div>}
        </> : active === "Policies" ? <PolicyLibrary
          identityHeaders={identityHeaders}
          role={data.identity.role}
          tenantKey={organizationId}
          announce={setAnnouncement}
        /> : <>
          {error && <div className="error banner" role="alert">{error}</div>}
          <div className={`summary${data.identity.role === "auditor" ? " auditor-summary" : ""}`} aria-label="Operations summary" role="list">
            <div role="listitem"><span>Assessments</span><strong>{data.assessments.length}</strong><small>recent records</small></div>
            <div role="listitem"><span>Evidence queue</span><strong>{data.evidence.length}</strong><small>{data.evidence.filter((row) => row.scan_status !== "clean").length} unavailable</small></div>
            {data.identity.role !== "auditor" && <><div role="listitem"><span>Integrations</span><strong>{data.integrations.length}</strong><small>{data.integrations.filter((row) => row.status === "error").length} need attention</small></div>
            <div role="listitem"><span>Endpoints</span><strong>{data.endpoints.length}</strong><small>{data.endpoints.filter((row) => row.status !== "active").length} not active</small></div></>}
          </div>
          <div className="primary-grid">
            <section className="panel" aria-labelledby="assessment-progress-heading"><div className="panel-title"><h2 id="assessment-progress-heading">Assessment progress</h2><button type="button" onClick={() => setActive("Assessments")}>View assessments</button></div>{data.assessments.length ? <table><caption className="sr-only">Recent compliance assessments</caption><thead><tr><th scope="col">Assessment</th><th scope="col">Status</th><th scope="col">Updated</th></tr></thead><tbody>{data.assessments.map((row) => <tr key={row.id}><td>{row.name}</td><td><Status value={row.status} /></td><td><time dateTime={row.updated_at!}>{new Date(row.updated_at!).toLocaleDateString()}</time></td></tr>)}</tbody></table> : <Empty>No assessments have been created.</Empty>}</section>
            <section className="panel" aria-labelledby="evidence-queue-heading"><div className="panel-title"><h2 id="evidence-queue-heading">Evidence {data.identity.role === "auditor" ? "available" : "review queue"}</h2><button type="button" onClick={() => setActive("Evidence")}>{data.identity.role === "auditor" ? "View evidence" : "Review evidence"}</button></div>{data.evidence.length ? <table><caption className="sr-only">Tenant evidence</caption><thead><tr><th scope="col">Evidence</th><th scope="col">Sensitivity</th><th scope="col">State</th></tr></thead><tbody>{data.evidence.map((row) => <tr key={row.id}><td>{row.title}</td><td>{row.sensitivity}</td><td><Status value={row.scan_status} /></td></tr>)}</tbody></table> : <Empty>No evidence is available.</Empty>}</section>
          </div>
          <div className={`secondary-grid${data.identity.role === "auditor" ? " auditor-secondary" : ""}`}>
            {data.identity.role !== "auditor" && <><section className="panel"><div className="panel-title"><h2>Integration health</h2></div>{data.integrations.length ? data.integrations.map((row) => <div className="line" key={row.id}><span>{row.display_name}</span><Status value={row.status} /></div>) : <Empty>No integrations configured.</Empty>}</section>
            <section className="panel"><div className="panel-title"><h2>Endpoint fleet status</h2></div>{data.endpoints.length ? data.endpoints.map((row) => <div className="line" key={row.id}><span><strong>{row.hostname}</strong><small>{row.platform}</small></span><Status value={row.status} /></div>) : <Empty>No endpoint collectors enrolled.</Empty>}</section></>}
            <section className="panel"><div className="panel-title"><h2>Recent audit activity</h2></div>{data.audit.length ? data.audit.map((row, index) => <div className="audit-line" key={`${row.target_id}-${index}`}><span className="timeline-dot" aria-hidden="true" /><span><strong>{row.event_type?.replaceAll(".", " ")}</strong><small>{row.target_type}</small></span><time dateTime={row.occurred_at!}>{new Date(row.occurred_at!).toLocaleString()}</time></div>) : <Empty>No audit activity recorded.</Empty>}</section>
          </div>
        </>)}
      </section>
    </main>
  </div>;
}
