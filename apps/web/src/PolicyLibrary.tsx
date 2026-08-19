import { FormEvent, useCallback, useEffect, useState } from "react";

type Headers = Record<string, string>;
type PolicySummary = {
  id: string;
  title: string;
  document_type: string;
  status: string;
  owner_display_name: string | null;
  review_due_at: string | null;
  current_version: number;
  control_count: number;
  evidence_count: number;
  updated_at: string;
};
type PolicyVersion = {
  id: string;
  version_number: number;
  content: string;
  change_summary: string;
  created_at: string;
};
type PolicyDetail = PolicySummary & {
  versions: PolicyVersion[];
  controls: Array<{
    framework_pack_version_id: number;
    framework: string;
    control_reference: string;
    control_title: string;
  }>;
  evidence: Array<{
    evidence_id: string;
    evidence_title: string;
    relationship: string;
    notes: string | null;
  }>;
};
type ReferenceOptions = {
  controls: Array<{
    framework_pack_version_id: number;
    framework: string;
    reference: string;
    title: string;
  }>;
  evidence: Array<{
    id: string;
    title: string;
    assessment_name: string;
    sensitivity: string;
  }>;
};

const emptyOptions: ReferenceOptions = { controls: [], evidence: [] };
const editors = new Set(["customer_admin", "control_owner", "msp_admin", "msp_analyst"]);
const approvers = new Set(["customer_admin", "msp_admin"]);

function PolicyStatus({ value }: { value: string }) {
  return <span className={`status status-${value}`}>{value}</span>;
}

export function PolicyLibrary({
  identityHeaders,
  role,
  tenantKey,
  announce,
}: {
  identityHeaders: () => Headers;
  role: string;
  tenantKey: string;
  announce: (message: string) => void;
}) {
  const [policies, setPolicies] = useState<PolicySummary[]>([]);
  const [options, setOptions] = useState<ReferenceOptions>(emptyOptions);
  const [selected, setSelected] = useState<PolicyDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [title, setTitle] = useState("");
  const [documentType, setDocumentType] = useState("policy");
  const [owner, setOwner] = useState("");
  const [reviewDueAt, setReviewDueAt] = useState("");
  const [content, setContent] = useState("");
  const [selectedControls, setSelectedControls] = useState<string[]>([]);
  const [selectedEvidence, setSelectedEvidence] = useState<string[]>([]);
  const [revisionContent, setRevisionContent] = useState("");
  const [changeSummary, setChangeSummary] = useState("");

  const loadLibrary = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [documentsResponse, optionsResponse] = await Promise.all([
        fetch("/v1/policies", { headers: identityHeaders() }),
        fetch("/v1/policies/reference-options", { headers: identityHeaders() }),
      ]);
      if (!documentsResponse.ok || !optionsResponse.ok) {
        throw new Error("Policy library request failed");
      }
      setPolicies(await documentsResponse.json());
      setOptions(await optionsResponse.json());
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Policy library request failed");
    } finally {
      setLoading(false);
    }
  }, [identityHeaders]);

  useEffect(() => {
    setSelected(null);
    void loadLibrary();
  }, [loadLibrary, tenantKey]);

  async function viewPolicy(documentId: string) {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`/v1/policies/${documentId}`, { headers: identityHeaders() });
      if (!response.ok) throw new Error(`Policy request failed (${response.status})`);
      const detail = await response.json() as PolicyDetail;
      setSelected(detail);
      setRevisionContent(detail.versions[0]?.content ?? "");
      setChangeSummary("");
      announce(`${detail.title} opened.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Policy request failed");
    } finally {
      setLoading(false);
    }
  }

  function toggleSelection(value: string, current: string[], update: (values: string[]) => void) {
    update(current.includes(value) ? current.filter((item) => item !== value) : [...current, value]);
  }

  async function createPolicy(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const response = await fetch("/v1/policies", {
        method: "POST",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          document_type: documentType,
          owner_display_name: owner || null,
          review_due_at: reviewDueAt || null,
          content,
          controls: options.controls.filter((control) => selectedControls.includes(`${control.framework_pack_version_id}:${control.reference}`)).map((control) => ({
            framework_pack_version_id: control.framework_pack_version_id,
            control_reference: control.reference,
          })),
          evidence: selectedEvidence.map((evidenceId) => ({
            evidence_id: evidenceId,
            relationship: "supports",
          })),
        }),
      });
      if (!response.ok) {
        const problem = await response.json() as { detail?: string };
        throw new Error(problem.detail ?? `Policy creation failed (${response.status})`);
      }
      const created = await response.json() as PolicyDetail;
      setPolicies((current) => [created, ...current]);
      setSelected(created);
      setRevisionContent(created.versions[0]?.content ?? "");
      setTitle("");
      setOwner("");
      setReviewDueAt("");
      setContent("");
      setSelectedControls([]);
      setSelectedEvidence([]);
      announce(`${created.title} created as draft version 1.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Policy creation failed");
    } finally {
      setSaving(false);
    }
  }

  async function createRevision(event: FormEvent) {
    event.preventDefault();
    if (!selected) return;
    setSaving(true);
    setError("");
    try {
      const response = await fetch(`/v1/policies/${selected.id}/versions`, {
        method: "POST",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ content: revisionContent, change_summary: changeSummary }),
      });
      if (!response.ok) throw new Error(`Revision creation failed (${response.status})`);
      const revised = await response.json() as PolicyDetail;
      setSelected(revised);
      setPolicies((current) => current.map((item) => item.id === revised.id ? revised : item));
      setChangeSummary("");
      announce(`${revised.title} version ${revised.current_version} created as a draft.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Revision creation failed");
    } finally {
      setSaving(false);
    }
  }

  async function approvePolicy() {
    if (!selected) return;
    setSaving(true);
    setError("");
    try {
      const response = await fetch(`/v1/policies/${selected.id}/status`, {
        method: "PUT",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ status: "approved", review_due_at: selected.review_due_at }),
      });
      if (!response.ok) throw new Error(`Policy approval failed (${response.status})`);
      const approved = await response.json() as PolicyDetail;
      setSelected(approved);
      setPolicies((current) => current.map((item) => item.id === approved.id ? approved : item));
      announce(`${approved.title} approved.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Policy approval failed");
    } finally {
      setSaving(false);
    }
  }

  return <div className="policy-library">
    {error && <div className="error banner" role="alert">{error}</div>}
    <section className="panel policy-index" aria-labelledby="policy-index-heading">
      <div className="panel-title">
        <h2 id="policy-index-heading">Document library</h2>
        <button type="button" onClick={() => void loadLibrary()} disabled={loading}>Refresh</button>
      </div>
      {policies.length ? <div className="table-scroll" role="region" aria-label="Policies and procedures" tabIndex={0}>
        <table>
          <caption className="sr-only">Tenant policies and procedures</caption>
          <thead><tr><th scope="col">Document</th><th scope="col">Status</th><th scope="col">Coverage</th><th scope="col">Updated</th><th scope="col">Action</th></tr></thead>
          <tbody>{policies.map((policy) => <tr key={policy.id}>
            <td><strong>{policy.title}</strong><small>{policy.document_type} · version {policy.current_version}</small></td>
            <td><PolicyStatus value={policy.status} /></td>
            <td>{policy.control_count} controls · {policy.evidence_count} evidence</td>
            <td><time dateTime={policy.updated_at}>{new Date(policy.updated_at).toLocaleDateString()}</time></td>
            <td><button type="button" className="table-action" onClick={() => void viewPolicy(policy.id)}>View</button></td>
          </tr>)}</tbody>
        </table>
      </div> : <div className="empty">No policies or procedures have been documented.</div>}
    </section>

    {editors.has(role) && <section className="panel policy-editor" aria-labelledby="create-policy-heading">
      <div className="panel-title"><h2 id="create-policy-heading">Create a controlled document</h2></div>
      <form className="policy-form" onSubmit={createPolicy}>
        <div className="policy-form-grid">
          <label>Title<input value={title} onChange={(event) => setTitle(event.target.value)} required maxLength={240} /></label>
          <label>Document type<select value={documentType} onChange={(event) => setDocumentType(event.target.value)}><option value="policy">Policy</option><option value="procedure">Procedure</option><option value="standard">Standard</option><option value="guideline">Guideline</option></select></label>
          <label>Owner <span className="optional">Optional</span><input value={owner} onChange={(event) => setOwner(event.target.value)} maxLength={200} /></label>
          <label>Review due <span className="optional">Optional</span><input type="date" value={reviewDueAt} onChange={(event) => setReviewDueAt(event.target.value)} /></label>
        </div>
        <label>Document body<textarea value={content} onChange={(event) => setContent(event.target.value)} rows={9} required placeholder="Document the purpose, scope, responsibilities, and required activities." /></label>
        <div className="reference-grid">
          <fieldset><legend>Cross-reference controls</legend>{options.controls.length ? options.controls.map((control) => {
            const value = `${control.framework_pack_version_id}:${control.reference}`;
            return <label className="check-row" key={value}><input type="checkbox" checked={selectedControls.includes(value)} onChange={() => toggleSelection(value, selectedControls, setSelectedControls)} /><span><strong>{control.reference}</strong>{control.title}<small>{control.framework}</small></span></label>;
          }) : <p>No assessed framework controls are available.</p>}</fieldset>
          <fieldset><legend>Link supporting evidence</legend>{options.evidence.length ? options.evidence.map((evidence) => <label className="check-row" key={evidence.id}><input type="checkbox" checked={selectedEvidence.includes(evidence.id)} onChange={() => toggleSelection(evidence.id, selectedEvidence, setSelectedEvidence)} /><span><strong>{evidence.title}</strong>{evidence.assessment_name}<small>{evidence.sensitivity.replaceAll("_", " ")}</small></span></label>) : <p>No tenant evidence is available.</p>}</fieldset>
        </div>
        <p className="form-note">Saving creates immutable version 1. Later changes are retained as new versions.</p>
        <button type="submit" disabled={saving}>{saving ? "Saving…" : "Create draft"}</button>
      </form>
    </section>}

    {selected && <section className="panel policy-detail" aria-labelledby="policy-detail-heading">
      <div className="panel-title"><h2 id="policy-detail-heading">{selected.title}</h2><div className="policy-actions"><PolicyStatus value={selected.status} />{approvers.has(role) && selected.status !== "approved" && <button type="button" onClick={() => void approvePolicy()} disabled={saving}>Approve</button>}</div></div>
      <div className="policy-detail-body">
        <dl className="policy-metadata"><div><dt>Type</dt><dd>{selected.document_type}</dd></div><div><dt>Owner</dt><dd>{selected.owner_display_name ?? "Not assigned"}</dd></div><div><dt>Current version</dt><dd>{selected.current_version}</dd></div><div><dt>Review due</dt><dd>{selected.review_due_at ? new Date(`${selected.review_due_at}T00:00:00`).toLocaleDateString() : "Not scheduled"}</dd></div></dl>
        <article className="document-content"><h3>Current document</h3><pre>{selected.versions[0]?.content}</pre></article>
        <div className="reference-grid policy-links">
          <section aria-labelledby="linked-controls-heading"><h3 id="linked-controls-heading">Linked controls</h3>{selected.controls.length ? <ul>{selected.controls.map((control) => <li key={`${control.framework_pack_version_id}:${control.control_reference}`}><strong>{control.control_reference}</strong> — {control.control_title}<small>{control.framework}</small></li>)}</ul> : <p>No controls linked.</p>}</section>
          <section aria-labelledby="linked-evidence-heading"><h3 id="linked-evidence-heading">Linked evidence</h3>{selected.evidence.length ? <ul>{selected.evidence.map((evidence) => <li key={evidence.evidence_id}><strong>{evidence.evidence_title}</strong><small>{evidence.relationship}{evidence.notes ? ` · ${evidence.notes}` : ""}</small></li>)}</ul> : <p>No evidence linked.</p>}</section>
        </div>
        <section className="version-history" aria-labelledby="version-history-heading"><h3 id="version-history-heading">Version history</h3><ol>{selected.versions.map((version) => <li key={version.id}><strong>Version {version.version_number}</strong><span>{version.change_summary}</span><time dateTime={version.created_at}>{new Date(version.created_at).toLocaleString()}</time></li>)}</ol></section>
        {editors.has(role) && <form className="revision-form" onSubmit={createRevision}><h3>Create a new revision</h3><label>Document body<textarea rows={9} value={revisionContent} onChange={(event) => setRevisionContent(event.target.value)} required /></label><label>Change summary<input value={changeSummary} onChange={(event) => setChangeSummary(event.target.value)} required maxLength={1000} /></label><button type="submit" disabled={saving}>{saving ? "Saving…" : "Save new version"}</button></form>}
      </div>
    </section>}
  </div>;
}
