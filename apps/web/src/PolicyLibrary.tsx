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
type AgreementRequest = {
  id: string;
  policy_document_id: string;
  policy_version: number;
  recipient_email: string;
  recipient_display_name: string | null;
  document_sha256: string;
  status: "pending" | "acknowledged" | "revoked" | "expired";
  expires_at: string;
  created_at: string;
  acknowledged_at: string | null;
  revoked_at: string | null;
  signer_display_name: string | null;
  identity_assurance: string | null;
  recurrence_days: number | null;
  prompt_before_days: number;
  next_review_at: string | null;
  schedule_basis: string | null;
  renewal_available: boolean;
};
type CadenceSuggestion = {
  key: string;
  label: string;
  recurrence_days: number;
  prompt_before_days: number;
  rationale: string;
  source_label: string;
  source_url: string;
  qualification: string;
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
  const [agreements, setAgreements] = useState<AgreementRequest[]>([]);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [recipientName, setRecipientName] = useState("");
  const [expiresInDays, setExpiresInDays] = useState("14");
  const [agreementLink, setAgreementLink] = useState("");
  const [cadenceSuggestions, setCadenceSuggestions] = useState<CadenceSuggestion[]>([]);
  const [cadenceKey, setCadenceKey] = useState("one-time");
  const [recurrenceDays, setRecurrenceDays] = useState<number | null>(null);
  const [promptBeforeDays, setPromptBeforeDays] = useState(14);

  const loadLibrary = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [documentsResponse, optionsResponse, cadenceResponse] = await Promise.all([
        fetch("/v1/policies", { headers: identityHeaders() }),
        fetch("/v1/policies/reference-options", { headers: identityHeaders() }),
        approvers.has(role)
          ? fetch("/v1/policies/agreement-cadence-suggestions", { headers: identityHeaders() })
          : Promise.resolve(null),
      ]);
      if (!documentsResponse.ok || !optionsResponse.ok || (cadenceResponse && !cadenceResponse.ok)) {
        throw new Error("Policy library request failed");
      }
      setPolicies(await documentsResponse.json());
      setOptions(await optionsResponse.json());
      setCadenceSuggestions(cadenceResponse ? await cadenceResponse.json() as CadenceSuggestion[] : []);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Policy library request failed");
    } finally {
      setLoading(false);
    }
  }, [identityHeaders, role]);

  useEffect(() => {
    setSelected(null);
    setAgreements([]);
    setAgreementLink("");
    void loadLibrary();
  }, [loadLibrary, tenantKey]);

  async function viewPolicy(documentId: string) {
    setLoading(true);
    setError("");
    try {
      const [response, agreementsResponse] = await Promise.all([
        fetch(`/v1/policies/${documentId}`, { headers: identityHeaders() }),
        approvers.has(role)
          ? fetch(`/v1/policies/${documentId}/agreements`, { headers: identityHeaders() })
          : Promise.resolve(null),
      ]);
      if (!response.ok) throw new Error(`Policy request failed (${response.status})`);
      if (agreementsResponse && !agreementsResponse.ok) throw new Error(`Agreement history failed (${agreementsResponse.status})`);
      const detail = await response.json() as PolicyDetail;
      setSelected(detail);
      setAgreements(agreementsResponse ? await agreementsResponse.json() as AgreementRequest[] : []);
      setAgreementLink("");
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

  async function createAgreement(event: FormEvent) {
    event.preventDefault();
    if (!selected) return;
    setSaving(true);
    setError("");
    try {
      const response = await fetch(`/v1/policies/${selected.id}/agreements`, {
        method: "POST",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({
          recipient_email: recipientEmail,
          recipient_display_name: recipientName || null,
          expires_in_days: Number(expiresInDays),
          recurrence_days: recurrenceDays,
          prompt_before_days: recurrenceDays === null ? 14 : promptBeforeDays,
          schedule_basis: recurrenceDays === null ? null : cadenceKey,
        }),
      });
      if (!response.ok) {
        const problem = await response.json() as { detail?: string };
        throw new Error(problem.detail ?? `Agreement request failed (${response.status})`);
      }
      const created = await response.json() as AgreementRequest & { token: string };
      setAgreements((current) => [created, ...current]);
      setAgreementLink(`${window.location.origin}${window.location.pathname}#agreement=${encodeURIComponent(created.token)}`);
      setRecipientEmail("");
      setRecipientName("");
      announce(`Acknowledgement link created for ${created.recipient_email}. Copy it now; the secret is shown once.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Agreement request failed");
    } finally {
      setSaving(false);
    }
  }

  function selectCadence(key: string) {
    setCadenceKey(key);
    if (key === "one-time") {
      setRecurrenceDays(null);
      setPromptBeforeDays(14);
      return;
    }
    if (key === "custom") {
      setRecurrenceDays(365);
      setPromptBeforeDays(30);
      return;
    }
    const suggestion = cadenceSuggestions.find((item) => item.key === key);
    if (suggestion) {
      setRecurrenceDays(suggestion.recurrence_days);
      setPromptBeforeDays(suggestion.prompt_before_days);
    }
  }

  async function renewAgreement(agreement: AgreementRequest) {
    setSaving(true);
    setError("");
    try {
      const response = await fetch(`/v1/policy-agreements/${agreement.id}/renew`, {
        method: "POST",
        headers: identityHeaders(),
      });
      if (!response.ok) {
        const problem = await response.json() as { detail?: string };
        throw new Error(problem.detail ?? `Scheduled review creation failed (${response.status})`);
      }
      const renewed = await response.json() as AgreementRequest & { token: string };
      setAgreements((current) => [renewed, ...current.map((item) => item.id === agreement.id ? { ...item, renewal_available: false } : item)]);
      setAgreementLink(`${window.location.origin}${window.location.pathname}#agreement=${encodeURIComponent(renewed.token)}`);
      announce(`Scheduled review link created for ${renewed.recipient_email}. Copy it now; the secret is shown once.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Scheduled review creation failed");
    } finally {
      setSaving(false);
    }
  }

  async function revokeAgreement(agreementId: string) {
    setSaving(true);
    setError("");
    try {
      const response = await fetch(`/v1/policy-agreements/${agreementId}`, {
        method: "DELETE",
        headers: identityHeaders(),
      });
      if (!response.ok) throw new Error(`Agreement revocation failed (${response.status})`);
      if (selected) {
        const refreshed = await fetch(`/v1/policies/${selected.id}/agreements`, { headers: identityHeaders() });
        if (!refreshed.ok) throw new Error(`Agreement history refresh failed (${refreshed.status})`);
        setAgreements(await refreshed.json() as AgreementRequest[]);
      }
      announce("Acknowledgement request revoked.");
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Agreement revocation failed");
    } finally {
      setSaving(false);
    }
  }

  async function copyAgreementLink() {
    await navigator.clipboard.writeText(agreementLink);
    announce("Acknowledgement link copied.");
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
        {approvers.has(role) && <section className="policy-agreements" aria-labelledby="policy-agreements-heading">
          <div className="policy-agreements-heading"><div><h3 id="policy-agreements-heading">End-user acknowledgements</h3><p>Issue a recipient-specific link for this exact approved version. The link grants access only to this document—not the tenant dashboard.</p></div><span>{agreements.length} request{agreements.length === 1 ? "" : "s"}</span></div>
          {selected.status === "approved" ? <form className="agreement-request-form" onSubmit={createAgreement}>
            <div className="policy-form-grid">
              <label>Recipient email<input type="email" value={recipientEmail} onChange={(event) => setRecipientEmail(event.target.value)} autoComplete="email" required /></label>
              <label>Recipient name <span className="optional">Optional</span><input value={recipientName} onChange={(event) => setRecipientName(event.target.value)} autoComplete="name" maxLength={200} /></label>
              <label>Link expires in<select value={expiresInDays} onChange={(event) => setExpiresInDays(event.target.value)}><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option></select></label>
              <label>Review schedule<select value={cadenceKey} onChange={(event) => selectCadence(event.target.value)}><option value="one-time">One-time acknowledgement</option>{cadenceSuggestions.map((suggestion) => <option key={suggestion.key} value={suggestion.key}>{suggestion.label}</option>)}<option value="custom">Custom cadence</option></select></label>
              {cadenceKey === "custom" && <label>Repeat every (days)<input type="number" min="90" max="1095" value={recurrenceDays ?? 365} onChange={(event) => setRecurrenceDays(Number(event.target.value))} required /></label>}
              {recurrenceDays !== null && <label>Prompt before due date<select value={promptBeforeDays} onChange={(event) => setPromptBeforeDays(Number(event.target.value))}><option value="7">7 days before</option><option value="14">14 days before</option><option value="30">30 days before</option></select></label>}
            </div>
            {cadenceKey !== "one-time" && cadenceKey !== "custom" && (() => { const suggestion = cadenceSuggestions.find((item) => item.key === cadenceKey); return suggestion ? <aside className="cadence-guidance" aria-label="Cadence guidance"><strong>{suggestion.rationale}</strong><span>{suggestion.qualification}</span><a href={suggestion.source_url} target="_blank" rel="noreferrer">Source: {suggestion.source_label}</a></aside> : null; })()}
            <p className="form-note">Watchtower records the signer, exact version and SHA-256 fingerprint, attestation, timestamp, and request metadata in an immutable receipt.</p>
            <button type="submit" disabled={saving}>{saving ? "Creating…" : "Create acknowledgement link"}</button>
          </form> : <p className="approval-required">Approve the current draft before requesting acknowledgement.</p>}
          {agreementLink && <div className="agreement-link-result" role="status"><h4>One-time link ready</h4><p>Copy this link now. Watchtower stores only its hash and cannot display the secret again.</p><div className="copy-row"><input aria-label="End-user acknowledgement link" value={agreementLink} readOnly /><button type="button" onClick={() => void copyAgreementLink()}>Copy link</button></div></div>}
          {agreements.length ? <div className="table-scroll" role="region" aria-label="Policy acknowledgement requests" tabIndex={0}><table><caption className="sr-only">Policy acknowledgement requests and receipts</caption><thead><tr><th scope="col">Recipient</th><th scope="col">Version</th><th scope="col">Status</th><th scope="col">Activity</th><th scope="col">Next review</th><th scope="col">Action</th></tr></thead><tbody>{agreements.map((agreement) => <tr key={agreement.id}><td><strong>{agreement.recipient_display_name ?? agreement.recipient_email}</strong><small>{agreement.recipient_email}</small></td><td>{agreement.policy_version}</td><td><PolicyStatus value={agreement.status} /></td><td>{agreement.acknowledged_at ? <><time dateTime={agreement.acknowledged_at}>{new Date(agreement.acknowledged_at).toLocaleString()}</time><small>Signed by {agreement.signer_display_name ?? "recipient"}</small></> : <><time dateTime={agreement.expires_at}>Expires {new Date(agreement.expires_at).toLocaleDateString()}</time><small>Requested {new Date(agreement.created_at).toLocaleDateString()}</small></>}</td><td>{agreement.next_review_at ? <><time dateTime={agreement.next_review_at}>{new Date(agreement.next_review_at).toLocaleDateString()}</time><small>{agreement.prompt_before_days} day prompt · every {agreement.recurrence_days} days</small></> : agreement.recurrence_days ? <span>Starts after signing</span> : <span>One time</span>}</td><td>{agreement.status === "pending" ? <button type="button" className="danger-action" disabled={saving} onClick={() => void revokeAgreement(agreement.id)}>Revoke</button> : agreement.renewal_available ? <button type="button" className="table-action" disabled={saving} onClick={() => void renewAgreement(agreement)}>Create review link</button> : <span>—</span>}</td></tr>)}</tbody></table></div> : <p className="empty">No acknowledgement requests for this document.</p>}
        </section>}
        {editors.has(role) && <form className="revision-form" onSubmit={createRevision}><h3>Create a new revision</h3><label>Document body<textarea rows={9} value={revisionContent} onChange={(event) => setRevisionContent(event.target.value)} required /></label><label>Change summary<input value={changeSummary} onChange={(event) => setChangeSummary(event.target.value)} required maxLength={1000} /></label><button type="submit" disabled={saving}>{saving ? "Saving…" : "Save new version"}</button></form>}
      </div>
    </section>}
  </div>;
}
