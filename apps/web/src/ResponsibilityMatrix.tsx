import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type Headers = Record<string, string>;
type Holder = {
  id: string;
  display_name: string;
  email: string | null;
  is_primary: boolean;
  starts_on: string | null;
  ends_on: string | null;
};
type Role = {
  id: string;
  name: string;
  description: string | null;
  party: "customer" | "msp" | "vendor";
  status: string;
  holders: Holder[];
};
type Assignment = {
  id: string;
  role_id: string;
  role_name: string;
  role_party: string;
  target_type: "policy" | "control";
  target_key: string;
  target_title: string;
  framework: string | null;
  raci: "responsible" | "accountable" | "consulted" | "informed";
  delivery_model: "customer" | "msp" | "shared" | "vendor";
  notes: string | null;
};
type Matrix = {
  roles: Role[];
  assignments: Assignment[];
  options: {
    policies: Array<{ id: string; title: string; document_type: string; status: string; current_version: number }>;
    controls: Array<{ framework_pack_version_id: number; framework: string; reference: string; title: string }>;
  };
};

const emptyMatrix: Matrix = { roles: [], assignments: [], options: { policies: [], controls: [] } };
const administrators = new Set(["customer_admin", "msp_admin"]);
const raciLabels = {
  accountable: "Accountable",
  responsible: "Responsible",
  consulted: "Consulted",
  informed: "Informed",
};

function partyLabel(party: Role["party"]): string {
  return party === "msp" ? "MSP" : party[0].toUpperCase() + party.slice(1);
}

export function ResponsibilityMatrix({
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
  const [matrix, setMatrix] = useState<Matrix>(emptyMatrix);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [roleName, setRoleName] = useState("");
  const [roleParty, setRoleParty] = useState("customer");
  const [roleDescription, setRoleDescription] = useState("");
  const [holderRoleId, setHolderRoleId] = useState("");
  const [holderName, setHolderName] = useState("");
  const [holderEmail, setHolderEmail] = useState("");
  const [holderPrimary, setHolderPrimary] = useState(false);
  const [mappingRoleId, setMappingRoleId] = useState("");
  const [targetType, setTargetType] = useState<"policy" | "control">("policy");
  const [targetKey, setTargetKey] = useState("");
  const [raci, setRaci] = useState("responsible");
  const [deliveryModel, setDeliveryModel] = useState("customer");
  const [notes, setNotes] = useState("");

  const loadMatrix = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/v1/responsibilities", { headers: identityHeaders() });
      if (!response.ok) throw new Error(`Responsibility matrix request failed (${response.status})`);
      const loaded = await response.json() as Matrix;
      setMatrix(loaded);
      setHolderRoleId((current) => current || loaded.roles[0]?.id || "");
      setMappingRoleId((current) => current || loaded.roles[0]?.id || "");
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Responsibility matrix request failed");
    } finally {
      setLoading(false);
    }
  }, [identityHeaders]);

  useEffect(() => { void loadMatrix(); }, [loadMatrix, tenantKey]);

  const targets = useMemo(() => {
    const grouped = new Map<string, { title: string; type: string; framework: string | null; assignments: Assignment[] }>();
    for (const assignment of matrix.assignments) {
      const key = `${assignment.target_type}:${assignment.target_key}`;
      const current = grouped.get(key) ?? {
        title: assignment.target_title,
        type: assignment.target_type,
        framework: assignment.framework,
        assignments: [],
      };
      current.assignments.push(assignment);
      grouped.set(key, current);
    }
    return [...grouped.entries()];
  }, [matrix.assignments]);

  async function createRole(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const response = await fetch("/v1/responsibility-roles", {
        method: "POST",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ name: roleName, party: roleParty, description: roleDescription || null }),
      });
      if (!response.ok) {
        const problem = await response.json() as { detail?: string };
        throw new Error(problem.detail ?? `Role creation failed (${response.status})`);
      }
      const created = await response.json() as Role;
      setMatrix((current) => ({ ...current, roles: [...current.roles, created] }));
      setHolderRoleId((current) => current || created.id);
      setMappingRoleId((current) => current || created.id);
      setRoleName("");
      setRoleDescription("");
      announce(`${created.name} added to the organizational role catalog.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Role creation failed");
    } finally {
      setSaving(false);
    }
  }

  async function addHolder(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const response = await fetch(`/v1/responsibility-roles/${holderRoleId}/holders`, {
        method: "POST",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({
          display_name: holderName,
          email: holderEmail || null,
          is_primary: holderPrimary,
        }),
      });
      if (!response.ok) {
        const problem = await response.json() as { detail?: string };
        throw new Error(problem.detail ?? `Role-holder assignment failed (${response.status})`);
      }
      const holder = await response.json() as Holder;
      setMatrix((current) => ({
        ...current,
        roles: current.roles.map((item) => item.id === holderRoleId ? { ...item, holders: [...item.holders, holder] } : item),
      }));
      setHolderName("");
      setHolderEmail("");
      setHolderPrimary(false);
      announce("Role holder assigned. This did not grant application access.");
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Role-holder assignment failed");
    } finally {
      setSaving(false);
    }
  }

  async function createMapping(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const policyTarget = targetType === "policy";
      const separator = targetKey.indexOf(":");
      const frameworkVersion = policyTarget ? null : targetKey.slice(0, separator);
      const controlReference = policyTarget ? null : targetKey.slice(separator + 1);
      const response = await fetch("/v1/responsibility-assignments", {
        method: "POST",
        headers: { ...identityHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({
          role_id: mappingRoleId,
          target_type: targetType,
          policy_document_id: policyTarget ? targetKey : null,
          framework_pack_version_id: policyTarget ? null : Number(frameworkVersion),
          control_reference: controlReference,
          raci,
          delivery_model: deliveryModel,
          notes: notes || null,
        }),
      });
      if (!response.ok) {
        const problem = await response.json() as { detail?: string };
        throw new Error(problem.detail ?? `Responsibility mapping failed (${response.status})`);
      }
      const assignment = await response.json() as Assignment;
      setMatrix((current) => ({ ...current, assignments: [...current.assignments, assignment] }));
      setNotes("");
      announce(`${assignment.role_name} mapped as ${assignment.raci} for ${assignment.target_title}.`);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Responsibility mapping failed");
    } finally {
      setSaving(false);
    }
  }

  async function removeMapping(assignmentId: string) {
    setSaving(true);
    setError("");
    try {
      const response = await fetch(`/v1/responsibility-assignments/${assignmentId}`, {
        method: "DELETE",
        headers: identityHeaders(),
      });
      if (!response.ok) throw new Error(`Responsibility removal failed (${response.status})`);
      setMatrix((current) => ({ ...current, assignments: current.assignments.filter((item) => item.id !== assignmentId) }));
      announce("Responsibility mapping removed and recorded in the audit ledger.");
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Responsibility removal failed");
    } finally {
      setSaving(false);
    }
  }

  const canManage = administrators.has(role);
  const availableTargets = targetType === "policy" ? matrix.options.policies : matrix.options.controls;

  return <div className="responsibility-workspace">
    {error && <div className="error banner" role="alert">{error}</div>}
    <section className="responsibility-summary" aria-label="Responsibility summary">
      <div><span>Organizational roles</span><strong>{matrix.roles.length}</strong></div>
      <div><span>Named role holders</span><strong>{matrix.roles.reduce((total, item) => total + item.holders.length, 0)}</strong></div>
      <div><span>Mapped responsibilities</span><strong>{matrix.assignments.length}</strong></div>
      <div><span>Shared delivery</span><strong>{matrix.assignments.filter((item) => item.delivery_model === "shared").length}</strong></div>
    </section>

    <section className="panel responsibility-roles" aria-labelledby="organizational-roles-heading">
      <div className="panel-title"><h2 id="organizational-roles-heading">Organizational role catalog</h2><button type="button" onClick={() => void loadMatrix()} disabled={loading}>Refresh</button></div>
      {matrix.roles.length ? <div className="role-card-grid">{matrix.roles.map((item) => <article className="role-card" key={item.id}><div><span className={`party-badge party-${item.party}`}>{partyLabel(item.party)}</span><h3>{item.name}</h3><p>{item.description ?? "No responsibility description documented."}</p></div><div className="role-holders"><h4>Current role holders</h4>{item.holders.length ? <ul>{item.holders.map((holder) => <li key={holder.id}><strong>{holder.display_name}{holder.is_primary && <span className="primary-holder">Primary</span>}</strong><span>{holder.email ?? "No email recorded"}</span></li>)}</ul> : <p>Vacant or not yet assigned.</p>}</div></article>)}</div> : <div className="empty">No organizational responsibility roles have been documented.</div>}
    </section>

    {canManage && <div className="responsibility-editor-grid">
      <section className="panel" aria-labelledby="create-role-heading"><div className="panel-title"><h2 id="create-role-heading">Create an organizational role</h2></div><form className="responsibility-form" onSubmit={createRole}><label>Role name<input value={roleName} onChange={(event) => setRoleName(event.target.value)} required /></label><label>Organization party<select value={roleParty} onChange={(event) => setRoleParty(event.target.value)}><option value="customer">Customer</option><option value="msp">MSP</option><option value="vendor">Vendor</option></select></label><label>Description<textarea value={roleDescription} onChange={(event) => setRoleDescription(event.target.value)} rows={4} placeholder="Describe the authority, decisions, and recurring duties attached to this role." /></label><button type="submit" disabled={saving}>{saving ? "Saving…" : "Create role"}</button></form></section>
      <section className="panel" aria-labelledby="assign-holder-heading"><div className="panel-title"><h2 id="assign-holder-heading">Assign a role holder</h2></div><form className="responsibility-form" onSubmit={addHolder}><label>Organizational role<select value={holderRoleId} onChange={(event) => setHolderRoleId(event.target.value)} required><option value="" disabled>Select a role</option>{matrix.roles.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label>Person's name<input value={holderName} onChange={(event) => setHolderName(event.target.value)} autoComplete="name" required /></label><label>Email <span className="optional">Optional</span><input type="email" value={holderEmail} onChange={(event) => setHolderEmail(event.target.value)} autoComplete="email" /></label><label className="responsibility-check"><input type="checkbox" checked={holderPrimary} onChange={(event) => setHolderPrimary(event.target.checked)} /><span>Primary holder for this role</span></label><p className="form-note">Documenting a role holder does not grant Watchtower access. Tenant permissions remain separately administered.</p><button type="submit" disabled={saving || !holderRoleId}>{saving ? "Saving…" : "Assign holder"}</button></form></section>
    </div>}

    {canManage && <section className="panel responsibility-mapper" aria-labelledby="map-responsibility-heading"><div className="panel-title"><h2 id="map-responsibility-heading">Map responsibility</h2></div><form className="responsibility-form responsibility-map-form" onSubmit={createMapping}><label>Organizational role<select value={mappingRoleId} onChange={(event) => setMappingRoleId(event.target.value)} required><option value="" disabled>Select a role</option>{matrix.roles.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label>Target type<select value={targetType} onChange={(event) => { setTargetType(event.target.value as "policy" | "control"); setTargetKey(""); }}><option value="policy">Policy or procedure</option><option value="control">Assessed control</option></select></label><label>Policy or control<select value={targetKey} onChange={(event) => setTargetKey(event.target.value)} required><option value="" disabled>Select a target</option>{targetType === "policy" ? matrix.options.policies.map((item) => <option key={item.id} value={item.id}>{item.title} · v{item.current_version}</option>) : matrix.options.controls.map((item) => <option key={`${item.framework_pack_version_id}:${item.reference}`} value={`${item.framework_pack_version_id}:${item.reference}`}>{item.reference} · {item.title}</option>)}</select></label><label>RACI relationship<select value={raci} onChange={(event) => setRaci(event.target.value)}><option value="responsible">Responsible — performs the work</option><option value="accountable">Accountable — owns the outcome</option><option value="consulted">Consulted — provides input</option><option value="informed">Informed — receives updates</option></select></label><label>Delivery model<select value={deliveryModel} onChange={(event) => setDeliveryModel(event.target.value)}><option value="customer">Customer-owned</option><option value="msp">MSP-owned</option><option value="shared">Shared responsibility</option><option value="vendor">Vendor-owned</option></select></label><label>Responsibility notes <span className="optional">Optional</span><input value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Clarify boundaries, handoffs, or escalation expectations." /></label><button type="submit" disabled={saving || !mappingRoleId || !targetKey || !availableTargets.length}>{saving ? "Saving…" : "Add responsibility"}</button></form></section>}

    <section className="panel responsibility-matrix" aria-labelledby="responsibility-matrix-heading"><div className="panel-title"><h2 id="responsibility-matrix-heading">Responsibility matrix</h2></div>{targets.length ? <div className="table-scroll" role="region" aria-label="RACI responsibility matrix" tabIndex={0}><table><caption className="sr-only">Organizational responsibilities by policy and compliance control</caption><thead><tr><th scope="col">Policy or control</th><th scope="col">Accountable</th><th scope="col">Responsible</th><th scope="col">Consulted</th><th scope="col">Informed</th><th scope="col">Delivery</th>{canManage && <th scope="col">Action</th>}</tr></thead><tbody>{targets.map(([key, target]) => <tr key={key}><td><strong>{target.title}</strong><small>{target.framework ?? target.type}</small></td>{(["accountable", "responsible", "consulted", "informed"] as const).map((relationship) => <td key={relationship}>{target.assignments.filter((item) => item.raci === relationship).map((item) => <span className="matrix-role" key={item.id}>{item.role_name}<small>{item.role_party}</small></span>)}</td>)}<td>{[...new Set(target.assignments.map((item) => item.delivery_model))].map((model) => <span className={`delivery-badge delivery-${model}`} key={model}>{model}</span>)}</td>{canManage && <td>{target.assignments.map((item) => <button type="button" className="table-action mapping-remove" key={item.id} onClick={() => void removeMapping(item.id)} aria-label={`Remove ${raciLabels[item.raci]} mapping for ${item.role_name}`}>Remove {item.raci[0].toUpperCase()}</button>)}</td>}</tr>)}</tbody></table></div> : <div className="empty">No policy or control responsibilities have been mapped.</div>}</section>
  </div>;
}
