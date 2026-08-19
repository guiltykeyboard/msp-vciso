import { FormEvent, useEffect, useState } from "react";

type Agreement = {
  request_id: string;
  organization_name: string;
  document_title: string;
  document_type: string;
  version_number: number;
  document_content: string;
  document_sha256: string;
  recipient_email: string;
  recipient_display_name: string | null;
  attestation_text: string;
  agreement_status: "pending" | "acknowledged";
  expires_at: string;
  acknowledged_at: string | null;
};

type Receipt = {
  acknowledgement_id: string;
  signed_at: string;
  signed_document_sha256: string;
  signed_version: number;
};

export function AgreementAcceptance({ token }: { token: string }) {
  const [agreement, setAgreement] = useState<Agreement | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [signerName, setSignerName] = useState("");
  const [agreed, setAgreed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [signing, setSigning] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let current = true;
    async function inspectAgreement() {
      try {
        const response = await fetch("/v1/policy-agreements:inspect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        if (!response.ok) {
          throw new Error(response.status === 401
            ? "This agreement link is invalid, expired, or revoked."
            : `Agreement request failed (${response.status})`);
        }
        const inspected = await response.json() as Agreement;
        if (!current) return;
        setAgreement(inspected);
        setSignerName(inspected.recipient_display_name ?? "");
      } catch (problem) {
        if (current) setError(problem instanceof Error ? problem.message : "Agreement request failed");
      } finally {
        if (current) setLoading(false);
      }
    }
    void inspectAgreement();
    return () => { current = false; };
  }, [token]);

  async function acknowledge(event: FormEvent) {
    event.preventDefault();
    if (!agreed || signing) return;
    setSigning(true);
    setError("");
    try {
      const response = await fetch("/v1/policy-agreements:acknowledge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token,
          signer_display_name: signerName,
          agreed: true,
        }),
      });
      if (!response.ok) {
        throw new Error(response.status === 401
          ? "This agreement has expired, was revoked, or was already acknowledged."
          : `Acknowledgement failed (${response.status})`);
      }
      const signedReceipt = await response.json() as Receipt;
      setReceipt(signedReceipt);
      window.history.replaceState({}, "", window.location.pathname);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Acknowledgement failed");
    } finally {
      setSigning(false);
    }
  }

  if (loading) {
    return <main className="agreement-page" id="main-content" aria-busy="true">
      <div className="agreement-shell"><p>Loading protected document…</p></div>
    </main>;
  }

  if (error && !agreement) {
    return <main className="agreement-page" id="main-content">
      <section className="agreement-shell agreement-error" aria-labelledby="agreement-error-heading">
        <div className="brand invitation-brand"><span className="brand-mark">W</span><span>Watchtower</span></div>
        <h1 id="agreement-error-heading">Document unavailable</h1>
        <p role="alert">{error}</p>
        <p>Contact the organization that sent the agreement for a new link.</p>
      </section>
    </main>;
  }

  if (!agreement) return null;

  const completed = receipt || agreement.agreement_status === "acknowledged";
  return <main className="agreement-page" id="main-content">
    <div className="agreement-shell">
      <header className="agreement-header">
        <div className="brand invitation-brand"><span className="brand-mark">W</span><span>Watchtower</span></div>
        <div><span>{agreement.organization_name}</span><h1>{agreement.document_title}</h1><p>{agreement.document_type} · version {agreement.version_number}</p></div>
      </header>
      <section className="identity-notice" aria-labelledby="identity-heading">
        <h2 id="identity-heading">Recipient identity</h2>
        <p>This request was issued to <strong>{agreement.recipient_email}</strong>. Production deployments require verified work-account sign-in before signing; this development deployment uses the recipient-specific secure link.</p>
      </section>
      <article className="agreement-document" aria-labelledby="document-heading">
        <div className="agreement-document-heading"><h2 id="document-heading">Document to acknowledge</h2><span>SHA-256 {agreement.document_sha256}</span></div>
        <pre>{agreement.document_content}</pre>
      </article>
      {completed ? <section className="agreement-complete" aria-labelledby="agreement-complete-heading">
        <h2 id="agreement-complete-heading">Acknowledgement recorded</h2>
        <p>Your acknowledgement of version {receipt?.signed_version ?? agreement.version_number} is complete.</p>
        <dl><div><dt>Signed</dt><dd>{new Date(receipt?.signed_at ?? agreement.acknowledged_at ?? "").toLocaleString()}</dd></div><div><dt>Document fingerprint</dt><dd>{receipt?.signed_document_sha256 ?? agreement.document_sha256}</dd></div>{receipt && <div><dt>Receipt ID</dt><dd>{receipt.acknowledgement_id}</dd></div>}</dl>
      </section> : <form className="agreement-signature" onSubmit={acknowledge} aria-describedby="signature-explanation">
        <h2>Electronic acknowledgement</h2>
        <p id="signature-explanation">Typing your name and selecting the agreement below creates an electronic record containing this exact document version, its fingerprint, the date and time, and request metadata.</p>
        <label>Full legal name<input value={signerName} onChange={(event) => setSignerName(event.target.value)} autoComplete="name" required minLength={2} maxLength={200} /></label>
        <label className="agreement-checkbox"><input type="checkbox" checked={agreed} onChange={(event) => setAgreed(event.target.checked)} required /><span>{agreement.attestation_text}</span></label>
        <button type="submit" disabled={!agreed || signing}>{signing ? "Recording…" : "Agree and sign"}</button>
        {error && <p className="error" role="alert">{error}</p>}
      </form>}
    </div>
  </main>;
}
