type PublicResource = {
  id: string;
  title: string;
  summary: string;
  category: string;
  document_type: string;
  version: number;
  published_at: string;
};

export type PublicTrustData = {
  organization_slug: string;
  display_name: string;
  headline: string;
  overview: string;
  security_contact_email: string | null;
  primary_color: string;
  updated_at: string;
  resources: PublicResource[];
};

export function PublicTrustCenter({ data }: { data: PublicTrustData }) {
  return <main className="public-trust" style={{ "--trust-accent": data.primary_color } as React.CSSProperties}>
    <a className="skip-link" href="#trust-content">Skip to trust center content</a>
    <header className="public-trust-header">
      <div className="public-trust-mark" aria-hidden="true">{data.display_name.slice(0, 1).toUpperCase()}</div>
      <div><span>Security &amp; Trust Center</span><strong>{data.display_name}</strong></div>
      {data.security_contact_email && <a href={`mailto:${data.security_contact_email}`}>Contact security</a>}
    </header>
    <div id="trust-content" className="public-trust-content" tabIndex={-1}>
      <section className="public-trust-hero" aria-labelledby="trust-heading">
        <p className="eyebrow">Transparency by design</p>
        <h1 id="trust-heading">{data.headline}</h1>
        <p>{data.overview}</p>
      </section>
      <section className="public-trust-assurance" aria-labelledby="assurance-heading">
        <div><p className="eyebrow">Published assurance</p><h2 id="assurance-heading">Security documentation</h2></div>
        <p>These summaries are intentionally public. Sensitive implementation details and evidence remain access-controlled.</p>
        {data.resources.length ? <div className="public-resource-grid">{data.resources.map((resource) => <article key={resource.id}>
          <div><span className="public-resource-category">{resource.category}</span><span>{resource.document_type} · v{resource.version}</span></div>
          <h3>{resource.title}</h3>
          <p>{resource.summary}</p>
          <small>Published <time dateTime={resource.published_at}>{new Date(resource.published_at).toLocaleDateString()}</time></small>
        </article>)}</div> : <p className="public-trust-empty">No public assurance summaries have been posted yet.</p>}
      </section>
    </div>
    <footer className="public-trust-footer"><span>{data.display_name}</span><span>Last reviewed <time dateTime={data.updated_at}>{new Date(data.updated_at).toLocaleDateString()}</time></span></footer>
  </main>;
}

export function TrustCenterUnavailable() {
  return <main className="public-trust public-trust-unavailable"><section><p className="eyebrow">Trust Center</p><h1>Trust center unavailable</h1><p>This address does not have a published trust center.</p></section></main>;
}
