import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import "./responsive-fixes.css";
import { App } from "./App";
import { PublicTrustCenter, PublicTrustData, TrustCenterUnavailable } from "./PublicTrustCenter";

function Root() {
  const trustPath = window.location.pathname === "/trust" || window.location.pathname.startsWith("/trust/");
  const slug = window.location.pathname.startsWith("/trust/") ? window.location.pathname.slice(7).split("/")[0] : "";
  const [state, setState] = useState<{ checked: boolean; data: PublicTrustData | null }>({ checked: false, data: null });
  useEffect(() => {
    const query = slug ? `?slug=${encodeURIComponent(slug)}` : "";
    void fetch(`/v1/public/trust${query}`).then(async (response) => {
      setState({ checked: true, data: response.ok ? await response.json() as PublicTrustData : null });
    }).catch(() => setState({ checked: true, data: null }));
  }, [slug]);
  if (!state.checked) return <main className="bootstrap-loading"><p>Loading…</p></main>;
  if (state.data) return <PublicTrustCenter data={state.data} />;
  if (trustPath) return <TrustCenterUnavailable />;
  return <App />;
}

createRoot(document.getElementById("root")!).render(<StrictMode><Root /></StrictMode>);
