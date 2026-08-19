import { cleanup, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import userEvent from "@testing-library/user-event";
import { axe } from "jest-axe";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";


const dashboard = {
  organization: { id: "organization-a", name: "Test Public Safety" },
  identity: { actor_id: "actor-a", role: "msp_admin" },
  assessments: [
    {
      id: "assessment-a",
      name: "CJIS assessment",
      status: "active",
      updated_at: "2026-08-19T12:00:00Z",
    },
  ],
  evidence: [],
  integrations: [],
  endpoints: [],
  audit: [],
};

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body,
  } as Response;
}

describe("Watchtower accessibility baseline", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
    window.localStorage.clear();
    vi.restoreAllMocks();
  });

  afterEach(() => cleanup());

  it("has no detectable axe violations on the connection screen", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);

    const skipLink = screen.getByRole("link", { name: "Skip to main content" });
    expect(skipLink).toHaveProperty(
      "hash",
      "#main-content",
    );
    expect(screen.getByRole("main")).toHaveAttribute("id", "main-content");
    await user.click(skipLink);
    expect(screen.getByRole("main")).toHaveFocus();
    expect(screen.getByLabelText("Organization ID")).toBeRequired();
    expect(screen.getByLabelText("Actor ID")).toBeRequired();
    expect((await axe(container)).violations).toEqual([]);
  });

  it("keeps the authenticated dashboard named, operable, and announced", async () => {
    window.localStorage.setItem("watchtower.organization", "organization-a");
    window.localStorage.setItem("watchtower.actor", "actor-a");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = input.toString();
      if (url.endsWith("/v1/dashboard")) return jsonResponse(dashboard);
      if (url.endsWith("/v1/me/organizations")) return jsonResponse([
        { id: "organization-a", name: "Test Public Safety", slug: "test-public-safety", role: "msp_admin" },
        { id: "organization-b", name: "Second Customer", slug: "second-customer", role: "msp_admin" },
      ]);
      if (url.endsWith("/v1/access/roles")) return jsonResponse([
        { id: "customer_admin", name: "Customer administrator", description: "Tenant administration", permissions: ["manage_client_access"] },
        { id: "control_owner", name: "Control owner", description: "Compliance work", permissions: ["submit_evidence"] },
        { id: "auditor", name: "External auditor", description: "Read-only tenant access", permissions: ["read_evidence"] },
      ]);
      if (url.endsWith("/v1/invitations/external-auditor") && init?.method === "POST") return jsonResponse({
        id: "invitation-a",
        email: "client@example.gov",
        display_name: "Client Person",
        role: "auditor",
        status: "pending",
        expires_at: "2026-08-26T12:00:00Z",
        created_at: "2026-08-19T12:00:00Z",
        accepted_at: null,
        revoked_at: null,
        token: "invitation-a.secret",
      });
      if (url.endsWith("/v1/invitations")) return jsonResponse([]);
      if (init?.method === "PUT") return jsonResponse({ theme: "dark" });
      return jsonResponse({ theme: "light" });
    });
    const user = userEvent.setup();
    const { container } = render(<App />);

    await screen.findByText("Test Public Safety");
    const tenantSelector = await screen.findByLabelText("Current tenant");
    expect(tenantSelector).toHaveValue("organization-a");
    await user.selectOptions(tenantSelector, "organization-b");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/v1/dashboard",
      expect.objectContaining({
        headers: expect.objectContaining({ "X-Watchtower-Organization": "organization-b" }),
      }),
    ));
    expect(screen.getByRole("table", { name: "Recent compliance assessments" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Overview" })).toHaveAttribute(
      "aria-current",
      "page",
    );

    const themeToggle = screen.getByRole("button", { name: "Dark mode" });
    expect(themeToggle).toHaveAttribute("aria-pressed", "false");
    await user.click(themeToggle);
    expect(themeToggle).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("status")).toHaveTextContent("Dark mode saved to your profile.");
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");

    await user.click(screen.getByRole("button", { name: "Collapse navigation" }));
    expect(screen.getByRole("button", { name: "Expand navigation" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/v1/profile/preferences",
      expect.objectContaining({ method: "PUT" }),
    ));

    await user.click(screen.getByRole("button", { name: "Customers" }));
    await screen.findByRole("heading", { name: "Invite client personnel or an external auditor" });
    expect(screen.getByLabelText("Email address")).toHaveAttribute("type", "email");
    expect(screen.getByLabelText("Access profile")).toBeVisible();
    await user.selectOptions(screen.getByLabelText("Access profile"), "auditor");
    expect(screen.getByText(/one identity while keeping each tenant membership separate/i)).toBeVisible();
    await user.type(screen.getByLabelText("Email address"), "client@example.gov");
    await user.click(screen.getByRole("button", { name: "Create invitation" }));
    expect((await screen.findByLabelText("Tenant acceptance link") as HTMLInputElement).value).toContain("#invite=");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/v1/invitations/external-auditor",
      expect.objectContaining({ method: "POST" }),
    ));
    expect((await axe(container)).violations).toEqual([]);
  });

  it("gives a multi-tenant auditor a read-only tenant switcher", async () => {
    window.localStorage.setItem("watchtower.organization", "organization-a");
    window.localStorage.setItem("watchtower.actor", "auditor-a");
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = input.toString();
      if (url.endsWith("/v1/dashboard")) return jsonResponse({
        ...dashboard,
        identity: { actor_id: "auditor-a", role: "auditor" },
        integrations: [],
        endpoints: [],
      });
      if (url.endsWith("/v1/me/organizations")) return jsonResponse([
        { id: "organization-a", name: "Test Public Safety", slug: "test-public-safety", role: "auditor" },
        { id: "organization-b", name: "Second Customer", slug: "second-customer", role: "auditor" },
      ]);
      if (url.endsWith("/v1/policies/reference-options")) return jsonResponse({ controls: [], evidence: [] });
      if (url.endsWith("/v1/policies")) return jsonResponse([]);
      return jsonResponse({ theme: "light" });
    });
    const { container } = render(<App />);

    expect(await screen.findByLabelText("Current tenant")).toHaveValue("organization-a");
    expect(screen.getByRole("button", { name: "View evidence" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Customers" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Integrations" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Endpoints" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Policies" })).toBeVisible();
    expect(screen.queryByRole("heading", { name: "Integration health" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Recent audit activity" })).toBeVisible();
    expect((await axe(container)).violations).toEqual([]);
  });

  it("creates an accessible controlled document with compliance links", async () => {
    window.localStorage.setItem("watchtower.organization", "organization-a");
    window.localStorage.setItem("watchtower.actor", "actor-a");
    const createdPolicy = {
      id: "policy-a",
      title: "Incident Response Policy",
      document_type: "policy",
      status: "draft",
      owner_display_name: "Security Officer",
      review_due_at: "2027-08-19",
      current_version: 1,
      control_count: 1,
      evidence_count: 1,
      updated_at: "2026-08-19T12:00:00Z",
      versions: [{ id: "version-a", version_number: 1, content: "Purpose and scope", change_summary: "Initial version", created_at: "2026-08-19T12:00:00Z" }],
      controls: [{ framework_pack_version_id: 1, framework: "CJIS 2024", control_reference: "CJIS-5.10.1", control_title: "Incident response" }],
      evidence: [{ evidence_id: "evidence-a", evidence_title: "Approved response plan", relationship: "supports", notes: null }],
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = input.toString();
      if (url.endsWith("/v1/dashboard")) return jsonResponse(dashboard);
      if (url.endsWith("/v1/me/organizations")) return jsonResponse([{ id: "organization-a", name: "Test Public Safety", slug: "test-public-safety", role: "msp_admin" }]);
      if (url.endsWith("/v1/policies/reference-options")) return jsonResponse({
        controls: [{ framework_pack_version_id: 1, framework: "CJIS 2024", reference: "CJIS-5.10.1", title: "Incident response" }],
        evidence: [{ id: "evidence-a", title: "Approved response plan", assessment_name: "CJIS assessment", sensitivity: "confidential" }],
      });
      if (url.endsWith("/v1/policies/agreement-cadence-suggestions")) return jsonResponse([{
        key: "cjis-annual",
        label: "Annual CJIS-aligned review",
        recurrence_days: 365,
        prompt_before_days: 30,
        rationale: "Align acknowledgement review with annual CJIS training.",
        source_label: "FBI CJIS Security Policy 6.1, AT-2",
        source_url: "https://le.fbi.gov/file-repository/cjis_security_policy_v6-1_20260625.pdf/view",
        qualification: "Training cadence does not make every signature annual.",
      }]);
      if (url.endsWith("/v1/policies") && init?.method === "POST") return jsonResponse(createdPolicy);
      if (url.endsWith("/v1/policies")) return jsonResponse([]);
      return jsonResponse({ theme: "light" });
    });
    const user = userEvent.setup();
    const { container } = render(<App />);

    await screen.findByText("Test Public Safety");
    await user.click(screen.getByRole("button", { name: "Policies" }));
    await screen.findByRole("heading", { name: "Create a controlled document" });
    await user.type(screen.getByLabelText("Title"), "Incident Response Policy");
    await user.type(screen.getByLabelText("Owner Optional"), "Security Officer");
    await user.type(screen.getByLabelText("Document body"), "Purpose and scope");
    await user.click(screen.getByRole("checkbox", { name: /CJIS-5.10.1/ }));
    await user.click(screen.getByRole("checkbox", { name: /Approved response plan/ }));
    await user.click(screen.getByRole("button", { name: "Create draft" }));

    expect(await screen.findByRole("heading", { name: "Incident Response Policy" })).toBeVisible();
    expect(screen.getAllByText("CJIS-5.10.1")).toHaveLength(2);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/v1/policies",
      expect.objectContaining({ method: "POST" }),
    ));
    expect((await axe(container)).violations).toEqual([]);
  });

  it("keeps the one-time invitation acceptance screen labeled and operable", async () => {
    window.history.replaceState({}, "", "/#invite=invitation-id.secret-value-that-is-long-enough");
    const { container } = render(<App />);

    expect(screen.getByRole("heading", { name: "Accept client access" })).toBeVisible();
    expect(screen.getByLabelText("Display name")).toHaveAttribute("autocomplete", "name");
    expect(screen.getByRole("button", { name: "Accept invitation" })).toBeEnabled();
    expect((await axe(container)).violations).toEqual([]);
  });

  it("keeps recipient policy acknowledgement explicit, versioned, and accessible", async () => {
    window.history.replaceState({}, "", "/#agreement=request-id.secret-value-that-is-long-enough");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = input.toString();
      if (url.endsWith("/v1/policy-agreements:inspect")) return jsonResponse({
        request_id: "request-id",
        organization_name: "Test Public Safety",
        document_title: "Acceptable Use Policy",
        document_type: "policy",
        version_number: 3,
        document_content: "Use agency systems only for authorized work.",
        document_sha256: "8d7f5ab6b0aa247ab619156446926119ea618a6d00f0c7f173348b121527fa45",
        recipient_email: "officer@example.gov",
        recipient_display_name: "Alex Officer",
        attestation_text: "I have read this document and agree to follow its requirements.",
        agreement_status: "pending",
        expires_at: "2026-08-26T12:00:00Z",
        acknowledged_at: null,
      });
      if (url.endsWith("/v1/policy-agreements:acknowledge") && init?.method === "POST") return jsonResponse({
        acknowledgement_id: "receipt-id",
        signed_at: "2026-08-19T12:00:00Z",
        signed_document_sha256: "8d7f5ab6b0aa247ab619156446926119ea618a6d00f0c7f173348b121527fa45",
        signed_version: 3,
      });
      throw new Error(`Unexpected request: ${url}`);
    });
    const user = userEvent.setup();
    const { container } = render(<App />);

    expect(await screen.findByRole("heading", { name: "Acceptable Use Policy" })).toBeVisible();
    expect(screen.getByText("officer@example.gov")).toBeVisible();
    expect(screen.getByRole("heading", { name: "Document to acknowledge" })).toBeVisible();
    expect(screen.getByLabelText("Full legal name")).toHaveValue("Alex Officer");
    const attestation = screen.getByRole("checkbox", { name: /I have read this document/ });
    const signButton = screen.getByRole("button", { name: "Agree and sign" });
    expect(signButton).toBeDisabled();
    await user.click(attestation);
    expect(signButton).toBeEnabled();
    await user.click(signButton);

    expect(await screen.findByRole("heading", { name: "Acknowledgement recorded" })).toBeVisible();
    expect(screen.getByText("receipt-id")).toBeVisible();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/v1/policy-agreements:acknowledge",
      expect.objectContaining({ method: "POST" }),
    ));
    expect((await axe(container)).violations).toEqual([]);
  });
});
