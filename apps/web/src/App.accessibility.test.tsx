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
      if (url.endsWith("/v1/access/roles")) return jsonResponse([
        { id: "customer_admin", name: "Customer administrator", description: "Tenant administration", permissions: ["manage_client_access"] },
        { id: "control_owner", name: "Control owner", description: "Compliance work", permissions: ["submit_evidence"] },
      ]);
      if (url.endsWith("/v1/invitations") && init?.method === "POST") return jsonResponse({
        id: "invitation-a",
        email: "client@example.gov",
        display_name: "Client Person",
        role: "control_owner",
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
    await screen.findByRole("heading", { name: "Invite client personnel" });
    expect(screen.getByLabelText("Email address")).toHaveAttribute("type", "email");
    expect(screen.getByLabelText("Access profile")).toBeVisible();
    await user.type(screen.getByLabelText("Email address"), "client@example.gov");
    await user.click(screen.getByRole("button", { name: "Create invitation" }));
    expect((await screen.findByLabelText("Client acceptance link") as HTMLInputElement).value).toContain("#invite=");
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
});
