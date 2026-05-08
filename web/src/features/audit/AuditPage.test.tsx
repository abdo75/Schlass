import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditPage } from "./AuditPage";
import { fakeEvent } from "./test-helpers";

vi.mock("@/components/AdminLayout", () => ({
  AdminPageHeader: ({ primaryAction }: { primaryAction?: React.ReactNode }) => <div>{primaryAction}</div>,
  AdminPageContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

afterEach(() => {
  vi.restoreAllMocks();
});

function mockListResponse(items: ReturnType<typeof fakeEvent>[]) {
  vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    if (url.startsWith("/api/audit?")) {
      return Promise.resolve(
        new Response(JSON.stringify({ items, total: items.length, page: 1, page_size: 25 }), { status: 200 }),
      );
    }
    return Promise.resolve(new Response("not mocked", { status: 404 }));
  });
}

describe("AuditPage deep link", () => {
  it("opens the panel for ?event=<id> once the list arrives", async () => {
    const target = fakeEvent({ id: "evt-deep", event_type: "login.succeeded" });
    mockListResponse([fakeEvent({ id: "evt-other" }), target]);

    render(
      <MemoryRouter initialEntries={["/admin/audit?event=evt-deep"]}>
        <Routes>
          <Route path="/admin/audit" element={<AuditPage />} />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: /event detail/i })).toBeVisible(),
    );
  });
});
