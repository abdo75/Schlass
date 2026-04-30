import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ChangedValuesList, ChangedValuesScalar, ReasonCard } from "./AuditPanelModules";
import { fakeEvent } from "./test-helpers";

describe("AuditPanelModules", () => {
  it("scalar diff renders old and new plus hint", () => {
    render(<ChangedValuesScalar event={fakeEvent({ event_type: "config.access_token_ttl_secs.changed", metadata: { from: 900, to: 600 } })} />);
    expect(screen.getByText("900")).toBeVisible();
    expect(screen.getByText("600")).toBeVisible();
    expect(screen.getByText(/access tokens now expire sooner/i)).toBeVisible();
  });

  it("list diff distinguishes added vs removed", () => {
    render(<ChangedValuesList event={fakeEvent({ event_type: "client.redirect_uris_updated", metadata: { from: ["https://a"], to: ["https://a", "https://b"] } })} />);
    expect(screen.getByText("https://b")).toHaveClass("added");
  });

  it("reason card falls back gracefully on unknown reason", () => {
    render(<ReasonCard result={{ key: null, raw: "wat", fallback: true }} />);
    expect(screen.getByText("Not yet documented")).toBeVisible();
    expect(screen.getByText(/wat/i)).toBeVisible();
  });
});
