import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n";
import { RecoveryCodesDisplay } from "../RecoveryCodesDisplay";

describe("RecoveryCodesDisplay", () => {
  it("renders all 10 codes", () => {
    const codes = Array.from(
      { length: 10 },
      (_, i) => `AAAA-${String(i).padStart(4, "0")}`,
    );
    render(
      <I18nextProvider i18n={i18n}>
        <RecoveryCodesDisplay codes={codes} />
      </I18nextProvider>,
    );
    for (const c of codes) expect(screen.getByText(c)).toBeInTheDocument();
  });

  it("has Copy all, Download, Print actions", () => {
    const codes = ["AAAA-0000"];
    render(
      <I18nextProvider i18n={i18n}>
        <RecoveryCodesDisplay codes={codes} />
      </I18nextProvider>,
    );
    expect(
      screen.getByRole("button", { name: /copy all/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /download/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /print/i }),
    ).toBeInTheDocument();
  });

  it("renders the warning banner text", () => {
    const codes = ["AAAA-0000"];
    render(
      <I18nextProvider i18n={i18n}>
        <RecoveryCodesDisplay codes={codes} />
      </I18nextProvider>,
    );
    expect(
      screen.getByText(/save these now/i),
    ).toBeInTheDocument();
  });
});
