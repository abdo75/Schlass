import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { LanguageSwitcher } from "../LanguageSwitcher";
import i18n from "@/i18n";

describe("LanguageSwitcher", () => {
  beforeEach(async () => {
    await i18n.changeLanguage("en");
  });

  it("renders three buttons EN FR DE with the current language highlighted", () => {
    render(<LanguageSwitcher />);
    expect(screen.getByRole("button", { name: "EN" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "FR" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "DE" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "EN" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("switches language on click and persists to localStorage", async () => {
    const spy = vi.spyOn(Storage.prototype, "setItem");
    render(<LanguageSwitcher />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "FR" }));
    expect(i18n.language).toBe("fr");
    expect(spy).toHaveBeenCalledWith("schlass-language", "fr");
    spy.mockRestore();
  });
});
