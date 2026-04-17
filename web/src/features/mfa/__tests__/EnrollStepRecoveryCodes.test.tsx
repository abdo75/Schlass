import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n";
import { EnrollStepRecoveryCodes } from "../EnrollStepRecoveryCodes";

const completeMock = vi.fn();
vi.mock("../api", () => ({
  completeEnrollment: (): Promise<void> => completeMock() as Promise<void>,
}));

describe("EnrollStepRecoveryCodes", () => {
  it("finish button disabled until checkbox ticked", () => {
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepRecoveryCodes codes={["A-A"]} onComplete={() => {}} />
      </I18nextProvider>,
    );
    const button = screen.getByRole("button", { name: /finish/i });
    expect(button).toBeDisabled();
    const checkbox = screen.getByRole("checkbox");
    fireEvent.click(checkbox);
    expect(button).toBeEnabled();
  });

  it("calls completeEnrollment and onComplete on finish", async () => {
    completeMock.mockResolvedValue(undefined);
    const onComplete = vi.fn();
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepRecoveryCodes codes={["A-A"]} onComplete={onComplete} />
      </I18nextProvider>,
    );
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: /finish/i }));
    await waitFor(() => expect(onComplete).toHaveBeenCalled());
    expect(completeMock).toHaveBeenCalled();
  });
});
