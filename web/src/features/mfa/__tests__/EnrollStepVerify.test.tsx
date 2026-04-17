import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { I18nextProvider } from "react-i18next";
import i18n from "@/i18n";
import { EnrollStepVerify } from "../EnrollStepVerify";

const verifyMock = vi.fn(
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  (_code: string): Promise<{ recovery_codes: string[] }> =>
    Promise.resolve({ recovery_codes: [] }),
);
vi.mock("../api", () => ({
  verifyEnrollment: (code: string) => verifyMock(code),
}));

describe("EnrollStepVerify", () => {
  beforeEach(() => {
    verifyMock.mockReset();
  });

  it("renders 6 digit boxes", () => {
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepVerify onNext={() => {}} />
      </I18nextProvider>,
    );
    const inputs = screen.getAllByLabelText(/digit/i);
    expect(inputs).toHaveLength(6);
  });

  it("verify button disabled until 6 digits entered", () => {
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepVerify onNext={() => {}} />
      </I18nextProvider>,
    );
    const button = screen.getByRole("button", { name: /verify/i });
    expect(button).toBeDisabled();
  });

  it("calls verifyEnrollment and onNext with recovery codes on success", async () => {
    verifyMock.mockResolvedValue({ recovery_codes: ["AAAA-AAAA", "BBBB-BBBB"] });
    const onNext = vi.fn();
    render(
      <I18nextProvider i18n={i18n}>
        <EnrollStepVerify onNext={onNext} />
      </I18nextProvider>,
    );
    const inputs = screen.getAllByLabelText(/digit/i);
    const digits = "123456".split("");
    digits.forEach((d, i) => fireEvent.change(inputs[i], { target: { value: d } }));
    fireEvent.click(screen.getByRole("button", { name: /verify/i }));
    await waitFor(() => expect(onNext).toHaveBeenCalledWith(["AAAA-AAAA", "BBBB-BBBB"]));
    expect(verifyMock).toHaveBeenCalledWith("123456");
  });
});
