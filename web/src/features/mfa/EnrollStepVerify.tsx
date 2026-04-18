import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { verifyEnrollment } from "./api";
import { SixDigitInput } from "./SixDigitInput";

interface Props {
  onNext: (codes: string[]) => void;
}

export function EnrollStepVerify({ onNext }: Props) {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [attemptsRemaining, setAttemptsRemaining] = useState(5);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (code.length !== 6 || submitting) return;
    setSubmitting(true);
    setErrorCode(null);
    try {
      const { recovery_codes } = await verifyEnrollment(code);
      onNext(recovery_codes);
    } catch (err: unknown) {
      const ec =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setErrorCode(ec);
      setCode("");
      setAttemptsRemaining((n) => Math.max(0, n - 1));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={(e) => void handleSubmit(e)} className="flex flex-col gap-[18px]">
      <SixDigitInput value={code} onChange={setCode} autoFocus disabled={submitting} />
      <div className="text-center text-[10.5px] text-muted-foreground">
        {t("mfa.enrollment.verify_helper", { count: attemptsRemaining })}
      </div>

      {errorCode && (
        <p role="alert" className="text-sm text-destructive">
          {t(`errors.${errorCode}`)}
        </p>
      )}

      <Button
        type="submit"
        className="h-9 w-full"
        disabled={code.length !== 6 || submitting}
      >
        {submitting ? t("mfa.enrollment.verify_submitting") : t("mfa.enrollment.verify_button")}
      </Button>
    </form>
  );
}
