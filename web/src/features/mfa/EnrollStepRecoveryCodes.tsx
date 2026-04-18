import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { completeEnrollment } from "./api";
import { RecoveryCodesDisplay } from "./RecoveryCodesDisplay";

interface Props {
  codes: string[];
  onComplete: () => void | Promise<void>;
}

export function EnrollStepRecoveryCodes({ codes, onComplete }: Props) {
  const { t } = useTranslation();
  const [ack, setAck] = useState(false);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleFinish = async () => {
    if (!ack || submitting) return;
    setSubmitting(true);
    setErrorCode(null);
    try {
      await completeEnrollment();
      await onComplete();
    } catch (err: unknown) {
      const ec =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setErrorCode(ec);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex flex-col gap-[18px]">
      <RecoveryCodesDisplay codes={codes} />

      <label className="flex cursor-pointer items-start gap-[7px] text-[12px] leading-[1.4]">
        <input
          type="checkbox"
          checked={ack}
          onChange={(e) => setAck(e.target.checked)}
          className="mt-[1px] h-[15px] w-[15px] accent-primary"
        />
        <span>{t("mfa.enrollment.acknowledgement")}</span>
      </label>

      {errorCode && (
        <p role="alert" className="text-sm text-destructive">
          {t(`errors.${errorCode}`)}
        </p>
      )}

      <Button
        type="button"
        className="h-9 w-full"
        disabled={!ack || submitting}
        onClick={() => void handleFinish()}
      >
        {submitting
          ? t("mfa.enrollment.finish_submitting")
          : t("mfa.enrollment.finish_button")}
      </Button>
    </div>
  );
}
