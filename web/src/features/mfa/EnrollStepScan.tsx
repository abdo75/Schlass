import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { QRCodeSVG } from "qrcode.react";
import { Button } from "@/components/ui/button";
import { startEnrollment, type EnrollmentStartResponse } from "./api";

interface Props {
  onNext: (data: EnrollmentStartResponse) => void;
}

export function EnrollStepScan({ onNext }: Props) {
  const { t } = useTranslation();
  const [data, setData] = useState<EnrollmentStartResponse | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [showSecret, setShowSecret] = useState(false);

  useEffect(() => {
    let cancelled = false;
    startEnrollment()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const code =
          err && typeof err === "object" && "code" in err
            ? String((err as { code: unknown }).code)
            : "INTERNAL_ERROR";
        setErrorCode(code);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (errorCode) {
    return <p role="alert" className="text-sm text-destructive">{t(`errors.${errorCode}`)}</p>;
  }
  if (!data) {
    return <p className="text-[12px] text-muted-foreground">{t("common.loading")}</p>;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-center">
        <div className="flex h-[160px] w-[160px] items-center justify-center rounded-md border border-border bg-white p-2">
          <QRCodeSVG value={data.provision_uri} size={140} />
        </div>
      </div>

      <button
        type="button"
        className="text-center text-[11.5px] text-primary underline underline-offset-2"
        onClick={() => setShowSecret((v) => !v)}
      >
        {showSecret ? t("mfa.enrollment.hide_manual_secret") : t("mfa.enrollment.cannot_scan_link")}
      </button>

      {showSecret && (
        <div className="rounded-md bg-muted px-3 py-2 text-center font-mono text-[12px] tracking-[0.1em] text-foreground">
          {data.secret_base32}
        </div>
      )}

      <Button type="button" className="mt-1 h-9 w-full" onClick={() => onNext(data)}>
        {t("mfa.enrollment.next_button")}
      </Button>
    </div>
  );
}
