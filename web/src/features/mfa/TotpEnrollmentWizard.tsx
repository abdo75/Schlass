import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/features/auth/AuthContext";
import { AuthLayout } from "@/components/AuthLayout";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EnrollStepScan } from "./EnrollStepScan";
import { EnrollStepVerify } from "./EnrollStepVerify";
import { EnrollStepRecoveryCodes } from "./EnrollStepRecoveryCodes";
import type { EnrollmentStartResponse } from "./api";

type Step = 1 | 2 | 3;

interface StepperProps {
  current: Step;
}

function Stepper({ current }: StepperProps) {
  const { t } = useTranslation();
  const steps: { n: Step; labelKey: string }[] = [
    { n: 1, labelKey: "mfa.enrollment.step1_label" },
    { n: 2, labelKey: "mfa.enrollment.step2_label" },
    { n: 3, labelKey: "mfa.enrollment.step3_label" },
  ];

  return (
    <div className="relative flex items-start justify-between pt-1">
      {/* background line */}
      <div className="absolute left-[14%] right-[14%] top-[13px] h-[2px] bg-muted" />
      {/* filled line — extends to current step */}
      <div
        className="absolute left-[14%] top-[13px] h-[2px] bg-primary transition-[width]"
        style={{ width: `${((current - 1) / 2) * 72}%` }}
      />

      {steps.map(({ n, labelKey }) => {
        const isActive = current === n;
        const isComplete = current > n;
        const isFuture = current < n;
        return (
          <div key={n} className="relative z-10 flex flex-1 flex-col items-center gap-1.5">
            <div
              className={
                "flex h-[26px] w-[26px] items-center justify-center rounded-full text-[12px] font-semibold " +
                (isFuture
                  ? "border-[1.5px] border-border bg-background text-muted-foreground"
                  : "bg-primary text-primary-foreground")
              }
            >
              {isComplete ? (
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              ) : (
                n
              )}
            </div>
            <div
              className={
                "text-[10.5px] " +
                (isActive ? "font-semibold text-foreground" : isFuture ? "text-muted-foreground" : "text-foreground/80")
              }
            >
              {t(labelKey)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function TotpEnrollmentWizard() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { refreshUser } = useAuth();
  const [step, setStep] = useState<Step>(1);
  const [enrollment, setEnrollment] = useState<EnrollmentStartResponse | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  const titleKey = `mfa.enrollment.step${step}_title`;
  const descKey = `mfa.enrollment.step${step}_description`;

  return (
    <AuthLayout>
      <Card className="w-full overflow-hidden border-border">
        <CardHeader className="gap-0 border-b border-border px-[22px] pb-[14px] pt-[20px]">
          <CardTitle className="text-[18px] font-semibold leading-tight tracking-tight">{t(titleKey)}</CardTitle>
          <CardDescription className="mt-[2px] text-[12px] leading-[1.5]">{t(descKey)}</CardDescription>
          <div className="mt-[14px]">
            <Stepper current={step} />
          </div>
        </CardHeader>
        <CardContent className="px-[22px] pb-[20px] pt-[18px]">
          {step === 1 && (
            <EnrollStepScan
              onNext={(data) => {
                setEnrollment(data);
                setStep(2);
              }}
            />
          )}
          {step === 2 && enrollment && (
            <EnrollStepVerify onNext={(codes) => { setRecoveryCodes(codes); setStep(3); }} />
          )}
          {step === 3 && (
            <EnrollStepRecoveryCodes
              codes={recoveryCodes}
              onComplete={async () => {
                // The enrollment-complete endpoint issued a session cookie.
                // Refresh AuthContext so AuthGuard on destination routes sees
                // the user. Navigate based on role so super_admin lands at
                // /admin and regular users land at /account.
                const u = await refreshUser();
                const dest = u?.role === "super_admin" ? "/admin" : "/account";
                void navigate(dest, { replace: true });
              }}
            />
          )}
        </CardContent>
      </Card>
    </AuthLayout>
  );
}

