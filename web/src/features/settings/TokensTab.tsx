import { NumberInput } from "@/components/ui/NumberInput";
import type { TokenSettings } from "./api";

interface Props {
  value: TokenSettings;
  onChange: (next: TokenSettings) => void;
  dirtyKeys: Set<keyof TokenSettings>;
}

function DirtyDot({ show }: { show: boolean }) {
  if (!show) return null;
  return (
    <span
      className="inline-block w-1.5 h-1.5 rounded-full ml-2 align-middle"
      style={{ background: "oklch(0.76 0.15 80)" }}
      aria-hidden="true"
    />
  );
}

// TokensTab — OIDC token lifetimes. Backend stores seconds; UI takes
// minutes (access, 5-60) and hours (refresh, 1-168). Conversion happens
// here so admins can think in human units. Matches V8 mockup geometry
// (single card, 2 rows, NumberInput flush-right).
export function TokensTab({ value, onChange, dirtyKeys }: Props) {
  return (
    <div className="mb-4 rounded-xl border border-border bg-background overflow-hidden">
      <div className="px-6 pt-5 pb-1">
        <h3 className="text-[15px] font-semibold">OIDC token lifetimes</h3>
        <p className="mt-1 text-[13px] text-muted-foreground leading-relaxed">
          Shortens the reach of a leaked token. Applies to all relying-party clients; per-client overrides are not supported in v1.
        </p>
      </div>
      <div className="px-6 pt-[14px] pb-5 flex flex-col gap-[14px]">
        <div className="grid grid-cols-[1fr_auto] items-center gap-5">
          <span className="text-[13.5px] font-medium">
            Access token lifetime (minutes)
            <DirtyDot show={dirtyKeys.has("access_token_ttl_secs")} />
          </span>
          <NumberInput
            value={Math.round(value.access_token_ttl_secs / 60)}
            min={5}
            max={60}
            ariaLabel="Access token lifetime (minutes)"
            onChange={(n) => onChange({ ...value, access_token_ttl_secs: n * 60 })}
          />
        </div>
        <div className="grid grid-cols-[1fr_auto] items-center gap-5">
          <span className="text-[13.5px] font-medium">
            Refresh token lifetime (hours)
            <DirtyDot show={dirtyKeys.has("refresh_token_ttl_secs")} />
          </span>
          <NumberInput
            value={Math.round(value.refresh_token_ttl_secs / 3600)}
            min={1}
            max={168}
            ariaLabel="Refresh token lifetime (hours)"
            onChange={(n) => onChange({ ...value, refresh_token_ttl_secs: n * 3600 })}
          />
        </div>
      </div>
    </div>
  );
}
