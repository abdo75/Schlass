import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export type PillVariant = "dashed" | "active" | "openerActive";

interface BasePillProps {
  variant: PillVariant;
  children: ReactNode;
  onClick: () => void;
  title?: string;
  ariaLabel?: string;
}

interface OpenerPillProps extends BasePillProps {
  variant: "dashed" | "openerActive";
  active: boolean;
  popoverId: string;
  popup: "dialog" | "listbox" | "menu";
}

interface ActivePillProps extends BasePillProps {
  variant: "active";
}

export type PillProps = OpenerPillProps | ActivePillProps;

export function Pill(props: PillProps) {
  const dashed = props.variant === "dashed";
  const className = cn(
    dashed
      ? "rounded-full border border-dashed border-border bg-background px-3 py-1.5 text-xs font-medium text-muted-foreground hover:border-primary/40 hover:text-foreground"
      : "inline-flex items-center gap-1 rounded-full border border-primary/30 bg-accent px-3 py-1.5 text-xs font-medium text-accent-foreground transition-colors hover:bg-accent/70",
  );
  if (props.variant === "active") {
    return (
      <button type="button" title={props.title} aria-label={props.ariaLabel} className={className} onClick={props.onClick}>
        {props.children}
      </button>
    );
  }
  return (
    <button
      type="button"
      title={props.title}
      aria-label={props.ariaLabel}
      aria-expanded={props.active}
      aria-haspopup={props.popup}
      aria-controls={props.popoverId}
      className={className}
      onClick={props.onClick}
    >
      {props.children}
    </button>
  );
}
