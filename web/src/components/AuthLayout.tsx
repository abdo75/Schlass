import type { ReactNode } from "react";

interface AuthLayoutProps {
  children: ReactNode;
}

export function AuthLayout({ children }: AuthLayoutProps) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
      <div className="mb-8 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-primary">Schlass</h1>
        <p className="text-sm text-muted-foreground">Identity Provider</p>
      </div>
      {children}
    </div>
  );
}
