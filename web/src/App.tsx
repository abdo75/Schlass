import { useEffect, useState, type ReactNode } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "@/features/auth/AuthContext";
import { AuthGuard } from "@/components/AuthGuard";
import { LoginPage } from "@/features/auth/LoginPage";
import { DashboardPage } from "@/features/dashboard/DashboardPage";
import { SetupPage } from "@/features/setup/SetupPage";

// GET /api/setup returns 200 when setup is incomplete (with a body) and 404
// when setup is complete — matches the existing setup handler contract.
async function isSetupComplete(): Promise<boolean> {
  const res = await fetch("/api/setup");
  return res.status === 404;
}

// Bootstrap runs once on app mount. Checks setup state before any routing
// decision — prevents the footgun where a fresh-DB user types /admin, gets
// redirected to /login, and finds no user to log in as.
function Bootstrap({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [needsSetup, setNeedsSetup] = useState(false);

  useEffect(() => {
    let cancelled = false;
    isSetupComplete()
      .then((complete) => {
        if (!cancelled) setNeedsSetup(!complete);
      })
      .catch(() => {
        // On error, assume setup is complete and let the auth flow handle it.
        if (!cancelled) setNeedsSetup(false);
      })
      .finally(() => {
        if (!cancelled) setReady(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!ready) return null;
  if (needsSetup) return <Navigate to="/setup" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/setup" element={<SetupPage />} />
          <Route
            path="/login"
            element={
              <Bootstrap>
                <LoginPage />
              </Bootstrap>
            }
          />
          <Route
            path="/admin"
            element={
              <Bootstrap>
                <AuthGuard>
                  <DashboardPage />
                </AuthGuard>
              </Bootstrap>
            }
          />
          <Route path="/" element={<Navigate to="/admin" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
