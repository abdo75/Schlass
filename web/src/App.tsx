import { useEffect, useState, type ReactNode } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/features/auth/AuthContext";
import { AuthGuard } from "@/components/AuthGuard";
import { AdminGuard } from "@/components/AdminGuard";
import { AdminLayout } from "@/components/AdminLayout";
import { LoginPage } from "@/features/auth/LoginPage";
import { ChangePasswordPage } from "@/features/auth/ChangePasswordPage";
import { TotpEnrollmentWizard } from "@/features/mfa/TotpEnrollmentWizard";
import { TotpChallengePage } from "@/features/mfa/TotpChallengePage";
import { SetupPage } from "@/features/setup/SetupPage";
import { UsersPage } from "@/features/users/UsersPage";
import { UserCreatePage } from "@/features/users/UserCreatePage";
import { UserDetailPage } from "@/features/users/UserDetailPage";
import { UserAccountPage } from "@/features/account/UserAccountPage";
import { AuthorizeErrorPage } from "@/features/oidc/AuthorizeErrorPage";
import { DevCallbackPage } from "@/features/oidc/DevCallbackPage";
import { ClientsPage } from "@/features/clients/ClientsPage";
import { ClientCreatePage } from "@/features/clients/ClientCreatePage";
import { ClientDetailPage } from "@/features/clients/ClientDetailPage";
import { SigningKeysPage } from "@/features/clients/SigningKeysPage";

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

// Role-aware root redirect: admins land at /admin, everyone else at
// /account. Uses useAuth so it automatically respects auth loading state.
function RootRedirect() {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return user.role === "super_admin"
    ? <Navigate to="/admin" replace />
    : <Navigate to="/account" replace />;
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
          {/* /mfa-challenge is public — the server-side challenge cookie is the
              real gate. A missing cookie manifests as a 401 on submit and
              bounces the user back to /login. */}
          <Route path="/mfa-challenge" element={<TotpChallengePage />} />
          {/* /change-password and /setup-mfa intentionally skip Bootstrap: AuthGuard
              redirects force-password-change and force-mfa-enrollment users here
              respectively, and Bootstrap would race those redirects with its own
              /setup check. */}
          <Route
            path="/change-password"
            element={
              <AuthGuard>
                <ChangePasswordPage />
              </AuthGuard>
            }
          />
          {/* /setup-mfa has two entry points:
              (a) login returns 202 + schlass_mfa_enroll cookie (no session yet)
              (b) AuthGuard redirects a user with force_mfa_enrollment=true (existing session)
              AuthGuard cannot gate this route because case (a) has no session.
              TotpEnrollmentWizard handles the 401 path itself — if the enrollment
              cookie has expired, /api/mfa/enrollment/start returns MFA_ENROLLMENT_EXPIRED
              and the wizard surfaces the error and lets the user return to /login. */}
          <Route
            path="/setup-mfa"
            element={<TotpEnrollmentWizard />}
          />
          {/* /oidc/error is public — rendered when /authorize can't safely bounce back
              to the RP (untrusted client_id or redirect_uri). Shows generic message
              plus opaque error reference with copy button. */}
          <Route
            path="/oidc/error"
            element={<AuthorizeErrorPage />}
          />
          {/* /oidc/dev-callback — the redirect URI registered by the dev-seed
              OIDC client. Production RPs own their own callback servers; this
              route exists so a human running through the authorize flow
              locally can see the returned code + state and optionally trigger
              a /token exchange from the browser. Unauthenticated — the page
              is a display-only helper. */}
          <Route
            path="/oidc/dev-callback"
            element={<DevCallbackPage />}
          />
          <Route
            path="/account"
            element={
              <AuthGuard>
                <UserAccountPage />
              </AuthGuard>
            }
          />
          <Route
            path="/admin"
            element={
              <Bootstrap>
                <AuthGuard>
                  <AdminGuard>
                    <AdminLayout />
                  </AdminGuard>
                </AuthGuard>
              </Bootstrap>
            }
          >
            <Route index element={<Navigate to="/admin/users" replace />} />
            <Route path="users" element={<UsersPage />} />
            <Route path="users/new" element={<UserCreatePage />} />
            <Route path="users/:id" element={<UserDetailPage />} />
            <Route path="clients" element={<ClientsPage />} />
            <Route path="clients/new" element={<ClientCreatePage />} />
            <Route path="clients/:id" element={<ClientDetailPage />} />
            <Route path="signing-keys" element={<SigningKeysPage />} />
          </Route>
          <Route path="/" element={<Bootstrap><RootRedirect /></Bootstrap>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
