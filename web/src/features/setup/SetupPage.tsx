import { useState, useEffect, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { apiFetch, ApiRequestError } from "@/lib/api";
import { AuthLayout } from "@/components/AuthLayout";
import { ThemeToggle } from "@/components/ThemeToggle";

export function SetupPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [setupAvailable, setSetupAvailable] = useState(false);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [instanceName, setInstanceName] = useState("");

  useEffect(() => {
    apiFetch<{ setup_required: boolean }>("/api/setup")
      .then(() => {
        setSetupAvailable(true);
        setLoading(false);
      })
      .catch((err) => {
        if (err instanceof ApiRequestError && err.status === 404) {
          navigate("/login", { replace: true });
        } else {
          setError("Failed to check setup status.");
          setLoading(false);
        }
      });
  }, [navigate]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      const result = await apiFetch<{ redirect: string }>("/api/setup", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          confirm_password: confirmPassword,
          instance_name: instanceName,
        }),
      });
      navigate(result.redirect, { replace: true });
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred.");
      }
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-muted-foreground">Loading...</p>
      </div>
    );
  }

  if (!setupAvailable) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-destructive">{error}</p>
      </div>
    );
  }

  return (
    <AuthLayout>
      <ThemeToggle />
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">Set up Schlass</CardTitle>
          <CardDescription>
            Create the administrator account to get started.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="instance-name">Instance Name</Label>
              <Input
                id="instance-name"
                type="text"
                placeholder="My Company"
                value={instanceName}
                onChange={(e) => setInstanceName(e.target.value)}
                required
                maxLength={128}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Admin Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="admin@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={12}
              />
              <p className="text-xs text-muted-foreground">
                Minimum 12 characters, at least one uppercase letter and one
                digit.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm-password">Confirm Password</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>

            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? "Creating account..." : "Complete Setup"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
