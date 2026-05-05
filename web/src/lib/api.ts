interface ApiError {
  error: string;
  message: string;
  retry_after_seconds?: number;
}

export class ApiRequestError extends Error {
  code: string;
  status: number;
  // Populated when the backend includes retry_after_seconds in the body
  // (currently only the ACCOUNT_LOCKED response). Callers can use this to
  // render a countdown instead of a generic "try again later" message.
  retryAfterSeconds?: number;

  constructor(status: number, body: ApiError) {
    super(body.message);
    this.code = body.error;
    this.status = status;
    this.retryAfterSeconds = body.retry_after_seconds;
  }
}

export async function apiFetch<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
    },
    ...options,
  });

  if (!response.ok) {
    const body = (await response.json()) as ApiError;
    if (response.status === 401 && body.error !== "STEPUP_REQUIRED") {
      window.dispatchEvent(new CustomEvent("schlass:unauthorized"));
    }
    throw new ApiRequestError(response.status, body);
  }

  // 204 No Content has no body — return undefined cast to T (callers use T = void).
  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}
