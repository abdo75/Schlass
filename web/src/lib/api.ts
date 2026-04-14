interface ApiError {
  error: string;
  message: string;
}

export class ApiRequestError extends Error {
  code: string;
  status: number;

  constructor(status: number, body: ApiError) {
    super(body.message);
    this.code = body.error;
    this.status = status;
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
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent("schlass:unauthorized"));
    }
    const body = (await response.json()) as ApiError;
    throw new ApiRequestError(response.status, body);
  }

  // 204 No Content has no body — return undefined cast to T (callers use T = void).
  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}
