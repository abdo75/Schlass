import { useCallback, useEffect, useMemo, useState } from "react";
import type { AuditState, ListResponse } from "./types";
import { stateToParams } from "./useUrlState";

type Result = { data: ListResponse | null; error: Error | null; key: string; nonce: number };

const INITIAL: Result = { data: null, error: null, key: "", nonce: 0 };

function isListResponse(body: unknown): body is ListResponse {
  if (!body || typeof body !== "object") return false;
  const candidate = body as { items?: unknown; total?: unknown };
  return Array.isArray(candidate.items) && typeof candidate.total === "number";
}

export function useAuditList(state: AuditState) {
  const query = useMemo(() => stateToParams(state).toString(), [state]);
  const [nonce, setNonce] = useState(0);
  const [result, setResult] = useState<Result>(INITIAL);
  const fingerprint = `${nonce}|${query}`;

  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/audit?${query}`, { signal: controller.signal })
      .then((res) => {
        if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
        return res.json();
      })
      .then((body: unknown) => {
        if (!isListResponse(body)) throw new Error("invalid audit response shape");
        setResult({ data: body, error: null, key: fingerprint, nonce });
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        if (err instanceof Error && err.name === "AbortError") return;
        const wrapped = err instanceof Error ? err : new Error(String(err));
        setResult({ data: null, error: wrapped, key: fingerprint, nonce });
      });
    return () => controller.abort();
  }, [query, nonce, fingerprint]);

  const retry = useCallback(() => setNonce((n) => n + 1), []);
  const matches = result.key === fingerprint;
  return {
    data: matches ? result.data : null,
    error: matches ? result.error : null,
    loading: !matches,
    retry,
  };
}
