import { useEffect, useMemo, useState } from "react";
import type { AuditState, ListResponse } from "./types";
import { stateToParams } from "./useUrlState";

type Result = { data: ListResponse | null; error: Error | null; key: string };

const INITIAL: Result = { data: null, error: null, key: "" };

export function useAuditList(state: AuditState) {
  const query = useMemo(() => stateToParams(state).toString(), [state]);
  const [result, setResult] = useState<Result>(INITIAL);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/audit?${query}`, { signal: controller.signal })
      .then((res) => {
        if (!res.ok) throw new Error("fetch failed");
        return res.json() as Promise<ListResponse>;
      })
      .then((data) => setResult({ data, error: null, key: query }))
      .catch((err: Error) => {
        if (err.name !== "AbortError") setResult({ data: null, error: err, key: query });
      });
    return () => controller.abort();
  }, [query]);

  return {
    data: result.key === query ? result.data : null,
    error: result.key === query ? result.error : null,
    loading: result.key !== query,
  };
}
