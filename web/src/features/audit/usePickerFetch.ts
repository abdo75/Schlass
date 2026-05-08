import { useCallback, useEffect, useMemo, useState } from "react";

type State<T> = { data: T | null; loading: boolean; error: Error | null; key: string };

export interface PickerFetchResult<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
  retry: () => void;
}

interface Options<T> {
  skip?: boolean;
  validate?: (body: unknown) => body is T;
}

export function usePickerFetch<T>(
  url: string,
  params: URLSearchParams,
  options: Options<T> = {},
): PickerFetchResult<T> {
  const { skip = false, validate } = options;
  const query = useMemo(() => params.toString(), [params]);
  const fingerprint = `${url}?${query}`;
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<State<T>>({ data: null, loading: !skip, error: null, key: "" });

  useEffect(() => {
    if (skip) return;
    const controller = new AbortController();
    fetch(`${url}?${query}`, { signal: controller.signal })
      .then((res) => {
        if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
        return res.json();
      })
      .then((body: unknown) => {
        if (validate && !validate(body)) throw new Error("invalid response shape");
        setState({ data: body as T, loading: false, error: null, key: fingerprint });
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        if (err instanceof Error && err.name === "AbortError") return;
        const wrapped = err instanceof Error ? err : new Error(String(err));
        setState({ data: null, loading: false, error: wrapped, key: fingerprint });
      });
    return () => controller.abort();
  }, [url, query, fingerprint, nonce, skip, validate]);

  const retry = useCallback(() => setNonce((n) => n + 1), []);
  const matches = state.key === fingerprint;
  return {
    data: matches && !skip ? state.data : null,
    loading: skip ? false : !matches,
    error: matches ? state.error : null,
    retry,
  };
}
