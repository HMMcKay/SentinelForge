import { useCallback, useEffect, useState } from 'react';
import { useLive } from '../context/LiveContext';

interface QueryState<T> {
  data?: T;
  error?: Error;
  loading: boolean;
  refreshing: boolean;
}

interface QueryResult<T> extends QueryState<T> {
  reload: () => void;
}

export function useApiQuery<T>(
  loader: (signal: AbortSignal) => Promise<T>,
  refreshOnLive = true,
): QueryResult<T> {
  const { refreshToken } = useLive();
  const liveRefreshToken = refreshOnLive ? refreshToken : 0;
  const [retryToken, setRetryToken] = useState(0);
  const [state, setState] = useState<QueryState<T>>({ loading: true, refreshing: false });

  const reload = useCallback(() => setRetryToken((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setState((current) => ({
      ...current,
      loading: current.data === undefined,
      refreshing: current.data !== undefined,
      error: undefined,
    }));
    void loader(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setState({ data, loading: false, refreshing: false });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        const normalized = error instanceof Error ? error : new Error('An unexpected error occurred.');
        setState((current) => ({ ...current, error: normalized, loading: false, refreshing: false }));
      });
    return () => controller.abort();
  }, [loader, retryToken, liveRefreshToken]);

  return { ...state, reload };
}
