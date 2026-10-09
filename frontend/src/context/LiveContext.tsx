import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { liveWebSocketUrl } from '../api/client';
import type { LiveMessage, LiveStatus } from '../types';

interface LiveContextValue {
  status: LiveStatus;
  lastMessage?: LiveMessage;
  refreshToken: number;
  reconnectAttempt: number;
  markMutation: () => void;
}

const LiveContext = createContext<LiveContextValue | undefined>(undefined);

function decodeMessage(data: unknown): LiveMessage {
  try {
    const parsed = JSON.parse(String(data)) as unknown;
    if (parsed && typeof parsed === 'object') {
      const item = parsed as Record<string, unknown>;
      return {
        type: typeof item.type === 'string' ? item.type : 'update',
        timestamp: typeof item.timestamp === 'string' ? item.timestamp : new Date().toISOString(),
        payload: item.payload ?? parsed,
      };
    }
  } catch {
    // Non-JSON keepalive messages still prove that the connection is alive.
  }
  return { type: 'update', timestamp: new Date().toISOString(), payload: data };
}

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<LiveStatus>('connecting');
  const [lastMessage, setLastMessage] = useState<LiveMessage>();
  const [refreshToken, setRefreshToken] = useState(0);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const pendingRefresh = useRef<number>();

  const markMutation = useCallback(() => {
    window.clearTimeout(pendingRefresh.current);
    pendingRefresh.current = window.setTimeout(() => {
      setRefreshToken((value) => value + 1);
    }, 250);
  }, []);

  useEffect(() => {
    const url = liveWebSocketUrl();
    if (!url) {
      setStatus('unsupported');
      return undefined;
    }

    let active = true;
    let socket: WebSocket | undefined;
    let retryTimer: number | undefined;
    let attempts = 0;

    const connect = () => {
      if (!active) return;
      setStatus('connecting');
      socket = new WebSocket(url);
      socket.addEventListener('open', () => {
        attempts = 0;
        setReconnectAttempt(0);
        setStatus('connected');
      });
      socket.addEventListener('message', (event) => {
        setLastMessage(decodeMessage(event.data));
        markMutation();
      });
      socket.addEventListener('close', () => {
        if (!active) return;
        setStatus('disconnected');
        attempts += 1;
        setReconnectAttempt(attempts);
        const delay = Math.min(30_000, 1_000 * 2 ** Math.min(attempts - 1, 5));
        retryTimer = window.setTimeout(connect, delay);
      });
      socket.addEventListener('error', () => socket?.close());
    };

    const handleOffline = () => setStatus('disconnected');
    const handleOnline = () => {
      if (!socket || socket.readyState === WebSocket.CLOSED) connect();
    };
    window.addEventListener('offline', handleOffline);
    window.addEventListener('online', handleOnline);
    connect();

    return () => {
      active = false;
      window.clearTimeout(retryTimer);
      window.clearTimeout(pendingRefresh.current);
      window.removeEventListener('offline', handleOffline);
      window.removeEventListener('online', handleOnline);
      socket?.close();
    };
  }, [markMutation]);

  const value = useMemo(
    () => ({ status, lastMessage, refreshToken, reconnectAttempt, markMutation }),
    [status, lastMessage, refreshToken, reconnectAttempt, markMutation],
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveContextValue {
  const context = useContext(LiveContext);
  if (!context) throw new Error('useLive must be used inside LiveProvider');
  return context;
}
