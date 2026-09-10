import React, { useEffect, useRef, useState } from 'react';
import { WifiOff } from 'lucide-react';
import { FullPageError } from './FullPageError';
import { checkHealth } from '../../services/api';

interface OfflineScreenProps {
  /** Called the moment health returns OK, so the parent can dismiss this screen. */
  onBackOnline: () => void;
  pollIntervalMs?: number;
  fullViewport?: boolean;
}

/**
 * Shown on a network-level failure (backend unreachable, CORS rejection,
 * timeout). Reuses the existing checkHealth() health-check pattern already
 * used in App.tsx/api.ts, polling in the background and dismissing itself
 * automatically the instant the backend is reachable again — no manual
 * retry click required.
 */
export const OfflineScreen: React.FC<OfflineScreenProps> = ({
  onBackOnline,
  pollIntervalMs = 4000,
  fullViewport = false,
}) => {
  const [checking, setChecking] = useState(false);
  const onBackOnlineRef = useRef(onBackOnline);
  onBackOnlineRef.current = onBackOnline;

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      setChecking(true);
      try {
        const health = await checkHealth();
        if (!cancelled && health?.status) {
          onBackOnlineRef.current();
        }
      } catch {
        // Still offline — keep polling silently.
      } finally {
        if (!cancelled) setChecking(false);
      }
    };

    const interval = window.setInterval(poll, pollIntervalMs);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [pollIntervalMs]);

  return (
    <FullPageError
      title="You're offline"
      message="We can't reach the server. This will refresh automatically once your connection is back."
      icon={WifiOff}
      tone="muted"
      fullViewport={fullViewport}
    >
      <p className="text-xs text-text-muted">{checking ? 'Checking connection…' : 'Waiting to reconnect…'}</p>
    </FullPageError>
  );
};

export default OfflineScreen;
