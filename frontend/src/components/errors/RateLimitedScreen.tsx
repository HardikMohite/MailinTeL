import React, { useEffect, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { FullPageError } from './FullPageError';

interface RateLimitedScreenProps {
  /** Seconds to wait, parsed from a Retry-After header. Omit if the backend didn't send one. */
  retryAfterSeconds?: number;
  /** Shown as-is when there's no Retry-After to count down from. */
  fallbackMessage?: string;
  onRetry: () => void;
  fullViewport?: boolean;
}

export const RateLimitedScreen: React.FC<RateLimitedScreenProps> = ({
  retryAfterSeconds,
  fallbackMessage,
  onRetry,
  fullViewport = false,
}) => {
  const [secondsLeft, setSecondsLeft] = useState<number>(retryAfterSeconds ?? 0);

  useEffect(() => {
    setSecondsLeft(retryAfterSeconds ?? 0);
  }, [retryAfterSeconds]);

  useEffect(() => {
    if (secondsLeft <= 0) return;
    const timer = window.setInterval(() => {
      setSecondsLeft((s) => Math.max(0, s - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [secondsLeft > 0]);

  const hasCountdown = typeof retryAfterSeconds === 'number';
  const isWaiting = hasCountdown && secondsLeft > 0;

  const message = hasCountdown
    ? `Too many attempts — try again in ${secondsLeft}s`
    : fallbackMessage || 'Too many attempts — please wait a moment before trying again.';

  return (
    <FullPageError
      title="Too many attempts"
      message={message}
      icon={AlertTriangle}
      tone="high"
      fullViewport={fullViewport}
      actionLabel="Try again"
      onAction={onRetry}
      actionDisabled={isWaiting}
    />
  );
};

export default RateLimitedScreen;
