import React from 'react';
import { ServerCrash } from 'lucide-react';
import { FullPageError } from './FullPageError';

interface ServerErrorScreenProps {
  /** If the call site can re-issue the failed request, pass it here. */
  onRetry?: () => void;
  fullViewport?: boolean;
}

/**
 * 500 (or any unhandled 5xx). Backend deliberately sends no stack trace or
 * internals for these — see api docs — so there is nothing more to parse
 * out of the response than its generic message.
 */
export const ServerErrorScreen: React.FC<ServerErrorScreenProps> = ({ onRetry, fullViewport = false }) => (
  <FullPageError
    title="Something went wrong on our end"
    message="Please try again in a moment."
    icon={ServerCrash}
    tone="critical"
    fullViewport={fullViewport}
    actionLabel={onRetry ? 'Retry' : 'Reload'}
    onAction={onRetry ?? (() => window.location.reload())}
  />
);

export default ServerErrorScreen;
