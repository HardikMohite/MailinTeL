import React from 'react';
import { FileQuestion } from 'lucide-react';
import { FullPageError } from './FullPageError';

interface NotFoundScreenProps {
  onGoBack?: () => void;
  fullViewport?: boolean;
}

/**
 * 404 — used both for "this record was deleted/belongs to another org" and
 * for unrecognized app/tab state. Copy is deliberately the same generic
 * message in every case: don't imply the resource exists somewhere else,
 * and don't distinguish "not yours" from "doesn't exist".
 */
export const NotFoundScreen: React.FC<NotFoundScreenProps> = ({ onGoBack, fullViewport = false }) => (
  <FullPageError
    title="We couldn't find that"
    message="It may have been removed, or it never existed."
    icon={FileQuestion}
    tone="muted"
    fullViewport={fullViewport}
    actionLabel={onGoBack ? 'Go back' : undefined}
    onAction={onGoBack}
  />
);

export default NotFoundScreen;
