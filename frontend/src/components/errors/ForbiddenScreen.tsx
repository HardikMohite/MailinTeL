import React from 'react';
import { ShieldOff } from 'lucide-react';
import { FullPageError } from './FullPageError';

interface ForbiddenScreenProps {
  onGoBack?: () => void;
  fullViewport?: boolean;
}

/**
 * 403 — authenticated but not permitted (wrong org, wrong role). Copy is
 * intentionally generic: it never hints at what permission/role/org would
 * unlock this, since that's information disclosure about access controls.
 */
export const ForbiddenScreen: React.FC<ForbiddenScreenProps> = ({ onGoBack, fullViewport = false }) => (
  <FullPageError
    title="Access denied"
    message="You don't have access to this."
    icon={ShieldOff}
    tone="high"
    fullViewport={fullViewport}
    actionLabel={onGoBack ? 'Go back' : undefined}
    onAction={onGoBack}
  />
);

export default ForbiddenScreen;
