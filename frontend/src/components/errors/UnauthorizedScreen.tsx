import React from 'react';
import { ShieldOff } from 'lucide-react';
import { FullPageError } from './FullPageError';
import { useAuth } from '../../context/AuthContext';

interface UnauthorizedScreenProps {
  /** Fills the whole viewport by default — a dead session invalidates the whole app, not one view. */
  fullViewport?: boolean;
}

/**
 * Shown on a 401 (missing/invalid/expired token). This codebase doesn't have
 * a login screen/AuthGate yet, so "sign in again" today means: clear the
 * dead session and reload to a clean slate. Once a real AuthGate exists,
 * point the action at its login state instead of window.location.reload().
 */
export const UnauthorizedScreen: React.FC<UnauthorizedScreenProps> = ({ fullViewport = true }) => {
  const { logout } = useAuth();

  const handleSignInAgain = (): void => {
    logout();
    window.location.reload();
  };

  return (
    <FullPageError
      title="Your session has expired"
      message="Please sign in again to continue."
      icon={ShieldOff}
      tone="high"
      fullViewport={fullViewport}
      actionLabel="Sign in again"
      onAction={handleSignInAgain}
    />
  );
};

export default UnauthorizedScreen;
