import React, { useState } from 'react';
import { LucideIcon, ChevronDown, ChevronUp } from 'lucide-react';

export interface FullPageErrorProps {
  title: string;
  message: string;
  icon?: LucideIcon;
  actionLabel?: string;
  onAction?: () => void;
  actionDisabled?: boolean;
  secondaryLabel?: string;
  onSecondaryAction?: () => void;
  /**
   * When true, fills the entire viewport (used for app-wide takeovers like
   * session expiry). When false (default), fills its parent container —
   * used inside <main>, so the sidebar/header stay visible and usable.
   */
  fullViewport?: boolean;
  /**
   * Optional accent for the icon badge. Defaults to a neutral brand tone;
   * pass 'critical' for 500s, 'high' for 429/403.
   */
  tone?: 'critical' | 'high' | 'muted';
  /** Raw technical detail, never shown by default — only via the toggle below. */
  technicalDetail?: string;
  children?: React.ReactNode;
}

const TONE_CLASSES: Record<NonNullable<FullPageErrorProps['tone']>, string> = {
  critical: 'bg-severity-critical-soft text-severity-critical',
  high: 'bg-severity-high-soft text-severity-high',
  muted: 'bg-workspace-secondary text-text-secondary',
};

export const FullPageError: React.FC<FullPageErrorProps> = ({
  title,
  message,
  icon: Icon,
  actionLabel,
  onAction,
  actionDisabled,
  secondaryLabel,
  onSecondaryAction,
  fullViewport = false,
  tone = 'muted',
  technicalDetail,
  children,
}) => {
  const [showDetail, setShowDetail] = useState(false);

  return (
    <div
      className={`flex items-center justify-center px-6 ${
        fullViewport ? 'min-h-screen bg-workspace' : 'h-full min-h-[420px]'
      }`}
    >
      <div className="w-full max-w-md text-center">
        {Icon && (
          <div
            className={`mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-2xl ${TONE_CLASSES[tone]}`}
          >
            <Icon className="h-7 w-7" />
          </div>
        )}
        <h2 className="text-lg font-semibold text-text-primary">{title}</h2>
        <p className="mt-2 text-sm text-text-secondary">{message}</p>

        {children && <div className="mt-4">{children}</div>}

        {(actionLabel || secondaryLabel) && (
          <div className="mt-6 flex items-center justify-center gap-3">
            {actionLabel && onAction && (
              <button
                onClick={onAction}
                disabled={actionDisabled}
                className="rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {actionLabel}
              </button>
            )}
            {secondaryLabel && onSecondaryAction && (
              <button
                onClick={onSecondaryAction}
                className="rounded-lg border border-workspace-border px-4 py-2 text-sm font-medium text-text-secondary transition-colors hover:bg-workspace"
              >
                {secondaryLabel}
              </button>
            )}
          </div>
        )}

        {/* Never shown by default — an explicit opt-in toggle so a curious
            user/support agent can copy detail out, without it being part of
            the default, always-visible copy. Still no stack traces here. */}
        {technicalDetail && (
          <div className="mt-6 text-left">
            <button
              onClick={() => setShowDetail((v) => !v)}
              className="mx-auto flex items-center gap-1 text-xs text-text-muted hover:text-text-secondary"
            >
              Technical details
              {showDetail ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            </button>
            {showDetail && (
              <pre className="mt-2 max-h-40 overflow-auto rounded-lg border border-workspace-border bg-workspace-secondary p-3 text-left text-xs text-text-muted">
                {technicalDetail}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default FullPageError;
