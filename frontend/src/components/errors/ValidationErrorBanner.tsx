import React from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { PydanticErrorDetail } from '../../hooks/useApiErrorHandler';

interface ValidationErrorBannerProps {
  message?: string;
  details?: PydanticErrorDetail[];
  onDismiss?: () => void;
  className?: string;
}

/**
 * Humanizes a Pydantic `loc` path into a short field label, e.g.
 * ["body", "email"] -> "email", ["body", "recipients", 0, "address"] -> "recipients[0].address".
 * Never renders the raw loc/type — just enough to point at the field.
 */
function formatFieldLabel(loc: (string | number)[]): string {
  const parts = loc.filter((p) => p !== 'body' && p !== 'query' && p !== 'path');
  if (parts.length === 0) return 'This field';
  return parts.reduce<string>((label, part, i) => {
    if (typeof part === 'number') return `${label}[${part}]`;
    return i === 0 ? String(part) : `${label}.${part}`;
  }, '');
}

export const ValidationErrorBanner: React.FC<ValidationErrorBannerProps> = ({
  message,
  details,
  onDismiss,
  className = '',
}) => {
  return (
    <div
      role="alert"
      className={`flex items-start gap-3 rounded-xl border border-severity-high/20 bg-severity-high-soft p-4 ${className}`}
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-severity-high" />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-text-primary">
          {message || "Let's fix a few things before continuing"}
        </p>
        {details && details.length > 0 && (
          <ul className="mt-1.5 list-disc space-y-0.5 pl-4 text-[13px] text-text-secondary">
            {details.map((detail, i) => (
              <li key={i}>
                <span className="font-medium text-text-primary">{formatFieldLabel(detail.loc)}</span>
                {': '}
                {detail.msg}
              </li>
            ))}
          </ul>
        )}
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          aria-label="Dismiss"
          className="shrink-0 rounded-md p-1 text-text-muted transition-colors hover:bg-black/5 hover:text-text-secondary"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
};

export default ValidationErrorBanner;
