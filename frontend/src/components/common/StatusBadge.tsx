import React from 'react';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';
export type FeatureState = 'available' | 'processing' | 'beta' | 'planned' | 'coming_soon';

interface StatusBadgeProps {
  type: 'severity' | 'state';
  value: SeverityLevel | FeatureState | string;
  label?: string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  type,
  value,
  label,
  size = 'md',
}) => {
  const normalizedValue = value.toLowerCase();
  const displayLabel = label || value.toUpperCase().replace('_', ' ');

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';

  if (type === 'severity') {
    switch (normalizedValue) {
      case 'critical':
        return (
          <span className={`inline-flex items-center gap-1 rounded-full bg-severity-critical-soft text-severity-critical border border-severity-critical/20 ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-severity-critical animate-pulse" />
            {displayLabel}
          </span>
        );
      case 'high':
        return (
          <span className={`inline-flex items-center gap-1 rounded-full bg-severity-high-soft text-severity-high border border-severity-high/20 ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-severity-high" />
            {displayLabel}
          </span>
        );
      case 'medium':
        return (
          <span className={`inline-flex items-center gap-1 rounded-full bg-severity-medium-soft text-severity-medium border border-severity-medium/20 ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-severity-medium" />
            {displayLabel}
          </span>
        );
      case 'low':
      case 'informational':
        return (
          <span className={`inline-flex items-center gap-1 rounded-full bg-severity-low-soft text-severity-low border border-severity-low/20 ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-severity-low" />
            {displayLabel}
          </span>
        );
      case 'safe':
      case 'positive':
        return (
          <span className={`inline-flex items-center gap-1 rounded-full bg-severity-safe-soft text-severity-safe border border-severity-safe/20 ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-severity-safe" />
            {displayLabel}
          </span>
        );
      default:
        return (
          <span className={`inline-flex items-center rounded-full bg-gray-100 text-gray-700 border border-gray-200 ${sizeClasses}`}>
            {displayLabel}
          </span>
        );
    }
  }

  // Feature State Badge
  switch (normalizedValue) {
    case 'available':
      return (
        <span className={`inline-flex items-center gap-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200/60 ${sizeClasses}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          AVAILABLE
        </span>
      );
    case 'processing':
      return (
        <span className={`inline-flex items-center gap-1 rounded-full bg-blue-50 text-brand border border-brand/20 ${sizeClasses}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-brand animate-ping" />
          PROCESSING
        </span>
      );
    case 'planned':
    case 'coming_soon':
      return (
        <span className={`inline-flex items-center gap-1 rounded-full bg-slate-100 text-slate-600 border border-slate-200 ${sizeClasses}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
          {displayLabel}
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center rounded-full bg-slate-100 text-slate-700 ${sizeClasses}`}>
          {displayLabel}
        </span>
      );
  }
};
