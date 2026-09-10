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
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 font-semibold ${sizeClasses}`}>
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-600" />
            </span>
            {displayLabel}
          </span>
        );
      case 'high':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200 font-semibold ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-amber-600" />
            {displayLabel}
          </span>
        );
      case 'medium':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-purple-50 text-purple-800 border border-purple-200 font-medium ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-purple-600" />
            {displayLabel}
          </span>
        );
      case 'low':
      case 'informational':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-sky-50 text-sky-800 border border-sky-200 font-medium ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-sky-600" />
            {displayLabel}
          </span>
        );
      case 'safe':
      case 'positive':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200 font-semibold ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
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
