import React, { useEffect, useRef, useState } from 'react';
import { Search, Bell, RefreshCw, ChevronDown, LogOut, Settings } from 'lucide-react';
import { HealthResponse } from '../../services/api';
import { useAuth } from '../../context/AuthContext';

interface HeaderProps {
  health: HealthResponse | null;
  loading: boolean;
  onRefreshHealth: () => void;
  title?: string;
  breadcrumb?: string[];
  onBreadcrumbClick?: (crumb: string) => void;
  onNavigateToSettings?: () => void;
}

const ServiceDot: React.FC<{ ok?: boolean }> = ({ ok }) => (
  <span className="relative flex h-2 w-2 shrink-0">
    <span
      className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${
        ok ? 'beacon-pulse bg-emerald-400' : 'beacon-pulse-amber bg-amber-400'
      }`}
    />
    <span
      className={`relative inline-flex rounded-full h-2 w-2 ${
        ok ? 'bg-emerald-500' : 'bg-amber-500'
      }`}
    />
  </span>
);

export const Header: React.FC<HeaderProps> = ({
  health,
  loading,
  onRefreshHealth,
  title = 'Dashboard',
  breadcrumb = ['MailinteL'],
  onBreadcrumbClick,
  onNavigateToSettings,
}) => {
  return (
    <header className="h-16 glass-surface px-6 flex items-center justify-between sticky top-0 z-30 shrink-0 shadow-xs">
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-xs font-medium min-w-0">
        {breadcrumb.map((crumb, i) => (
          <React.Fragment key={i}>
            {i > 0 && <span className="text-text-muted/60">/</span>}
            {onBreadcrumbClick && i < breadcrumb.length ? (
              <button
                type="button"
                onClick={() => onBreadcrumbClick(crumb)}
                className={`hover:text-brand transition-colors rounded px-1.5 py-0.5 ${
                  i === breadcrumb.length - 1 && !title ? 'text-text-primary font-semibold' : 'text-text-muted hover:bg-workspace'
                }`}
              >
                {crumb}
              </button>
            ) : (
              <span className={i === breadcrumb.length - 1 && !title ? 'text-text-primary font-semibold' : 'text-text-muted'}>
                {crumb}
              </span>
            )}
          </React.Fragment>
        ))}
        {breadcrumb.length > 0 && title && <span className="text-text-muted/60">/</span>}
        {title && <span className="font-bold text-text-primary truncate">{title}</span>}
      </div>

      {/* Right side: search, system status, notifications, profile */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="relative hidden lg:block w-72 group">
          <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2 group-focus-within:text-brand transition-colors" />
          <input
            type="text"
            placeholder="Search threats, hashes, campaigns..."
            className="w-full pl-9 pr-10 py-1.5 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-brand/20 focus:border-brand focus:bg-white transition-all shadow-xs"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none inline-flex items-center gap-0.5 rounded border border-workspace-border bg-white px-1.5 py-0.5 font-mono text-[9.5px] font-semibold text-text-muted shadow-xs">
            /
          </kbd>
        </div>

        <button
          onClick={onRefreshHealth}
          title="Backend status & health monitor"
          className="hidden md:flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-workspace-border text-xs text-text-secondary hover:bg-workspace hover:text-text-primary transition-all shadow-xs"
        >
          {loading ? (
            <RefreshCw className="w-3 h-3 animate-spin text-text-muted" />
          ) : health ? (
            <ServiceDot ok />
          ) : (
            <ServiceDot ok={false} />
          )}
          <span className="font-medium text-[11.5px]">{loading ? 'Checking…' : health ? 'Engine Online' : 'Backend Unreachable'}</span>
        </button>

        <button
          title="Notifications"
          className="relative p-2 rounded-lg text-text-secondary hover:bg-workspace hover:text-text-primary transition-colors"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-brand rounded-full ring-2 ring-white" />
        </button>

        <UserMenu onNavigateToSettings={onNavigateToSettings} />
      </div>
    </header>
  );
};

function getInitials(label: string): string {
  const parts = label.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

const formatRoleLabel = (role?: string): string => {
  switch (role) {
    case 'SYSTEM_ADMIN':
      return 'System Administrator';
    case 'INSTITUTION_ADMIN':
      return 'Institution Administrator';
    case 'CYBER_CELL_INVESTIGATOR':
      return 'Cyber Cell Investigator';
    case 'SECURITY_ANALYST':
      return 'Security Analyst';
    case 'ANALYST':
      return 'Forensic Analyst';
    default:
      return 'Standard User';
  }
};

const UserMenu: React.FC<{ onNavigateToSettings?: () => void }> = ({ onNavigateToSettings }) => {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  if (!user) return null;

  const displayName = user.full_name || user.email;

  return (
    <div className="relative pl-3 border-l border-workspace-border" ref={menuRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2.5 rounded-lg py-1 pr-1 hover:bg-workspace transition-colors"
      >
        <div className="w-8 h-8 rounded-full bg-brand text-white flex items-center justify-center font-semibold text-xs shrink-0">
          {getInitials(displayName)}
        </div>
        <div className="hidden sm:block leading-tight text-left">
          <div className="text-[13px] font-semibold text-text-primary truncate max-w-[140px]">{displayName}</div>
          <div className="text-[11px] text-text-muted truncate max-w-[140px]">
            {user.organization_name || 'Personal Workspace'}
          </div>
        </div>
        <ChevronDown className="hidden sm:block w-3.5 h-3.5 text-text-muted" />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-64 bg-workspace-card border border-workspace-border rounded-xl shadow-lg py-1.5 z-40 animate-fade-in">
          <div className="px-3.5 py-2.5 border-b border-workspace-border">
            <div className="flex items-center justify-between gap-2">
              <div className="text-[13px] font-semibold text-text-primary truncate">{displayName}</div>
              <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-brand-soft text-brand border border-brand/20 shrink-0">
                {formatRoleLabel(user.role)}
              </span>
            </div>
            <div className="text-[12px] text-text-muted truncate mt-0.5">{user.email}</div>
          </div>

          <div className="py-1">
            {onNavigateToSettings && (
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onNavigateToSettings();
                }}
                className="w-full flex items-center gap-2.5 px-3.5 py-2 text-[13px] text-text-secondary hover:bg-workspace hover:text-text-primary transition-colors"
              >
                <Settings className="w-4 h-4 text-brand" />
                Account Settings
              </button>
            )}
          </div>

          <div className="border-t border-workspace-border pt-1">
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                logout();
              }}
              className="w-full flex items-center gap-2.5 px-3.5 py-2 text-[13px] text-rose-600 hover:bg-rose-50/50 transition-colors"
            >
              <LogOut className="w-4 h-4" />
              Log out
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Header;
