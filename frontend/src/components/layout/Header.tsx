import React, { useEffect, useRef, useState } from 'react';
import {
  Bell,
  RefreshCw,
  ChevronDown,
  LogOut,
  Settings,
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  Clock,
  Radio,
  Check,
  Trash2,
  Send,
} from 'lucide-react';
import { HealthResponse } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { useNotificationsWebSocket } from '../../services/websocket';

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
  // Real-time WebSocket notifications hook
  const {
    notifications,
    unreadCount,
    status: wsStatus,
    markAsRead,
    markAllAsRead,
    clearAll,
    sendTestAlert,
    reconnect,
  } = useNotificationsWebSocket();

  // Notification drawer open/close
  const [notifOpen, setNotifOpen] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);

  // Live UTC Clock
  const [timeStr, setTimeStr] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(
        now.toLocaleTimeString('en-US', {
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          timeZone: 'UTC',
        }) + ' UTC'
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Click outside to close notifications
  useEffect(() => {
    if (!notifOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [notifOpen]);

  // Format relative timestamp
  const formatTimeAgo = (isoString?: string) => {
    if (!isoString) return 'Just now';
    try {
      const date = new Date(isoString);
      const diffSecs = Math.floor((Date.now() - date.getTime()) / 1000);
      if (diffSecs < 10) return 'Just now';
      if (diffSecs < 60) return `${diffSecs}s ago`;
      const diffMins = Math.floor(diffSecs / 60);
      if (diffMins < 60) return `${diffMins}m ago`;
      const diffHours = Math.floor(diffMins / 60);
      if (diffHours < 24) return `${diffHours}h ago`;
      return `${Math.floor(diffHours / 24)}d ago`;
    } catch {
      return 'Recent';
    }
  };

  return (
    <header className="h-16 bg-white/95 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30 shrink-0 border-b border-slate-200/80 shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
      {/* Left side: Breadcrumb & Platform Environment */}
      <div className="flex items-center gap-2.5 min-w-0">
        <div className="flex items-center gap-1.5 text-xs font-medium min-w-0">
          {breadcrumb.map((crumb, i) => (
            <React.Fragment key={i}>
              {i > 0 && <span className="text-slate-300">/</span>}
              {onBreadcrumbClick && i < breadcrumb.length ? (
                <button
                  type="button"
                  onClick={() => onBreadcrumbClick(crumb)}
                  className={`hover:text-blue-600 transition-colors rounded-md px-1.5 py-0.5 ${
                    i === breadcrumb.length - 1 && !title
                      ? 'text-slate-900 font-bold'
                      : 'text-slate-500 hover:bg-blue-50/50'
                  }`}
                >
                  {crumb}
                </button>
              ) : (
                <span
                  className={
                    i === breadcrumb.length - 1 && !title
                      ? 'text-slate-900 font-bold'
                      : 'text-slate-500'
                  }
                >
                  {crumb}
                </span>
              )}
            </React.Fragment>
          ))}
          {breadcrumb.length > 0 && title && <span className="text-slate-300">/</span>}
          {title && (
            <span className="font-bold text-slate-900 truncate tracking-tight text-[13px]">
              {title}
            </span>
          )}
        </div>

        {/* Forensic Environment Pill */}
        <span className="hidden xl:inline-flex items-center gap-1 text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200/70">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
          SOC NODE
        </span>
      </div>

      {/* Right side: Live UTC Clock, WS Status, Engine Status, WS Notifications, User Menu */}
      <div className="flex items-center gap-2.5 shrink-0">
        {/* Live UTC Clock */}
        <div
          title="Synchronized UTC SOC Time"
          className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-slate-50 border border-slate-200/70 text-slate-600 text-xs font-mono shadow-2xs"
        >
          <Clock className="w-3.5 h-3.5 text-slate-400" />
          <span className="font-semibold text-[11px] tracking-tight">{timeStr || 'UTC'}</span>
        </div>

        {/* WebSocket Real-time Status Badge */}
        <div
          title={`WebSocket Status: ${wsStatus}`}
          className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-[11px] font-medium border transition-colors shadow-2xs ${
            wsStatus === 'connected'
              ? 'bg-emerald-50/60 border-emerald-200 text-emerald-800'
              : wsStatus === 'connecting'
              ? 'bg-amber-50/60 border-amber-200 text-amber-800'
              : 'bg-rose-50/60 border-rose-200 text-rose-800 cursor-pointer hover:bg-rose-100'
          }`}
          onClick={wsStatus === 'disconnected' ? reconnect : undefined}
        >
          <span className="relative flex h-2 w-2 shrink-0">
            <span
              className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${
                wsStatus === 'connected'
                  ? 'beacon-pulse bg-emerald-400'
                  : wsStatus === 'connecting'
                  ? 'beacon-pulse-amber bg-amber-400'
                  : 'bg-rose-400'
              }`}
            />
            <span
              className={`relative inline-flex rounded-full h-2 w-2 ${
                wsStatus === 'connected'
                  ? 'bg-emerald-500'
                  : wsStatus === 'connecting'
                  ? 'bg-amber-500'
                  : 'bg-rose-500'
              }`}
            />
          </span>
          <span className="font-semibold tracking-tight text-[11px]">
            {wsStatus === 'connected'
              ? 'WS Live'
              : wsStatus === 'connecting'
              ? 'WS Connecting'
              : 'WS Offline (Retry)'}
          </span>
        </div>

        {/* Backend Engine Health Monitor */}
        <button
          onClick={onRefreshHealth}
          title="Backend engine status & health monitor (click to refresh)"
          className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-blue-100 bg-blue-50/40 text-xs text-blue-900 hover:bg-blue-50 hover:border-blue-200 transition-all shadow-2xs"
        >
          {loading ? (
            <RefreshCw className="w-3 h-3 animate-spin text-blue-500" />
          ) : health ? (
            <ServiceDot ok />
          ) : (
            <ServiceDot ok={false} />
          )}
          <span className="font-semibold text-[11.5px] hidden sm:inline">
            {loading ? 'Checking…' : health ? 'Engine Online' : 'Engine Offline'}
          </span>
        </button>

        {/* Real-time Notifications Bell & Dropdown */}
        <div className="relative" ref={notifRef}>
          <button
            type="button"
            onClick={() => setNotifOpen((v) => !v)}
            title="Real-time SOC Threat Notifications"
            className={`relative p-2 rounded-xl transition-all ${
              notifOpen
                ? 'bg-blue-100/70 text-blue-700 shadow-inner'
                : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
            }`}
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 flex h-4.5 min-w-[18px] px-1 items-center justify-center rounded-full bg-rose-600 text-white text-[10px] font-bold shadow-sm ring-2 ring-white animate-pulse">
                {unreadCount > 99 ? '99+' : unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Drawer Popover */}
          {notifOpen && (
            <div className="absolute right-0 mt-2.5 w-80 sm:w-96 bg-white border border-slate-200 rounded-2xl shadow-2xl shadow-slate-900/15 py-0 z-50 animate-fade-in overflow-hidden">
              {/* Drawer Header */}
              <div className="px-4 py-3 bg-gradient-to-r from-slate-50 to-blue-50/40 border-b border-slate-200/80 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-lg bg-blue-600/10 border border-blue-200 flex items-center justify-center text-blue-600">
                    <Radio className="w-3.5 h-3.5 animate-pulse" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 tracking-tight flex items-center gap-1.5">
                      Threat Notifications
                      {unreadCount > 0 && (
                        <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-rose-100 text-rose-700 border border-rose-200">
                          {unreadCount} new
                        </span>
                      )}
                    </h4>
                    <p className="text-[10.5px] text-slate-500 font-mono">
                      WebSocket Live Feed • {notifications.length} events
                    </p>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={markAllAsRead}
                    disabled={unreadCount === 0}
                    title="Mark all as read"
                    className="p-1 rounded-lg hover:bg-slate-200/60 text-slate-500 hover:text-slate-800 disabled:opacity-40 transition-colors"
                  >
                    <Check className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={clearAll}
                    disabled={notifications.length === 0}
                    title="Clear notification list"
                    className="p-1 rounded-lg hover:bg-rose-50 text-slate-400 hover:text-rose-600 disabled:opacity-40 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Notification List */}
              <div className="max-h-[380px] overflow-y-auto divide-y divide-slate-100">
                {notifications.length === 0 ? (
                  <div className="py-12 px-4 text-center">
                    <div className="w-10 h-10 rounded-2xl bg-emerald-50 text-emerald-600 border border-emerald-200 flex items-center justify-center mx-auto mb-2">
                      <CheckCircle2 className="w-5 h-5" />
                    </div>
                    <p className="text-xs font-bold text-slate-800">All Clear</p>
                    <p className="text-[11px] text-slate-500 mt-0.5">
                      No active threat alerts in this session.
                    </p>
                  </div>
                ) : (
                  notifications.map((item) => {
                    const isCritical = item.severity === 'critical';
                    const isHigh = item.severity === 'high';
                    const isRead = item.read;

                    return (
                      <div
                        key={item.id}
                        onClick={() => markAsRead(item.id)}
                        className={`p-3.5 transition-colors cursor-pointer hover:bg-slate-50/90 flex items-start gap-3 ${
                          !isRead ? 'bg-blue-50/25' : 'bg-white opacity-85'
                        }`}
                      >
                        {/* Icon */}
                        <div
                          className={`w-7 h-7 rounded-xl flex items-center justify-center shrink-0 mt-0.5 border ${
                            isCritical
                              ? 'bg-rose-50 border-rose-200 text-rose-600'
                              : isHigh
                              ? 'bg-amber-50 border-amber-200 text-amber-600'
                              : 'bg-blue-50 border-blue-200 text-blue-600'
                          }`}
                        >
                          {isCritical ? (
                            <ShieldAlert className="w-3.5 h-3.5" />
                          ) : isHigh ? (
                            <AlertTriangle className="w-3.5 h-3.5" />
                          ) : (
                            <Info className="w-3.5 h-3.5" />
                          )}
                        </div>

                        {/* Text */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-2">
                            <h5
                              className={`text-xs font-bold truncate ${
                                isCritical ? 'text-rose-950' : 'text-slate-900'
                              }`}
                            >
                              {item.title}
                            </h5>
                            <span className="text-[10px] font-mono text-slate-400 shrink-0">
                              {formatTimeAgo(item.timestamp)}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 mt-0.5 leading-relaxed">
                            {item.message}
                          </p>

                          {/* Chips */}
                          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                            <span
                              className={`text-[9.5px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${
                                isCritical
                                  ? 'bg-rose-100/70 border-rose-200 text-rose-700'
                                  : isHigh
                                  ? 'bg-amber-100/70 border-amber-200 text-amber-700'
                                  : 'bg-slate-100 border-slate-200 text-slate-600'
                              }`}
                            >
                              {item.severity}
                            </span>
                            {item.data?.threat_score !== undefined && (
                              <span className="text-[9.5px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                                Score: {item.data.threat_score}/100
                              </span>
                            )}
                            {!isRead && (
                              <span className="w-1.5 h-1.5 rounded-full bg-blue-600 ml-auto" />
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              {/* Drawer Footer: Live stream info & Test simulation trigger */}
              <div className="px-3.5 py-2.5 bg-slate-50 border-t border-slate-200/80 flex items-center justify-between text-xs">
                <span className="text-[10.5px] text-slate-500 font-mono flex items-center gap-1">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      wsStatus === 'connected' ? 'bg-emerald-500' : 'bg-amber-500'
                    }`}
                  />
                  {wsStatus === 'connected' ? 'Live Streaming' : 'Reconnecting...'}
                </span>

                <button
                  type="button"
                  onClick={sendTestAlert}
                  title="Simulate a real-time threat alert over WebSocket"
                  className="flex items-center gap-1 text-[11px] font-medium text-blue-600 hover:text-blue-700 hover:bg-blue-50 px-2 py-1 rounded-lg border border-blue-200/70 transition-colors"
                >
                  <Send className="w-3 h-3" />
                  Simulate Threat Alert
                </button>
              </div>
            </div>
          )}
        </div>

        {/* User Account Menu */}
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
    <div className="relative pl-2 sm:pl-3 border-l border-slate-200" ref={menuRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-xl py-1 pr-1 hover:bg-slate-50 transition-colors"
      >
        <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-blue-600 to-indigo-600 text-white flex items-center justify-center font-bold text-xs ring-2 ring-blue-100 shadow-2xs shrink-0">
          {getInitials(displayName)}
        </div>
        <div className="hidden lg:block leading-tight text-left">
          <div className="text-[12.5px] font-bold text-slate-900 truncate max-w-[130px]">
            {displayName}
          </div>
          <div className="text-[10.5px] text-slate-500 truncate max-w-[130px]">
            {user.organization_name || 'Personal Workspace'}
          </div>
        </div>
        <ChevronDown className="hidden sm:block w-3.5 h-3.5 text-slate-400" />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-64 bg-white border border-slate-200 rounded-2xl shadow-xl shadow-slate-900/10 py-1.5 z-40 animate-fade-in">
          <div className="px-3.5 py-2.5 border-b border-slate-100">
            <div className="flex items-center justify-between gap-2">
              <div className="text-[13px] font-bold text-slate-900 truncate">{displayName}</div>
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 shrink-0">
                {formatRoleLabel(user.role)}
              </span>
            </div>
            <div className="flex items-center gap-1.5 text-[12px] text-slate-500 truncate mt-0.5">
              <span>{user.email}</span>
              {user.username && (
                <span className="text-blue-600 font-mono text-[11px]">(@{user.username})</span>
              )}
            </div>
          </div>

          <div className="py-1">
            {onNavigateToSettings && (
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onNavigateToSettings();
                }}
                className="w-full flex items-center gap-2.5 px-3.5 py-2 text-[13px] text-slate-700 hover:bg-blue-50/70 hover:text-blue-700 font-medium transition-colors"
              >
                <Settings className="w-4 h-4 text-blue-600" />
                Account Settings
              </button>
            )}
          </div>

          <div className="border-t border-slate-100 pt-1">
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                logout();
              }}
              className="w-full flex items-center gap-2.5 px-3.5 py-2 text-[13px] text-rose-600 hover:bg-rose-50/60 font-medium transition-colors"
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
