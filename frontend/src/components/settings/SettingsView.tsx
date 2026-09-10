import React from 'react';
import {
  Settings as SettingsIcon,
  Database,
  HardDrive,
  Server,
  Cpu,
  RefreshCw,
  AlertTriangle,
  UserCircle2,
  SlidersHorizontal,
  Radar,
} from 'lucide-react';
import { HealthResponse, DetailedHealthResponse } from '../../services/api';
import { StatusBadge } from '../common/StatusBadge';

interface SettingsViewProps {
  health: HealthResponse | null;
  detailedHealth: DetailedHealthResponse | null;
  loading?: boolean;
  onRefreshHealth: () => void;
}

const fmtDateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : 'N/A');

const connectivityBadge = (status?: string) => {
  const normalized = (status || '').toLowerCase();
  if (normalized === 'connected' || normalized === 'healthy' || normalized === 'ready') {
    return <StatusBadge type="severity" value="safe" label="CONNECTED" size="sm" />;
  }
  if (normalized === 'disconnected' || normalized === 'not_ready') {
    return <StatusBadge type="severity" value="critical" label="DISCONNECTED" size="sm" />;
  }
  return <StatusBadge type="severity" value="medium" label="UNKNOWN" size="sm" />;
};

const latencyLabel = (ms?: number) => (typeof ms === 'number' ? `${ms.toFixed(0)} ms` : '—');

// Correlation/clustering engine defaults, as applied server-side when no
// per-request override is supplied. Sourced from the same constants the
// backend uses (similarity_service.py, campaigns.py) — not independently
// adjustable from this screen, since the platform does not yet expose a
// settings-persistence endpoint (see Design.md §38).
const ENGINE_DEFAULTS = [
  {
    label: 'Semantic Similarity Threshold',
    value: '65%',
    detail: 'Minimum cosine similarity required to surface a related/similar email match.',
  },
  {
    label: 'Campaign Auto-Clustering Threshold',
    value: '60%',
    detail: 'Minimum composite correlation score required to group emails into a campaign via auto-clustering.',
  },
  {
    label: 'Live Correlation Threshold',
    value: '40%',
    detail: 'Minimum correlation score surfaced when computing live multi-vector correlation signals for an email.',
  },
];

// Threat intelligence adapters wired into the correlation engine. Shown here
// as configured integration points, not as a live-verified "active" status —
// the health endpoints this screen reads from don't report per-provider
// connectivity, so we don't claim one.
const THREAT_INTEL_SOURCES = [
  {
    name: 'VirusTotal v3 API',
    detail: 'Domain, URL, and file-hash reputation aggregation across multiple scanning engines.',
  },
  {
    name: 'AbuseIPDB v2 API',
    detail: 'IP address abuse-confidence scoring and historical abuse report lookups.',
  },
  {
    name: 'URLhaus (abuse.ch)',
    detail: 'Community-sourced malware distribution and phishing URL feed.',
  },
];

export const SettingsView: React.FC<SettingsViewProps> = ({
  health,
  detailedHealth,
  loading = false,
  onRefreshHealth,
}) => {
  const overallHealthy = health?.status === 'healthy';
  const showDisconnectedBanner = !loading && !health;

  return (
    <div className="space-y-6">
      {/* Page Title + Description */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <SettingsIcon className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary tracking-tight">Settings</h1>
            <p className="text-sm text-text-muted mt-0.5">
              Platform configuration, backend service health, and correlation engine defaults.
            </p>
          </div>
        </div>
        <button
          onClick={onRefreshHealth}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-workspace-card text-text-primary border border-workspace-border text-sm font-medium hover:bg-workspace-secondary transition-colors disabled:opacity-50 self-start md:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {showDisconnectedBanner && (
        <div className="px-4 py-2.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-sm text-severity-high flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>Could not reach the backend health endpoint. Status below may be stale — try refreshing.</span>
        </div>
      )}

      {/* Platform Status Summary */}
      <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm">
        {loading && !health ? (
          <div className="h-16 rounded-lg bg-workspace-secondary animate-pulse" />
        ) : (
          <div className="flex flex-wrap items-center gap-x-8 gap-y-3">
            <div className="flex items-center gap-2.5">
              <StatusBadge
                type="severity"
                value={overallHealthy ? 'safe' : 'critical'}
                label={health?.status ? health.status.toUpperCase() : 'UNKNOWN'}
              />
              <span className="text-sm font-semibold text-text-primary">
                {health?.app_name || 'MailIntel'}
              </span>
            </div>
            <div className="text-xs text-text-secondary">
              <span className="text-text-muted">Environment: </span>
              <span className="font-mono font-medium text-text-primary">{health?.environment || '—'}</span>
            </div>
            <div className="text-xs text-text-secondary">
              <span className="text-text-muted">Version: </span>
              <span className="font-mono font-medium text-text-primary">{health?.version || '—'}</span>
            </div>
            <div className="text-xs text-text-secondary">
              <span className="text-text-muted">Runtime: </span>
              <span className="font-mono font-medium text-text-primary">
                {detailedHealth?.runtime?.python_version?.split(' ')[0] || '—'}
                {detailedHealth?.runtime?.platform ? ` · ${detailedHealth.runtime.platform}` : ''}
              </span>
            </div>
            <div className="text-xs text-text-secondary ml-auto">
              <span className="text-text-muted">Last checked: </span>
              <span className="font-medium text-text-primary">{fmtDateTime(health?.timestamp)}</span>
            </div>
          </div>
        )}
      </div>

      {/* Service Health Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* PostgreSQL + pgvector */}
        <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-brand" />
              <h3 className="text-sm font-bold text-text-primary">Database</h3>
            </div>
            {connectivityBadge(health?.services?.database?.status)}
          </div>
          <div className="space-y-1.5 text-xs text-text-secondary border-t border-workspace-border pt-2.5">
            <div className="flex justify-between">
              <span className="text-text-muted">Latency:</span>
              <span className="font-mono font-medium text-text-primary">
                {latencyLabel(health?.services?.database?.latency_ms ?? detailedHealth?.services?.postgres?.latency_ms)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Configured DB:</span>
              <span className="font-mono font-medium text-text-primary">
                {detailedHealth?.services?.postgres?.configured_db || '—'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Host:</span>
              <span className="font-mono font-medium text-text-primary truncate max-w-[140px]" title={detailedHealth?.services?.postgres?.configured_host}>
                {detailedHealth?.services?.postgres?.configured_host || '—'}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-text-muted">pgvector:</span>
              {detailedHealth?.services?.postgres?.pgvector ? (
                <span className={`font-mono font-medium ${detailedHealth.services.postgres.pgvector.available ? 'text-severity-safe' : 'text-severity-critical'}`}>
                  {detailedHealth.services.postgres.pgvector.available
                    ? detailedHealth.services.postgres.pgvector.version || 'available'
                    : 'unavailable'}
                </span>
              ) : (
                <span className="text-text-primary">—</span>
              )}
            </div>
          </div>
        </div>

        {/* MinIO Object Storage */}
        <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-brand" />
              <h3 className="text-sm font-bold text-text-primary">Object Storage</h3>
            </div>
            {connectivityBadge(health?.services?.storage?.status)}
          </div>
          <div className="space-y-1.5 text-xs text-text-secondary border-t border-workspace-border pt-2.5">
            <div className="flex justify-between">
              <span className="text-text-muted">Latency:</span>
              <span className="font-mono font-medium text-text-primary">
                {latencyLabel(health?.services?.storage?.latency_ms ?? detailedHealth?.services?.minio?.latency_ms)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Endpoint:</span>
              <span className="font-mono font-medium text-text-primary truncate max-w-[140px]" title={detailedHealth?.services?.minio?.configured_endpoint}>
                {detailedHealth?.services?.minio?.configured_endpoint || '—'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Buckets available:</span>
              <span className="font-mono font-medium text-text-primary">
                {detailedHealth?.services?.minio
                  ? `${detailedHealth.services.minio.available_buckets.length}/${detailedHealth.services.minio.required_buckets.length}`
                  : '—'}
              </span>
            </div>
            {detailedHealth?.services?.minio?.required_buckets?.length ? (
              <div className="pt-1 flex flex-wrap gap-1.5">
                {detailedHealth.services.minio.required_buckets.map((bucket) => {
                  const isAvailable = detailedHealth.services.minio.available_buckets.includes(bucket);
                  return (
                    <span
                      key={bucket}
                      className={`px-1.5 py-0.5 rounded font-mono text-[10px] border ${
                        isAvailable
                          ? 'bg-severity-safe-soft text-severity-safe border-severity-safe/20'
                          : 'bg-severity-critical-soft text-severity-critical border-severity-critical/20'
                      }`}
                    >
                      {bucket}
                    </span>
                  );
                })}
              </div>
            ) : null}
          </div>
        </div>

        {/* Redis Queue */}
        <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-brand" />
              <h3 className="text-sm font-bold text-text-primary">Job Queue</h3>
            </div>
            {connectivityBadge(health?.services?.redis?.status)}
          </div>
          <div className="space-y-1.5 text-xs text-text-secondary border-t border-workspace-border pt-2.5">
            <div className="flex justify-between">
              <span className="text-text-muted">Latency:</span>
              <span className="font-mono font-medium text-text-primary">
                {latencyLabel(health?.services?.redis?.latency_ms)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Host:</span>
              <span className="font-mono font-medium text-text-primary truncate max-w-[140px]" title={detailedHealth?.services?.redis?.configured_host}>
                {detailedHealth?.services?.redis?.configured_host || '—'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Port:</span>
              <span className="font-mono font-medium text-text-primary">
                {detailedHealth?.services?.redis?.configured_port ?? '—'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Session Context */}
      {detailedHealth?.demo_context && (
        <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
          <div className="flex items-center gap-2">
            <UserCircle2 className="w-4 h-4 text-brand" />
            <h3 className="text-sm font-bold text-text-primary">Active Session</h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs border-t border-workspace-border pt-3">
            <div>
              <div className="text-text-muted">User</div>
              <div className="font-medium text-text-primary mt-0.5">{detailedHealth.demo_context.user_name || '—'}</div>
            </div>
            <div>
              <div className="text-text-muted">Role</div>
              <div className="font-medium text-text-primary mt-0.5">{detailedHealth.demo_context.role || '—'}</div>
            </div>
            <div>
              <div className="text-text-muted">Organization</div>
              <div className="font-medium text-text-primary mt-0.5">{detailedHealth.demo_context.organization_name || '—'}</div>
            </div>
            <div>
              <div className="text-text-muted">Mode</div>
              <div className="font-medium text-text-primary mt-0.5 font-mono">{detailedHealth.demo_context.mode || '—'}</div>
            </div>
          </div>
        </div>
      )}

      {/* Correlation Engine Defaults */}
      <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
        <div className="flex items-center gap-2">
          <SlidersHorizontal className="w-4 h-4 text-brand" />
          <h3 className="text-sm font-bold text-text-primary">Correlation Engine Defaults</h3>
        </div>
        <p className="text-xs text-text-muted -mt-2">
          Applied automatically wherever a screen doesn't request a different threshold. These
          are not yet independently configurable from this screen.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {ENGINE_DEFAULTS.map((item) => (
            <div key={item.label} className="p-4 rounded-lg bg-workspace border border-workspace-border">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-text-primary">{item.label}</span>
                <span className="text-sm font-mono font-bold text-brand">{item.value}</span>
              </div>
              <p className="text-[11px] text-text-muted mt-1.5 leading-relaxed">{item.detail}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Threat Intelligence Sources */}
      <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
        <div className="flex items-center gap-2">
          <Radar className="w-4 h-4 text-brand" />
          <h3 className="text-sm font-bold text-text-primary">Threat Intelligence Sources</h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {THREAT_INTEL_SOURCES.map((source) => (
            <div key={source.name} className="p-4 rounded-lg bg-workspace border border-workspace-border space-y-1.5">
              <div className="flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-text-muted shrink-0" />
                <strong className="text-xs font-semibold text-text-primary">{source.name}</strong>
              </div>
              <p className="text-[11px] text-text-muted leading-relaxed">{source.detail}</p>
            </div>
          ))}
        </div>
        <p className="text-[11px] text-text-muted">
          Live per-provider connectivity isn't reported by the health endpoints above, so no
          active/inactive status is shown here — these are the sources the correlation engine
          queries during domain and IP lookups.
        </p>
      </div>
    </div>
  );
};
export default SettingsView;
