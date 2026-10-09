import React, { useEffect, useState } from 'react';
import { FileText, ShieldAlert, Inbox, ArrowRight, Flag } from 'lucide-react';
import { StatusBadge } from '../common/StatusBadge';
import {
  getDashboardSummary,
  DashboardThreatDistribution,
  DashboardRecentThreat,
  DashboardActiveCampaign,
  listEmails,
  listCampaigns,
  listReports,
} from '../../services/api';
import { useAuth } from '../../context/AuthContext';

interface DashboardViewProps {
  onAnalyze?: () => void;
  onExploreGraph?: () => void;
  onSelectEmail: (emailId: string) => void;
}

const THREAT_STATUSES = new Set(['SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS', 'CAMPAIGN_RELATED', 'CRITICAL']);
const SAFE_STATUSES = new Set(['NORMAL', 'SAFE', 'BENIGN']);

const severityForQualification = (status: string): 'critical' | 'high' | 'medium' | 'low' | 'safe' => {
  switch (status) {
    case 'MALICIOUS':
    case 'CRITICAL':
      return 'critical';
    case 'HIGH_RISK':
    case 'HIGH':
      return 'high';
    case 'SUSPICIOUS':
    case 'CAMPAIGN_RELATED':
    case 'MEDIUM':
      return 'medium';
    case 'QUALIFIED_FOR_INVESTIGATION':
      return 'low';
    default:
      return 'safe';
  }
};

const timeAgo = (iso: string): string => {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

export const DashboardView: React.FC<DashboardViewProps> = ({ onSelectEmail }) => {
  const { user } = useAuth();
  const [totalPhishing, setTotalPhishing] = useState<number>(0);
  const [threatCount, setThreatCount] = useState<number>(0);
  const [totalCampaigns, setTotalCampaigns] = useState<number>(0);
  const [totalReports, setTotalReports] = useState<number>(0);
  const [distribution, setDistribution] = useState<DashboardThreatDistribution[]>([]);
  const [recent, setRecent] = useState<DashboardRecentThreat[]>([]);
  const [activeCampaigns, setActiveCampaigns] = useState<DashboardActiveCampaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        // High-speed unified dashboard summary endpoint (single network roundtrip, 5ms warm cache)
        const summary = await getDashboardSummary();
        if (cancelled) return;
        setTotalPhishing(summary.total_phishing);
        setThreatCount(summary.threat_count);
        setTotalCampaigns(summary.total_campaigns);
        setTotalReports(summary.total_reports);
        setDistribution(summary.distribution);
        setRecent(summary.recent_threats);
        setActiveCampaigns(summary.active_campaigns);
      } catch (err) {
        // Fallback to legacy parallel endpoints in case of edge errors
        try {
          const [emailPage, campaignList, reportPage] = await Promise.all([
            listEmails(0, 100).catch(() => ({ total: 0, items: [] })),
            listCampaigns(undefined, 0, 50).catch(() => []),
            listReports(undefined, undefined, 1).catch(() => ({ total_reports: 0, reports: [] })),
          ]);
          if (cancelled) return;
          const phishing = (emailPage.items || []).filter(
            (e) => !SAFE_STATUSES.has((e.qualification_status || '').toUpperCase())
          );
          setTotalPhishing(phishing.length);
          setThreatCount(phishing.filter((e) => THREAT_STATUSES.has(e.qualification_status)).length);
          setTotalCampaigns((campaignList || []).length);
          setTotalReports(reportPage.total_reports || 0);
          setDistribution(
            ['MALICIOUS', 'HIGH_RISK', 'SUSPICIOUS', 'CAMPAIGN_RELATED', 'QUALIFIED_FOR_INVESTIGATION']
              .map((status) => ({
                status,
                count: phishing.filter((e) => e.qualification_status === status).length,
              }))
              .filter((d) => d.count > 0)
          );
          setRecent(
            phishing.slice(0, 8).map((e) => ({
              id: e.id,
              subject: e.subject,
              sender_address: e.sender_address,
              qualification_status: e.qualification_status,
              created_at: e.created_at,
              original_filename: e.original_filename,
            }))
          );
          setActiveCampaigns(
            (campaignList || []).slice(0, 4).map((c) => ({
              id: c.id,
              campaign_name: c.campaign_name,
              member_count: c.member_count,
            }))
          );
        } catch {
          if (!cancelled) setError('Could not load dashboard data from the backend.');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [user?.organization_id]);

  const maxCount = Math.max(1, ...distribution.map((d) => d.count));
  const [filterQuery, setFilterQuery] = useState('');

  // Search filtered recent activity
  const filteredRecent = recent.filter((e) => {
    if (!filterQuery.trim()) return true;
    const q = filterQuery.toLowerCase();
    return (
      (e.subject || '').toLowerCase().includes(q) ||
      (e.sender_address || '').toLowerCase().includes(q) ||
      (e.original_filename || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {error && (
        <div className="px-4 py-3 rounded-xl bg-severity-high-soft border border-severity-high/30 text-sm text-severity-high flex items-center gap-2.5 shadow-xs">
          <ShieldAlert className="w-4 h-4 shrink-0 text-severity-high" />
          <span>{error}</span>
        </div>
      )}

      {/* KPI metric cards strip — 4 security columns */}
      <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {[
          {
            label: 'Total Phishing',
            value: totalPhishing,
            subtext: 'Ingested lures',
            icon: Inbox,
            color: 'text-blue-600',
            bg: 'bg-blue-50',
            accent: '#2563EB',
          },
          {
            label: 'Threats Detected',
            value: threatCount,
            subtext: 'High / Critical',
            icon: ShieldAlert,
            color: 'text-rose-600',
            bg: 'bg-rose-50',
            accent: '#DC2626',
          },
          {
            label: 'Campaigns',
            value: totalCampaigns,
            subtext: 'Correlated clusters',
            icon: Flag,
            color: 'text-indigo-600',
            bg: 'bg-indigo-50',
            accent: '#4F46E5',
          },
          {
            label: 'Reports Generated',
            value: totalReports,
            subtext: 'Forensic PDF/HTML',
            icon: FileText,
            color: 'text-blue-600',
            bg: 'bg-blue-50',
            accent: '#2563EB',
          },
        ].map((metric) => {
          const Icon = metric.icon;
          return (
            <div
              key={metric.label}
              style={{ '--kpi-accent': metric.accent } as React.CSSProperties}
              className="kpi-card p-4 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[11px] font-semibold text-text-muted uppercase tracking-wider truncate">
                  {metric.label}
                </span>
                <div className={`w-8 h-8 rounded-lg ${metric.bg} ${metric.color} flex items-center justify-center shrink-0 transition-transform group-hover:scale-110`}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>
              <div>
                <div className="text-2xl font-extrabold text-text-primary tabular-nums tracking-tight">
                  {loading ? (
                    <span className="inline-block w-12 h-6 rounded shimmer-bg" />
                  ) : (
                    metric.value
                  )}
                </div>
                <div className="text-[10.5px] text-text-muted mt-1 truncate">
                  {metric.subtext}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Placement: 8-col Recent Activity & 4-col Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Recent Threats table (8 columns) */}
        <div className="lg:col-span-8 rounded-xl bg-workspace-card border border-workspace-border shadow-xs overflow-hidden flex flex-col">
          <div className="px-5 py-3.5 border-b border-workspace-border flex items-center justify-between gap-3 bg-workspace-header/50">
            <div className="flex items-center gap-2.5">
              <h2 className="text-sm font-bold text-text-primary tracking-tight">Recent Threat Ingestion</h2>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-brand-soft text-brand border border-brand/20">
                {totalPhishing} threats
              </span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Filter recent..."
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                className="px-2.5 py-1 text-xs bg-workspace-card border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-brand/20 transition-all w-36 sm:w-48"
              />
            </div>
          </div>

          {loading ? (
            <div className="p-12 text-center text-sm text-text-muted flex flex-col items-center justify-center gap-2">
              <div className="w-6 h-6 border-2 border-brand border-t-transparent rounded-full animate-spin" />
              <span>Hydrating telemetry feed…</span>
            </div>
          ) : filteredRecent.length === 0 ? (
            <div className="p-12 text-center text-sm text-text-muted">
              No phishing or threat emails match your filter.
            </div>
          ) : (
            <div className="overflow-x-auto flex-1">
              <table className="w-full text-left text-xs">
                <thead className="bg-workspace-header text-text-muted uppercase text-[10.5px] tracking-wider font-semibold border-b border-workspace-border select-none">
                  <tr>
                    <th className="px-5 py-2.5">Subject & Sender</th>
                    <th className="px-3 py-2.5">Threat Level</th>
                    <th className="px-3 py-2.5 text-right">Ingested</th>
                    <th className="pr-5 pl-2 py-2.5 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-workspace-border">
                  {filteredRecent.map((email) => (
                    <tr
                      key={email.id}
                      onClick={() => onSelectEmail(email.id)}
                      className="hover:bg-brand-soft/25 cursor-pointer transition-colors group select-none"
                    >
                      <td className="px-5 py-3 min-w-0 max-w-sm">
                        <div className="font-semibold text-text-primary group-hover:text-brand transition-colors truncate">
                          {email.subject || email.original_filename || 'Untitled email'}
                        </div>
                        <div className="text-[11px] text-text-muted truncate mt-0.5">
                          {email.sender_address || 'Unknown sender'}
                        </div>
                      </td>
                      <td className="px-3 py-3 whitespace-nowrap">
                        <StatusBadge
                          type="severity"
                          value={severityForQualification(email.qualification_status)}
                          size="sm"
                        />
                      </td>
                      <td className="px-3 py-3 text-right text-[11px] text-text-muted whitespace-nowrap tabular-nums">
                        {timeAgo(email.created_at)}
                      </td>
                      <td className="pr-5 pl-2 py-3 text-right">
                        <div className="inline-flex items-center justify-center w-6 h-6 rounded-md group-hover:bg-brand/10 text-text-muted group-hover:text-brand transition-all">
                          <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Stack: Threat Distribution + Campaigns (4 columns) */}
        <div className="lg:col-span-4 space-y-5">
          {/* Threat Distribution Card */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-xs p-5 hover-lift">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-text-primary tracking-tight">Threat Severity Distribution</h2>
              <span className="text-[11px] text-text-muted font-medium">Verdict Breakdown</span>
            </div>

            {loading ? (
              <div className="space-y-3 py-2">
                {[1, 2, 3].map((n) => (
                  <div key={n} className="h-6 rounded shimmer-bg" />
                ))}
              </div>
            ) : distribution.length === 0 ? (
              <div className="text-xs text-text-muted py-4 text-center">No classified threats recorded yet.</div>
            ) : (
              <div className="space-y-3.5">
                {distribution.map((d) => {
                  const pct = Math.round((d.count / totalPhishing) * 100) || 0;
                  const sev = severityForQualification(d.status);
                  const barColor =
                    sev === 'critical'
                      ? 'bg-rose-500'
                      : sev === 'high'
                        ? 'bg-amber-500'
                        : sev === 'medium'
                          ? 'bg-purple-500'
                          : 'bg-blue-500';

                  return (
                    <div key={d.status} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-text-secondary font-medium text-[11.5px]">
                          {d.status.replace(/_/g, ' ')}
                        </span>
                        <div className="flex items-center gap-1.5 tabular-nums">
                          <span className="font-bold text-text-primary">{d.count}</span>
                          <span className="text-[10px] text-text-muted">({pct}%)</span>
                        </div>
                      </div>
                      <div className="h-2 rounded-full bg-workspace overflow-hidden border border-workspace-border/50">
                        <div
                          className={`h-full rounded-full ${barColor} transition-all duration-700 ease-out`}
                          style={{ width: `${(d.count / maxCount) * 100}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Active Campaigns Card */}
          {activeCampaigns.length > 0 && (
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-xs p-5 hover-lift">
              <div className="flex items-center justify-between mb-3.5">
                <div className="flex items-center gap-2">
                  <Flag className="w-4 h-4 text-amber-600" />
                  <h3 className="text-sm font-bold text-text-primary tracking-tight">Active Campaigns</h3>
                </div>
                <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200">
                  {totalCampaigns} Active
                </span>
              </div>
              <div className="space-y-2">
                {activeCampaigns.slice(0, 4).map((c) => (
                  <div
                    key={c.id}
                    className="p-2.5 rounded-lg border border-workspace-border bg-workspace/50 hover:bg-workspace hover:border-amber-300/60 transition-all flex items-center justify-between gap-2"
                  >
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-text-primary truncate">
                        {c.campaign_name || 'Unnamed Campaign Cluster'}
                      </div>
                      <div className="text-[10.5px] text-text-muted mt-0.5">
                        Cluster ID: <span className="font-mono">{c.id.slice(0, 8)}…</span>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-100/80 text-amber-800 shrink-0 tabular-nums">
                      {c.member_count} emails
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DashboardView;
