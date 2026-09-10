import React, { useEffect, useState } from 'react';
import { UploadCloud, Network, FileText, ShieldAlert, Inbox, ArrowRight } from 'lucide-react';
import { BrandLogo } from '../common/BrandLogo';
import { StatusBadge } from '../common/StatusBadge';
import {
  listEmails,
  listCampaigns,
  listReports,
  EmailDetailResponse,
  CampaignListItemResponse,
} from '../../services/api';

interface DashboardViewProps {
  onAnalyze: () => void;
  onExploreGraph: () => void;
  onSelectEmail: (emailId: string) => void;
}

const THREAT_STATUSES = new Set(['SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS', 'CAMPAIGN_RELATED']);

const severityForQualification = (status: string): 'critical' | 'high' | 'medium' | 'low' | 'safe' => {
  switch (status) {
    case 'MALICIOUS':
      return 'critical';
    case 'HIGH_RISK':
      return 'high';
    case 'SUSPICIOUS':
    case 'CAMPAIGN_RELATED':
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

export const DashboardView: React.FC<DashboardViewProps> = ({ onAnalyze, onExploreGraph, onSelectEmail }) => {
  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [totalEmails, setTotalEmails] = useState<number>(0);
  const [campaigns, setCampaigns] = useState<CampaignListItemResponse[]>([]);
  const [totalReports, setTotalReports] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const [emailPage, campaignList, reportPage] = await Promise.all([
          listEmails(0, 100),
          listCampaigns(undefined, 0, 5),
          listReports(undefined, undefined, 1),
        ]);
        if (cancelled) return;
        setEmails(emailPage.items);
        setTotalEmails(emailPage.total);
        setCampaigns(campaignList);
        setTotalReports(reportPage.total_reports);
      } catch (err) {
        if (!cancelled) setError('Could not load dashboard data from the backend.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const threatCount = emails.filter((e) => THREAT_STATUSES.has(e.qualification_status)).length;
  const criticalCount = emails.filter((e) => e.qualification_status === 'MALICIOUS').length;
  const recent = emails.slice(0, 8);

  const distribution = ['MALICIOUS', 'HIGH_RISK', 'SUSPICIOUS', 'CAMPAIGN_RELATED', 'QUALIFIED_FOR_INVESTIGATION', 'NORMAL']
    .map((status) => ({
      status,
      count: emails.filter((e) => e.qualification_status === status).length,
    }))
    .filter((d) => d.count > 0);
  const maxCount = Math.max(1, ...distribution.map((d) => d.count));

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div className="rounded-2xl bg-navy-sidebar text-white p-8 border border-navy-border relative overflow-hidden">
        <div className="relative z-10 flex flex-col lg:flex-row items-center gap-8">
          <div className="max-w-2xl">
            <span className="inline-block px-2.5 py-0.5 rounded-full text-[11px] font-semibold tracking-wide bg-sky-500/15 text-sky-300 border border-sky-400/30">
              Intelligence Behind Every Inbox
            </span>
            <h1 className="mt-3 text-3xl font-extrabold tracking-tight text-white">
              MailinteL Forensic Intelligence
            </h1>
            <p className="mt-3 text-sm text-slate-300 leading-relaxed">
              Upload a suspicious .eml file to reconstruct its transmission path, verify authentication,
              enrich infrastructure signals, and correlate it against known campaigns.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <button
                onClick={onAnalyze}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-brand text-white font-semibold text-sm hover:bg-brand-hover transition-colors"
              >
                <UploadCloud className="w-4 h-4" />
                Analyze Suspicious .eml
              </button>
              <button
                onClick={onExploreGraph}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-navy-elevated text-slate-200 border border-navy-border font-medium text-sm hover:bg-navy-deep hover:text-white transition-colors"
              >
                <Network className="w-4 h-4" />
                Explore Investigation Graph
              </button>
            </div>
          </div>
          <div className="shrink-0">
            <BrandLogo variant="hero" surface="dark" showTagline={false} />
          </div>
        </div>
      </div>

      {error && (
        <div className="px-4 py-2.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-sm text-severity-high">
          {error}
        </div>
      )}

      {/* What is happening / how serious / what needs attention — Design.md §12 */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Emails Analyzed', value: totalEmails, icon: Inbox, color: 'text-brand', bg: 'bg-brand-soft' },
          { label: 'Threats Detected', value: threatCount, icon: ShieldAlert, color: 'text-severity-high', bg: 'bg-severity-high-soft' },
          { label: 'Critical', value: criticalCount, icon: ShieldAlert, color: 'text-severity-critical', bg: 'bg-severity-critical-soft' },
          { label: 'Reports Generated', value: totalReports, icon: FileText, color: 'text-indigo-600', bg: 'bg-indigo-50' },
        ].map((metric) => {
          const Icon = metric.icon;
          return (
            <div key={metric.label} className="p-4 rounded-xl bg-workspace-card border border-workspace-border shadow-sm flex items-center gap-3.5">
              <div className={`w-10 h-10 rounded-xl ${metric.bg} ${metric.color} flex items-center justify-center shrink-0`}>
                <Icon className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <div className="text-[11px] text-text-muted font-medium truncate">{metric.label}</div>
                <div className="text-xl font-bold text-text-primary">{loading ? '—' : metric.value}</div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Recent Threats table */}
        <div className="lg:col-span-2 rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
          <div className="px-5 py-4 border-b border-workspace-border flex items-center justify-between">
            <h2 className="text-sm font-bold text-text-primary">Recent Activity</h2>
            <span className="text-xs text-text-muted">{totalEmails} total</span>
          </div>
          {loading ? (
            <div className="p-8 text-center text-sm text-text-muted">Loading…</div>
          ) : recent.length === 0 ? (
            <div className="p-8 text-center text-sm text-text-muted">
              No emails analyzed yet. Upload a .eml file to get started.
            </div>
          ) : (
            <table className="w-full text-sm">
              <tbody>
                {recent.map((email) => (
                  <tr
                    key={email.id}
                    onClick={() => onSelectEmail(email.id)}
                    className="border-b border-workspace-border last:border-0 hover:bg-workspace cursor-pointer transition-colors"
                  >
                    <td className="px-5 py-3 min-w-0">
                      <div className="font-medium text-text-primary truncate max-w-md">
                        {email.subject || email.original_filename || 'Untitled email'}
                      </div>
                      <div className="text-xs text-text-muted truncate max-w-md">
                        {email.sender_address || 'Unknown sender'}
                      </div>
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <StatusBadge type="severity" value={severityForQualification(email.qualification_status)} size="sm" />
                    </td>
                    <td className="px-3 py-3 text-right text-xs text-text-muted whitespace-nowrap">
                      {timeAgo(email.created_at)}
                    </td>
                    <td className="pl-1 pr-4 py-3">
                      <ArrowRight className="w-3.5 h-3.5 text-text-muted" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Threat Distribution */}
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
          <h2 className="text-sm font-bold text-text-primary mb-4">Threat Distribution</h2>
          {loading ? (
            <div className="text-sm text-text-muted">Loading…</div>
          ) : distribution.length === 0 ? (
            <div className="text-sm text-text-muted">No qualified emails yet.</div>
          ) : (
            <div className="space-y-3">
              {distribution.map((d) => (
                <div key={d.status}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-text-secondary">{d.status.replace(/_/g, ' ')}</span>
                    <span className="font-semibold text-text-primary">{d.count}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-workspace overflow-hidden">
                    <div
                      className={`h-full rounded-full bg-severity-${severityForQualification(d.status) === 'safe' ? 'safe' : severityForQualification(d.status)}`}
                      style={{ width: `${(d.count / maxCount) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}

          {campaigns.length > 0 && (
            <>
              <h3 className="text-xs font-bold text-text-primary mt-5 mb-2 uppercase tracking-wide">Active Campaigns</h3>
              <div className="space-y-2">
                {campaigns.slice(0, 4).map((c) => (
                  <div key={c.id} className="flex items-center justify-between text-xs">
                    <span className="text-text-secondary truncate">{c.campaign_name || 'Unnamed campaign'}</span>
                    <span className="text-text-muted">{c.member_count} emails</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default DashboardView;
