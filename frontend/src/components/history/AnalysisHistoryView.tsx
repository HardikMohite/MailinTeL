import React, { useState, useEffect, useMemo } from 'react';
import {
  History,
  Search,
  RefreshCw,
  ArrowRight,
  FileCheck,
  X,
  Mail,
  UploadCloud,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { listEmails, EmailDetailResponse } from '../../services/api';
import { StatusBadge } from '../common/StatusBadge';

interface AnalysisHistoryViewProps {
  onSelectEmail: (emailId: string) => void;
  onOpenReport?: (emailId: string) => void;
  onNavigateToAnalyze?: () => void;
}

type QualificationFilter =
  | 'ALL'
  | 'MALICIOUS'
  | 'HIGH_RISK'
  | 'SUSPICIOUS'
  | 'CAMPAIGN_RELATED'
  | 'QUALIFIED_FOR_INVESTIGATION'
  | 'NORMAL';

const FILTERS: QualificationFilter[] = [
  'ALL',
  'MALICIOUS',
  'HIGH_RISK',
  'SUSPICIOUS',
  'CAMPAIGN_RELATED',
  'QUALIFIED_FOR_INVESTIGATION',
  'NORMAL',
];

// Mirrors DashboardView's mapping so severity presentation is consistent
// across the app (Design.md §4 — colour must match meaning everywhere).
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

export const AnalysisHistoryView: React.FC<AnalysisHistoryViewProps> = ({
  onSelectEmail,
  onOpenReport,
  onNavigateToAnalyze,
}) => {
  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<QualificationFilter>('ALL');

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listEmails(0, 50);
      setEmails(res.items || []);
      setTotal(res.total ?? (res.items || []).length);
    } catch (err) {
      setError('Could not load analysis history from the backend.');
    } finally {
      setLoading(false);
    }
  };

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return emails.filter((em) => {
      const matchesSearch =
        !q ||
        (em.subject && em.subject.toLowerCase().includes(q)) ||
        (em.sender_address && em.sender_address.toLowerCase().includes(q)) ||
        (em.sha256_hash && em.sha256_hash.toLowerCase().includes(q)) ||
        em.id.toLowerCase().includes(q);

      const matchesFilter = statusFilter === 'ALL' || em.qualification_status === statusFilter;

      return matchesSearch && matchesFilter;
    });
  }, [emails, searchQuery, statusFilter]);

  const hasActiveFilters = searchQuery.trim().length > 0 || statusFilter !== 'ALL';
  const clearFilters = () => {
    setSearchQuery('');
    setStatusFilter('ALL');
  };

  return (
    <div className="space-y-6">
      {/* Page Title + Description + Primary Action — Design.md §7 */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <History className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary tracking-tight">Analysis History</h1>
            <p className="text-sm text-text-muted mt-0.5">
              Browse and filter every email analyzed by MailinteL.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative w-64">
            <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search subject, sender, hash…"
              className="w-full pl-9 pr-3 py-2 text-sm bg-workspace-card border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand"
            />
          </div>
          <button
            onClick={loadHistory}
            className="p-2 rounded-lg bg-workspace-card text-text-muted hover:text-brand border border-workspace-border transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="px-4 py-2.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-sm text-severity-high">
          {error}
        </div>
      )}

      {/* Filter row */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-text-muted uppercase tracking-wide mr-1">Qualification</span>
          {FILTERS.map((cat) => (
            <button
              key={cat}
              onClick={() => setStatusFilter(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                statusFilter === cat
                  ? 'bg-brand text-white'
                  : 'bg-workspace text-text-secondary hover:text-text-primary border border-workspace-border'
              }`}
            >
              {cat.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-3">
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="inline-flex items-center gap-1 text-xs font-medium text-brand hover:text-brand-hover transition-colors"
            >
              <X className="w-3 h-3" />
              Clear filters
            </button>
          )}
          <span className="text-xs text-text-muted">
            Showing {filtered.length} of {total}
          </span>
        </div>
      </div>

      {/* History Table — Design.md §38 (subject, sender, qualification, analyzed date) */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
        {loading ? (
          // Skeleton table — same column layout as the real table so content
          // appears to materialise in-place rather than jumping in from blank.
          <div className="overflow-x-auto" aria-busy="true" aria-label="Loading analysis history">
            <table className="w-full text-left text-sm">
              <thead className="bg-workspace-header text-text-muted uppercase text-[11px] border-b border-workspace-border">
                <tr>
                  <th className="px-5 py-3 font-semibold">Subject &amp; Sender</th>
                  <th className="px-3 py-3 font-semibold">Qualification</th>
                  <th className="px-3 py-3 font-semibold">Analyzed</th>
                  <th className="px-3 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-workspace-border">
                {Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="px-5 py-4">
                      <div className="h-3.5 bg-workspace-secondary rounded-md w-3/4 mb-2" />
                      <div className="h-2.5 bg-workspace-secondary rounded-md w-1/2 opacity-60" />
                    </td>
                    <td className="px-3 py-4">
                      <div className="h-5 bg-workspace-secondary rounded-lg w-20" />
                    </td>
                    <td className="px-3 py-4">
                      <div className="h-3 bg-workspace-secondary rounded-md w-28" />
                    </td>
                    <td className="px-3 py-4">
                      <div className="flex items-center justify-end gap-2">
                        <div className="h-7 bg-workspace-secondary rounded-lg w-24" />
                        <div className="h-7 bg-workspace-secondary rounded-lg w-16" />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-8 sm:p-12 text-center">
            {emails.length === 0 ? (
              <div className="py-6 px-4 max-w-lg mx-auto flex flex-col items-center justify-center text-center">
                {/* Gmail-style Stacked Email Cards — Theme-aligned Design */}
                <div className="relative w-full max-w-md h-56 mx-auto mb-6 flex items-center justify-center select-none">
                  {/* Soft Brand Glow */}
                  <div className="absolute inset-0 bg-brand-soft/80 blur-2xl rounded-full" />

                  {/* Card 3 (Bottom Layer) */}
                  <div className="absolute -top-3.5 w-[86%] bg-workspace-secondary border border-workspace-border rounded-2xl p-3.5 shadow-sm -rotate-6 translate-y-3 opacity-70">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-lg bg-severity-critical-soft text-severity-critical border border-severity-critical/20 flex items-center justify-center font-bold text-xs shrink-0">
                        <Mail className="w-3.5 h-3.5" />
                      </div>
                      <div className="flex-1 text-left min-w-0">
                        <div className="text-xs font-semibold text-text-primary truncate">security-alert@external-auth.com</div>
                        <div className="text-[10px] text-text-muted truncate">Urgent: Verify credential authorization</div>
                      </div>
                      <span className="text-[9px] font-bold px-2 py-0.5 rounded-md bg-severity-critical-soft text-severity-critical border border-severity-critical/30 shrink-0">
                        MALICIOUS
                      </span>
                    </div>
                  </div>

                  {/* Card 2 (Middle Layer) */}
                  <div className="absolute -top-1.5 w-[92%] bg-brand-soft/70 border border-brand/20 rounded-2xl p-3.5 shadow-md rotate-3 translate-y-1.5 opacity-90">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-lg bg-severity-high-soft text-severity-high border border-severity-high/20 flex items-center justify-center font-bold text-xs shrink-0">
                        <Mail className="w-3.5 h-3.5" />
                      </div>
                      <div className="flex-1 text-left min-w-0">
                        <div className="text-xs font-semibold text-text-primary truncate">payroll-update@finance-dept.org</div>
                        <div className="text-[10px] text-text-muted truncate">Direct Deposit Voucher &amp; Tax Documents</div>
                      </div>
                      <span className="text-[9px] font-bold px-2 py-0.5 rounded-md bg-severity-high-soft text-severity-high border border-severity-high/30 shrink-0">
                        SUSPICIOUS
                      </span>
                    </div>
                  </div>

                  {/* Card 1 (Top Front Main Card) */}
                  <div className="relative w-full bg-workspace-card border border-workspace-border rounded-2xl p-4 shadow-xl shadow-brand/5 transition-transform hover:scale-[1.01] duration-200">
                    {/* Header Line */}
                    <div className="flex items-center justify-between pb-3 border-b border-workspace-border gap-2">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="w-9 h-9 rounded-xl bg-brand text-white flex items-center justify-center shadow-md shadow-brand/25 font-bold shrink-0">
                          <Mail className="w-5 h-5" />
                        </div>
                        <div className="text-left min-w-0">
                          <div className="text-sm font-bold text-text-primary flex items-center gap-2 flex-wrap">
                            <span>Gmail &amp; EML Stack</span>
                            <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-severity-safe bg-severity-safe-soft px-2 py-0.5 rounded-full border border-severity-safe/30 whitespace-nowrap shrink-0">
                              <ShieldCheck className="w-3 h-3 shrink-0" /> Engine Ready
                            </span>
                          </div>
                          <div className="text-xs text-text-muted truncate">MailinteL Automated Forensic Ingestion</div>
                        </div>
                      </div>
                      <span className="text-xs font-semibold text-text-secondary bg-workspace-secondary px-2.5 py-1 rounded-lg border border-workspace-border whitespace-nowrap shrink-0">
                        0 Analyzed Emails
                      </span>
                    </div>

                    {/* Mail Body Preview */}
                    <div className="mt-3.5 text-left space-y-1.5">
                      <div className="text-xs font-semibold text-brand flex items-center gap-1.5">
                        <Sparkles className="w-4 h-4 text-severity-high shrink-0" />
                        No emails in analysis queue
                      </div>
                      <p className="text-xs text-text-secondary leading-relaxed">
                        Upload suspicious .eml files or headers to run header hop analysis, domain reputation, and AI threat scoring.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Empty State Text & Actions */}
                <h3 className="text-lg font-bold text-text-primary tracking-tight">No emails analyzed yet</h3>
                <p className="text-sm text-text-muted mt-1 max-w-md leading-relaxed">
                  Your forensic investigation queue is currently empty. Upload your first email to begin building campaign history.
                </p>

                {onNavigateToAnalyze && (
                  <button
                    onClick={onNavigateToAnalyze}
                    className="mt-5 inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand text-white text-sm font-semibold shadow-lg shadow-brand/25 hover:bg-brand-hover hover:shadow-brand/40 transition-all transform active:scale-95"
                  >
                    <UploadCloud className="w-4 h-4" />
                    Analyze Email
                    <ArrowRight className="w-4 h-4" />
                  </button>
                )}
              </div>
            ) : (
              <>
                <p className="text-sm font-semibold text-text-primary">No results for this filter</p>
                <p className="text-sm text-text-muted mt-1">
                  Try a different search term or qualification filter.
                </p>
                <button
                  onClick={clearFilters}
                  className="mt-4 inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-workspace border border-workspace-border text-sm font-medium text-text-primary hover:bg-workspace-secondary transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                  Clear filters
                </button>
              </>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-workspace-header text-text-muted uppercase text-[11px] border-b border-workspace-border">
                <tr>
                  <th className="px-5 py-3 font-semibold">Subject &amp; Sender</th>
                  <th className="px-3 py-3 font-semibold">Qualification</th>
                  <th className="px-3 py-3 font-semibold">Analyzed</th>
                  <th className="px-3 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-workspace-border">
                {filtered.map((em) => (
                  <tr key={em.id} className="hover:bg-workspace/60 transition-colors">
                    <td className="px-5 py-3.5 min-w-0 max-w-md">
                      <div className="font-medium text-text-primary truncate">{em.subject || 'No subject'}</div>
                      <div className="text-xs text-text-muted truncate mt-0.5">
                        {em.sender_address || 'Unknown sender'}
                      </div>
                    </td>
                    <td className="px-3 py-3.5 whitespace-nowrap">
                      {em.analysis_status === 'FAILED' ? (
                        <StatusBadge type="severity" value="high" label="ANALYSIS FAILED" size="sm" />
                      ) : em.analysis_status !== 'COMPLETED' ? (
                        <StatusBadge type="state" value="processing" label={em.analysis_status} size="sm" />
                      ) : (
                        <StatusBadge type="severity" value={severityForQualification(em.qualification_status)} label={em.qualification_status.replace(/_/g, ' ')} size="sm" />
                      )}
                    </td>
                    <td className="px-3 py-3.5 text-text-secondary whitespace-nowrap">
                      {new Date(em.created_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-3.5">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onSelectEmail(em.id)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors"
                        >
                          Workspace
                          <ArrowRight className="w-3 h-3" />
                        </button>
                        {onOpenReport && (
                          <button
                            onClick={() => onOpenReport(em.id)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-workspace border border-workspace-border text-text-primary text-xs font-medium hover:bg-workspace-secondary transition-colors"
                          >
                            <FileCheck className="w-3 h-3" />
                            Report
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalysisHistoryView;
