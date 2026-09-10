import React, { useState, useEffect, useMemo } from 'react';
import {
  History,
  Search,
  RefreshCw,
  ArrowRight,
  FileCheck,
  X,
} from 'lucide-react';
import { listEmails, EmailDetailResponse } from '../../services/api';
import { StatusBadge } from '../common/StatusBadge';

interface AnalysisHistoryViewProps {
  onSelectEmail: (emailId: string) => void;
  onOpenReport?: (emailId: string) => void;
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

export const AnalysisHistoryView: React.FC<AnalysisHistoryViewProps> = ({ onSelectEmail, onOpenReport }) => {
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
      const res = await listEmails(0, 100);
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
          <div className="p-10 text-center text-sm text-text-muted">Loading analysis history…</div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center">
            {emails.length === 0 ? (
              <>
                <p className="text-sm font-semibold text-text-primary">No emails analyzed yet</p>
                <p className="text-sm text-text-muted mt-1">
                  Upload a .eml file from Analyze Email to build your analysis history.
                </p>
              </>
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
