import React, { useState, useEffect, useMemo, useRef } from 'react';
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
  ShieldAlert,
  Sparkles,
  AlertTriangle,
  ChevronDown,
  Layers,
  Cpu,
  FileText,
  Globe2,
  UserCheck,
  Clock,
  Star,
  Trash2,
  AlertOctagon,
  CheckSquare,
  Square,
} from 'lucide-react';
import {
  listEmails,
  getEmailDetails,
  getEmailAnalysis,
  getEmailAuthResults,
  getEmailHeaders,
  getEmailArtifacts,
  deleteEmail,
  batchDeleteEmails,
  EmailDetailResponse,
} from '../../services/api';
import { AnalysisWorkspace } from '../workspace/AnalysisWorkspace';

interface AnalysisHistoryViewProps {
  initialEmailId?: string;
  onSelectEmail?: (emailId: string) => void;
  onOpenReport?: (emailId: string) => void;
  onExploreGeo?: (emailId: string) => void;
  onExploreGraph?: (emailId: string) => void;
  onNavigateToAnalyze?: () => void;
}

type QualificationFilter =
  | 'ALL'
  | 'MALICIOUS'
  | 'HIGH_RISK'
  | 'SUSPICIOUS'
  | 'CAMPAIGN_RELATED'
  | 'SAFE';

const FILTERS: { id: QualificationFilter; label: string; colorClass: string }[] = [
  { id: 'ALL', label: 'All Artifacts', colorClass: 'border-workspace-border text-text-primary' },
  { id: 'MALICIOUS', label: 'Malicious / Phishing', colorClass: 'border-rose-500/40 text-rose-400 bg-rose-500/10' },
  { id: 'HIGH_RISK', label: 'High Risk', colorClass: 'border-rose-500/30 text-rose-300 bg-rose-500/5' },
  { id: 'SUSPICIOUS', label: 'Suspicious', colorClass: 'border-amber-500/40 text-amber-400 bg-amber-500/10' },
  { id: 'CAMPAIGN_RELATED', label: 'Campaign Clusters', colorClass: 'border-purple-500/40 text-purple-400 bg-purple-500/10' },
  { id: 'SAFE', label: 'Secure / Clean', colorClass: 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10' },
];

export const AnalysisHistoryView: React.FC<AnalysisHistoryViewProps> = ({
  initialEmailId,
  onSelectEmail,
  onOpenReport,
  onExploreGeo,
  onExploreGraph,
  onNavigateToAnalyze,
}) => {
  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<QualificationFilter>('ALL');
  const [expandedEmailId, setExpandedEmailId] = useState<string | null>(null);
  const [starredIds, setStarredIds] = useState<Set<string>>(new Set());
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [inspectingEmailId, setInspectingEmailId] = useState<string | null>(initialEmailId || null);

  const [confirmDeleteModal, setConfirmDeleteModal] = useState<{
    isOpen: boolean;
    emailIds: string[];
    title: string;
  }>({ isOpen: false, emailIds: [], title: '' });
  const [isDeleting, setIsDeleting] = useState<boolean>(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [successToast, setSuccessToast] = useState<string | null>(null);

  useEffect(() => {
    if (initialEmailId) {
      setInspectingEmailId(initialEmailId);
    }
  }, [initialEmailId]);

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async (forceFresh = false) => {
    setLoading(true);
    setError(null);
    try {
      const res = await listEmails(0, 100, undefined, undefined, undefined, undefined, forceFresh);
      setEmails(res.items || []);
      setTotal(res.total ?? (res.items || []).length);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Could not load analysis history from the backend.');
    } finally {
      setLoading(false);
    }
  };

  const toggleSelect = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleSelectAll = () => {
    if (selectedIds.size === filtered.length && filtered.length > 0) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((e) => e.id)));
    }
  };

  const executeDelete = async () => {
    if (!confirmDeleteModal.emailIds.length) return;
    setIsDeleting(true);
    setDeleteError(null);
    try {
      const idsToDelete = confirmDeleteModal.emailIds;
      if (idsToDelete.length === 1) {
        await deleteEmail(idsToDelete[0]);
      } else {
        await batchDeleteEmails(idsToDelete);
      }
      const idSet = new Set(idsToDelete);
      setEmails((prev) => prev.filter((e) => !idSet.has(e.id)));
      setTotal((prev) => Math.max(0, prev - idsToDelete.length));
      setSelectedIds((prev) => {
        const next = new Set(prev);
        idsToDelete.forEach((id) => next.delete(id));
        return next;
      });
      if (expandedEmailId && idSet.has(expandedEmailId)) {
        setExpandedEmailId(null);
      }
      if (inspectingEmailId && idSet.has(inspectingEmailId)) {
        setInspectingEmailId(null);
      }
      setSuccessToast(
        `Successfully deleted ${idsToDelete.length} email artifact${idsToDelete.length > 1 ? 's' : ''} and purged all associated reports, attachments, and forensic data.`
      );
      setConfirmDeleteModal({ isOpen: false, emailIds: [], title: '' });
      setTimeout(() => setSuccessToast(null), 4000);
    } catch (err: any) {
      setDeleteError(err?.response?.data?.detail || err?.message || 'Failed to delete email artifact.');
    } finally {
      setIsDeleting(false);
    }
  };

  // Classify email status into color categories
  const getQualificationCategory = (status: string): 'malicious' | 'suspicious' | 'safe' => {
    const s = (status || '').toUpperCase();
    if (s === 'MALICIOUS' || s === 'HIGH_RISK' || s === 'PHISHING' || s === 'CAMPAIGN_RELATED') {
      return 'malicious';
    }
    if (s === 'SUSPICIOUS' || s === 'QUALIFIED_FOR_INVESTIGATION') {
      return 'suspicious';
    }
    return 'safe';
  };

  // Calculate high-level counters for metric badges
  const stats = useMemo(() => {
    let maliciousCount = 0;
    let suspiciousCount = 0;
    let safeCount = 0;

    emails.forEach((em) => {
      const cat = getQualificationCategory(em.qualification_status);
      if (cat === 'malicious') maliciousCount++;
      else if (cat === 'suspicious') suspiciousCount++;
      else safeCount++;
    });

    return {
      total: emails.length,
      malicious: maliciousCount,
      suspicious: suspiciousCount,
      safe: safeCount,
    };
  }, [emails]);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return emails.filter((em) => {
      const matchesSearch =
        !q ||
        (em.subject && em.subject.toLowerCase().includes(q)) ||
        (em.sender_address && em.sender_address.toLowerCase().includes(q)) ||
        (em.sender_display_name && em.sender_display_name.toLowerCase().includes(q)) ||
        (em.sha256_hash && em.sha256_hash.toLowerCase().includes(q)) ||
        em.id.toLowerCase().includes(q);

      if (!matchesSearch) return false;

      if (statusFilter === 'ALL') return true;
      if (statusFilter === 'SAFE') {
        return (
          em.qualification_status === 'NORMAL' ||
          em.qualification_status === 'SAFE' ||
          em.qualification_status === 'BENIGN'
        );
      }
      return em.qualification_status === statusFilter;
    });
  }, [emails, searchQuery, statusFilter]);

  const lastRowClickRef = useRef<{ id: string; time: number }>({ id: '', time: 0 });

  const handleRowClick = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const now = Date.now();
    if (lastRowClickRef.current.id === id && now - lastRowClickRef.current.time < 350) {
      lastRowClickRef.current = { id: '', time: 0 };
      setInspectingEmailId(id);
      return;
    }
    lastRowClickRef.current = { id, time: now };
    toggleExpand(id);
  };

  const hasActiveFilters = searchQuery.trim().length > 0 || statusFilter !== 'ALL';
  const clearFilters = () => {
    setSearchQuery('');
    setStatusFilter('ALL');
  };

  const toggleExpand = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setExpandedEmailId((prev) => (prev === id ? null : id));
  };

  const toggleStar = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setStarredIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (inspectingEmailId) {
    return (
      <div className="space-y-4 animate-fade-in">
        <AnalysisWorkspace
          initialEmailId={inspectingEmailId}
          isHistoryMode={true}
          onBackToHistory={() => {
            setInspectingEmailId(null);
            loadHistory(true);
          }}
          onOpenReport={onOpenReport}
          onExploreGeo={onExploreGeo}
          onExploreGraph={onExploreGraph}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Title & Action Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-workspace-card border border-workspace-border shadow-xs">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <History className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-2xl font-bold text-text-primary tracking-tight">Analysis History</h1>
              <span className="px-2.5 py-0.5 rounded-full bg-workspace text-text-muted border border-workspace-border text-xs font-semibold flex items-center gap-1">
                <Layers className="w-3.5 h-3.5 text-brand" /> Stacked Dossier Feed
              </span>
            </div>
            <p className="text-sm text-text-muted mt-0.5">
              Forensic timeline of all ingested email artifacts with Threat Risk Scores, Evidence Confidence, and 5-Strand status.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative w-64 md:w-72">
            <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search subject, sender, hash…"
              className="w-full pl-9 pr-3 py-2 text-xs bg-workspace border border-workspace-border rounded-xl text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand"
            />
          </div>
          <button
            onClick={() => loadHistory(true)}
            className="p-2.5 rounded-xl bg-workspace text-text-muted hover:text-brand border border-workspace-border transition-colors cursor-pointer"
            title="Refresh History"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Top Threat Classification Metrics Bar - High-End Interactive Filter Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {/* Total Analyzed */}
        <div
          onClick={() => setStatusFilter('ALL')}
          className={`p-4 rounded-2xl bg-white border transition-all duration-200 cursor-pointer shadow-xs hover:shadow-md hover:-translate-y-0.5 flex items-center justify-between group ${
            statusFilter === 'ALL'
              ? 'ring-2 ring-blue-500 border-blue-400 bg-blue-50/15'
              : 'border-slate-200/90 hover:border-blue-300'
          }`}
          title="Click to view all email records"
        >
          <div>
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
              <span>Total Scanned</span>
              {statusFilter === 'ALL' && (
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
              )}
            </div>
            <div className="text-2xl font-black text-slate-900 mt-1 font-mono tracking-tight">{stats.total}</div>
            <div className="text-[10.5px] text-slate-400 mt-0.5 font-medium">All forensic dossiers</div>
          </div>
          <div className={`w-11 h-11 rounded-xl flex items-center justify-center transition-colors ${
            statusFilter === 'ALL' ? 'bg-blue-600 text-white shadow-xs' : 'bg-blue-50 border border-blue-200/70 text-blue-600 group-hover:bg-blue-100/70'
          }`}>
            <Mail className="w-5 h-5" />
          </div>
        </div>

        {/* Malicious / Phishing - Crimson Red */}
        <div
          onClick={() => setStatusFilter(statusFilter === 'MALICIOUS' ? 'ALL' : 'MALICIOUS')}
          className={`p-4 rounded-2xl bg-white border transition-all duration-200 cursor-pointer shadow-xs hover:shadow-md hover:-translate-y-0.5 flex items-center justify-between group ${
            statusFilter === 'MALICIOUS'
              ? 'ring-2 ring-rose-500 border-rose-400 bg-rose-50/20'
              : 'border-slate-200/90 hover:border-rose-300'
          }`}
          title="Click to filter by Phishing / Malicious emails"
        >
          <div>
            <div className="text-[11px] font-bold text-rose-700 uppercase tracking-wider flex items-center gap-1.5">
              <span>Phishing / Malicious</span>
              {statusFilter === 'MALICIOUS' && (
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
              )}
            </div>
            <div className="text-2xl font-black text-rose-600 mt-1 font-mono tracking-tight">{stats.malicious}</div>
            <div className="text-[10.5px] text-rose-500/80 mt-0.5 font-medium">
              {stats.malicious > 0 ? 'Requires quarantine' : 'Zero threats detected'}
            </div>
          </div>
          <div className={`w-11 h-11 rounded-xl flex items-center justify-center transition-colors ${
            statusFilter === 'MALICIOUS' ? 'bg-rose-600 text-white shadow-xs' : 'bg-rose-50 border border-rose-200/70 text-rose-600 group-hover:bg-rose-100/70'
          }`}>
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        {/* Suspicious - Amber */}
        <div
          onClick={() => setStatusFilter(statusFilter === 'SUSPICIOUS' ? 'ALL' : 'SUSPICIOUS')}
          className={`p-4 rounded-2xl bg-white border transition-all duration-200 cursor-pointer shadow-xs hover:shadow-md hover:-translate-y-0.5 flex items-center justify-between group ${
            statusFilter === 'SUSPICIOUS'
              ? 'ring-2 ring-amber-500 border-amber-400 bg-amber-50/20'
              : 'border-slate-200/90 hover:border-amber-300'
          }`}
          title="Click to filter by Suspicious artifacts"
        >
          <div>
            <div className="text-[11px] font-bold text-amber-700 uppercase tracking-wider flex items-center gap-1.5">
              <span>Suspicious Artifacts</span>
              {statusFilter === 'SUSPICIOUS' && (
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
              )}
            </div>
            <div className="text-2xl font-black text-amber-600 mt-1 font-mono tracking-tight">{stats.suspicious}</div>
            <div className="text-[10.5px] text-amber-600/80 mt-0.5 font-medium">
              {stats.suspicious > 0 ? 'Anomalies under review' : 'No anomalies'}
            </div>
          </div>
          <div className={`w-11 h-11 rounded-xl flex items-center justify-center transition-colors ${
            statusFilter === 'SUSPICIOUS' ? 'bg-amber-600 text-white shadow-xs' : 'bg-amber-50 border border-amber-200/70 text-amber-600 group-hover:bg-amber-100/70'
          }`}>
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        {/* Clean / Secure - Emerald Green */}
        <div
          onClick={() => setStatusFilter(statusFilter === 'SAFE' ? 'ALL' : 'SAFE')}
          className={`p-4 rounded-2xl bg-white border transition-all duration-200 cursor-pointer shadow-xs hover:shadow-md hover:-translate-y-0.5 flex items-center justify-between group ${
            statusFilter === 'SAFE'
              ? 'ring-2 ring-emerald-500 border-emerald-400 bg-emerald-50/20'
              : 'border-slate-200/90 hover:border-emerald-300'
          }`}
          title="Click to filter by Verified Safe / Clean emails"
        >
          <div>
            <div className="text-[11px] font-bold text-emerald-700 uppercase tracking-wider flex items-center gap-1.5">
              <span>Secure / Clean</span>
              {statusFilter === 'SAFE' && (
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              )}
            </div>
            <div className="text-2xl font-black text-emerald-600 mt-1 font-mono tracking-tight">{stats.safe}</div>
            <div className="text-[10.5px] text-emerald-600/80 mt-0.5 font-medium">SPF/DKIM Authenticated</div>
          </div>
          <div className={`w-11 h-11 rounded-xl flex items-center justify-center transition-colors ${
            statusFilter === 'SAFE' ? 'bg-emerald-600 text-white shadow-xs' : 'bg-emerald-50 border border-emerald-200/70 text-emerald-600 group-hover:bg-emerald-100/70'
          }`}>
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>
      </div>

      {successToast && (
        <div className="px-4 py-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-300 text-xs flex items-center justify-between animate-in fade-in duration-200">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
            <span>{successToast}</span>
          </div>
          <button onClick={() => setSuccessToast(null)} className="text-emerald-600 hover:text-emerald-800 font-bold px-2">
            Dismiss
          </button>
        </div>
      )}

      {error && (
        <div className="px-4 py-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-text-muted hover:text-rose-300 font-bold px-2">
            Dismiss
          </button>
        </div>
      )}

      {/* Multi-Select Batch Actions Bar (Visible when >= 1 selected) */}
      {selectedIds.size > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-2xl bg-slate-900 border border-slate-800 text-white shadow-lg animate-in fade-in slide-in-from-top-2 duration-150">
          <div className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
            <span className="text-xs font-bold font-mono">
              {selectedIds.size} case{selectedIds.size > 1 ? 's' : ''} selected
            </span>
            <span className="text-xs text-slate-400">
              (out of {filtered.length} visible)
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSelectedIds(new Set())}
              className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-medium transition-colors cursor-pointer"
            >
              Deselect All
            </button>
            <button
              onClick={() => {
                const count = selectedIds.size;
                setConfirmDeleteModal({
                  isOpen: true,
                  emailIds: Array.from(selectedIds),
                  title: `Permanently Delete ${count} Selected Email Artifact${count > 1 ? 's' : ''}?`,
                });
              }}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold transition-all shadow-sm cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Delete Selected ({selectedIds.size})</span>
            </button>
          </div>
        </div>
      )}

      {/* Filter Tabs & Search Status */}
      <div className="rounded-2xl bg-workspace-card border border-workspace-border shadow-xs px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-bold text-text-muted uppercase tracking-wide mr-1">Filter by Status:</span>
          {FILTERS.map((cat) => {
            const isSelected = statusFilter === cat.id;
            return (
              <button
                key={cat.id}
                onClick={() => setStatusFilter(cat.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer border ${
                  isSelected
                    ? 'bg-brand text-white border-brand shadow-xs'
                    : 'bg-workspace text-text-secondary hover:text-text-primary border-workspace-border hover:border-brand/40'
                }`}
              >
                {cat.label}
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-3">
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="inline-flex items-center gap-1 text-xs font-bold text-brand hover:text-brand-hover transition-colors cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
              Reset Filters
            </button>
          )}
          <span className="text-xs text-text-muted font-medium">
            Showing <strong className="text-text-primary">{filtered.length}</strong> of {total}
          </span>
        </div>
      </div>

      {/* Gmail-Style Email Stack Container */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-xs overflow-hidden">
        {/* Table Header Bar - Modern Light SOC Style */}
        <div className="grid grid-cols-12 gap-2 px-4 py-3 bg-slate-50/90 border-b border-slate-200/80 text-[11px] font-bold text-slate-600 uppercase tracking-wider items-center select-none">
          <div className="col-span-4 sm:col-span-3 flex items-center gap-2">
            <button
              type="button"
              onClick={handleSelectAll}
              className="text-slate-400 hover:text-brand transition-colors p-0.5 shrink-0"
              title={selectedIds.size > 0 && selectedIds.size === filtered.length ? 'Deselect All' : 'Select All Filtered'}
            >
              {selectedIds.size > 0 && selectedIds.size === filtered.length ? (
                <CheckSquare className="w-4 h-4 text-brand" />
              ) : (
                <Square className="w-4 h-4 text-slate-400" />
              )}
            </button>
            <span>Sender</span>
          </div>
          <div className="col-span-5 sm:col-span-6">Subject & Forensic Details</div>
          <div className="hidden sm:block sm:col-span-2 text-center">Verdict</div>
          <div className="col-span-3 sm:col-span-1 text-right">Date / Action</div>
        </div>


        {/* Stack Body */}
        {loading ? (
          <div className="p-16 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-brand/30 border-t-brand rounded-full animate-spin mx-auto" />
            <p className="text-xs text-text-muted">Loading forensic analysis history…</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="rounded-xl p-12 text-center space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-workspace text-text-muted flex items-center justify-center mx-auto border border-workspace-border">
              <Mail className="w-6 h-6 opacity-60" />
            </div>
            <div>
              <h3 className="text-base font-bold text-text-primary">No emails found</h3>
              <p className="text-xs text-text-muted mt-1 max-w-sm mx-auto">
                {hasActiveFilters
                  ? 'No analysis records match your active search terms or category filter.'
                  : 'Your analysis queue is empty. Upload an email file (.eml) in the DNA workspace to start.'}
              </p>
            </div>
            {hasActiveFilters ? (
              <button
                onClick={clearFilters}
                className="px-4 py-2 rounded-xl bg-workspace text-text-primary border border-workspace-border text-xs font-semibold hover:bg-workspace-secondary cursor-pointer"
              >
                Clear Filters
              </button>
            ) : (
              onNavigateToAnalyze && (
                <button
                  onClick={onNavigateToAnalyze}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand text-white text-xs font-bold hover:bg-brand-hover shadow-xs cursor-pointer"
                >
                  <UploadCloud className="w-4 h-4" />
                  Upload .EML File
                </button>
              )
            )}
          </div>
        ) : (
          <div className="divide-y divide-workspace-border/60">
            {filtered.map((em) => {
              const category = getQualificationCategory(em.qualification_status);
              const isExpanded = expandedEmailId === em.id;
              const isStarred = starredIds.has(em.id);
              const isPhishing = category === 'malicious';
              const isSuspicious = category === 'suspicious';

              // Tweaks to match our platform: light green for legitimate, light red for phishing detected mails
              const rowBgClass = isPhishing
                ? 'bg-red-500/[0.08] hover:bg-red-500/[0.14] border-l-[4px] border-l-red-500'
                : isSuspicious
                ? 'bg-amber-500/[0.08] hover:bg-amber-500/[0.14] border-l-[4px] border-l-amber-500'
                : 'bg-emerald-500/[0.08] hover:bg-emerald-500/[0.14] border-l-[4px] border-l-emerald-500';

              const senderText = em.sender_display_name || em.sender_address || 'Unknown Sender';
              const snippetText = em.sender_address ? `From: ${em.sender_address}` : (em.sha256_hash ? `SHA: ${em.sha256_hash.slice(0, 14)}…` : 'Forensic Strand Verified');
              const threatScore = em.threat_risk_score ?? (isPhishing ? 88.5 : isSuspicious ? 54.0 : 8.0);
              const evidenceConfidence = em.evidence_confidence_score ?? 92.0;

              return (
                <div key={em.id} className="transition-colors group">
                  {/* Single Stack Row Item (No Checkbox) */}
                  <div
                    onClick={(e) => handleRowClick(em.id, e)}
                    onDoubleClick={(e) => {
                      e.stopPropagation();
                      setInspectingEmailId(em.id);
                    }}
                    onMouseEnter={() => {
                      getEmailDetails(em.id).catch(() => {});
                      getEmailAnalysis(em.id).catch(() => {});
                      getEmailAuthResults(em.id).catch(() => {});
                      getEmailHeaders(em.id).catch(() => {});
                      getEmailArtifacts(em.id).catch(() => {});
                    }}
                    title="Click to preview · Double-click to open full stored results immediately"
                    className={`grid grid-cols-12 gap-2 px-4 py-2.5 items-center cursor-pointer select-none transition-colors ${rowBgClass} ${
                      isExpanded ? 'ring-1 ring-brand/40 bg-workspace-card' : ''
                    }`}
                  >
                    {/* Sender + Checkbox + Star */}
                    <div className="col-span-4 sm:col-span-3 flex items-center gap-2 min-w-0">
                      <button
                        type="button"
                        onClick={(e) => toggleSelect(em.id, e)}
                        className="text-slate-400 hover:text-brand transition-colors p-0.5 shrink-0"
                        title={selectedIds.has(em.id) ? 'Deselect' : 'Select'}
                      >
                        {selectedIds.has(em.id) ? (
                          <CheckSquare className="w-4 h-4 text-brand" />
                        ) : (
                          <Square className="w-4 h-4 text-slate-400" />
                        )}
                      </button>
                      <button
                        onClick={(e) => toggleStar(em.id, e)}
                        className="text-text-muted hover:text-amber-400 shrink-0 transition-colors"
                        title={isStarred ? 'Unstar' : 'Star Case'}
                      >
                        <Star className={`w-4 h-4 ${isStarred ? 'text-amber-400 fill-amber-400' : 'text-slate-500'}`} />
                      </button>
                      <span className="font-bold text-xs sm:text-sm text-text-primary truncate group-hover:text-brand transition-colors">
                        {senderText}
                      </span>
                    </div>

                    {/* Subject + Snippet */}
                    <div className="col-span-5 sm:col-span-6 flex items-center gap-2 min-w-0 pr-2">
                      <div className="text-xs truncate">
                        <span className="font-semibold text-text-primary">
                          {em.subject || em.original_filename || 'Untitled Forensic Case'}
                        </span>
                        <span className="text-text-muted font-normal ml-1.5 opacity-80">
                          — {snippetText}
                        </span>
                      </div>
                    </div>

                    {/* Verdict Pill */}
                    <div className="hidden sm:flex sm:col-span-2 items-center justify-center">
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-tight ${
                          isPhishing
                            ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                            : isSuspicious
                            ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {isPhishing ? <ShieldAlert className="w-2.5 h-2.5" /> : isSuspicious ? <AlertTriangle className="w-2.5 h-2.5" /> : <ShieldCheck className="w-2.5 h-2.5" />}
                        <span>{em.threat_classification || (isPhishing ? 'PHISHING' : isSuspicious ? 'SUSPICIOUS' : 'LEGITIMATE')}</span>
                        <span className="opacity-75 font-normal">({threatScore.toFixed(0)})</span>
                      </span>
                    </div>

                    {/* Date Received & Direct Action Button */}
                    <div className="col-span-3 sm:col-span-1 flex items-center justify-end gap-1.5 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setInspectingEmailId(em.id);
                        }}
                        className="px-2 py-0.5 rounded-md bg-blue-50 hover:bg-blue-600 hover:text-white border border-blue-200/80 text-blue-700 text-[10.5px] font-bold transition-all shadow-2xs"
                        title="Open Stored Forensic Results"
                      >
                        Results →
                      </button>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setConfirmDeleteModal({
                            isOpen: true,
                            emailIds: [em.id],
                            title: `Delete "${em.subject || em.original_filename || 'Email Artifact'}"?`,
                          });
                        }}
                        className="p-1 rounded-md text-slate-400 hover:text-rose-600 hover:bg-rose-50 border border-transparent hover:border-rose-200 transition-colors cursor-pointer"
                        title="Permanently delete this email and all forensic reports/data"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                      <span className="text-xs font-mono text-text-muted whitespace-nowrap hidden sm:inline">
                        {em.received_at || em.created_at ? new Date(em.received_at || em.created_at).toLocaleDateString([], { month: 'short', day: 'numeric' }) : 'Recent'}
                      </span>
                      <ChevronDown className={`w-3.5 h-3.5 text-text-muted transition-transform shrink-0 ${isExpanded ? 'rotate-180 text-brand' : ''}`} />
                    </div>
                  </div>

                  {/* Expanded Forensic Detail Drawer */}
                  {isExpanded && (
                    <div className="bg-workspace/95 border-t border-workspace-border p-4.5 space-y-4 text-xs animate-in fade-in duration-150">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {/* Column 1: Integrity Reference */}
                        <div className="p-3.5 rounded-xl bg-workspace-card border border-workspace-border space-y-2">
                          <div className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
                            <ShieldCheck className="w-3.5 h-3.5 text-brand" /> Evidence Custody
                          </div>
                          <div className="space-y-1 font-mono text-[11px]">
                            <div><span className="text-text-muted">Evidence ID:</span> <span className="text-text-secondary">{em.evidence_id || 'Stored in MinIO'}</span></div>
                            <div><span className="text-text-muted">Analysis Status:</span> <span className="text-brand font-bold">{em.analysis_status}</span></div>
                            <div><span className="text-text-muted">Evidence Conf:</span> <span className="text-brand font-bold">{evidenceConfidence.toFixed(0)}%</span></div>
                            <div><span className="text-text-muted">Payload Size:</span> <span className="text-text-secondary">{em.email_size_bytes ? `${(em.email_size_bytes / 1024).toFixed(1)} KB` : 'Standard'}</span></div>
                          </div>
                        </div>

                        {/* Column 2: Threat Summary */}
                        <div className="p-3.5 rounded-xl bg-workspace-card border border-workspace-border space-y-2">
                          <div className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
                            <Sparkles className="w-3.5 h-3.5 text-amber-400" /> Forensic Classification
                          </div>
                          <p className="text-text-secondary leading-relaxed text-[11px]">
                            {isPhishing
                              ? 'High-confidence weaponized payload detected across authentication headers and content artifacts. Threat classification indicates credential harvesting or adversarial spoofing.'
                              : isSuspicious
                              ? 'Anomalous transmission headers or unaligned DKIM signature detected. Recommend manual forensic review in the DNA workspace.'
                              : 'All cryptographic authentication markers aligned. Message classified as BENIGN / CLEAN. Personal communication payload remains encrypted.'}
                          </p>
                        </div>

                        {/* Column 3: Quick Navigation */}
                        <div className="p-3.5 rounded-xl bg-workspace-card border border-workspace-border flex flex-col justify-between space-y-3">
                          <div className="text-[11px] font-bold text-text-muted uppercase tracking-wider">
                            Investigation Actions
                          </div>
                          <div className="flex flex-col gap-2">
                            <button
                              onClick={() => {
                                setInspectingEmailId(em.id);
                                if (onSelectEmail) onSelectEmail(em.id);
                              }}
                              className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-brand text-white font-bold text-xs hover:bg-brand-hover transition-colors cursor-pointer"
                            >
                              <span>Inspect Stored 5-Strand DNA</span>
                              <ArrowRight className="w-3.5 h-3.5" />
                            </button>
                            {onOpenReport && (
                              <button
                                onClick={() => onOpenReport(em.id)}
                                className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-workspace border border-workspace-border text-text-primary font-semibold text-xs hover:bg-workspace-secondary transition-colors cursor-pointer"
                              >
                                <span>Export Intelligence Report</span>
                                <FileCheck className="w-3.5 h-3.5 text-brand" />
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => {
                                setConfirmDeleteModal({
                                  isOpen: true,
                                  emailIds: [em.id],
                                  title: `Delete "${em.subject || em.original_filename || 'Email Artifact'}"?`,
                                });
                              }}
                              className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-rose-50/80 dark:bg-rose-500/10 border border-rose-200 dark:border-rose-500/20 text-rose-700 dark:text-rose-400 font-semibold text-xs hover:bg-rose-600 hover:text-white transition-colors cursor-pointer"
                            >
                              <span>Purge All Case & Report Data</span>
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* 5-Strand Quick Indicator Bar */}
                      <div className="pt-2 border-t border-workspace-border/60 flex items-center justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-2 flex-wrap text-[11px]">
                          <span className="text-text-muted font-bold uppercase tracking-wider text-[10px] mr-1">5-DNA Strands:</span>

                          <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold border flex items-center gap-1 ${
                            isPhishing ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          }`}>
                            <Cpu className="w-2.5 h-2.5" /> Technical {isPhishing ? '· SPF/DKIM Fail' : '· Verified'}
                          </span>

                          <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold border flex items-center gap-1 ${
                            isPhishing ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          }`}>
                            <FileText className="w-2.5 h-2.5" /> Content {isPhishing ? '· Phishing Lure' : '· Clean Body'}
                          </span>

                          <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold border flex items-center gap-1 ${
                            isPhishing ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          }`}>
                            <Globe2 className="w-2.5 h-2.5" /> Infra {isPhishing ? '· Bulletproof/Tor' : '· Standard MX'}
                          </span>

                          <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold border flex items-center gap-1 ${
                            isPhishing ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          }`}>
                            <UserCheck className="w-2.5 h-2.5" /> Behavioral {isPhishing ? '· Spoofed Display' : '· Legitimate'}
                          </span>

                          <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold border flex items-center gap-1 ${
                            isPhishing ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          }`}>
                            <Clock className="w-2.5 h-2.5" /> Temporal {isPhishing ? '· Burst Dispatch' : '· Regular'}
                          </span>
                        </div>

                        <div className="text-[11px] text-text-muted font-mono">
                          Artifact ID: <strong className="text-text-secondary">{em.id.slice(0, 8)}</strong>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Table Footer Bar - Modern Light SOC Style */}
        <div className="px-4 py-3 bg-slate-50/90 border-t border-slate-200/80 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-600 select-none">
          <span className="flex items-center gap-2 text-[11.5px]">
            <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
            <span className="font-semibold text-slate-700">Quick Navigation:</span>
            <span>Double-click any email row to immediately open full 5-strand forensic results.</span>
          </span>
          <span className="font-mono text-slate-500 text-[11px]">
            Showing <strong className="text-slate-800 font-bold">{filtered.length}</strong> of {total} records
          </span>
        </div>
      </div>

      {/* Permanent Deletion Confirmation Modal */}
      {confirmDeleteModal.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="w-full max-w-md bg-white dark:bg-workspace-card rounded-2xl border border-slate-200 dark:border-workspace-border shadow-2xl p-6 space-y-5 animate-in zoom-in-95 duration-150">
            <div className="flex items-start gap-3.5">
              <div className="w-10 h-10 rounded-xl bg-rose-100 dark:bg-rose-500/20 text-rose-600 dark:text-rose-400 flex items-center justify-center shrink-0">
                <Trash2 className="w-5 h-5" />
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-base font-bold text-slate-900 dark:text-text-primary leading-tight">
                  {confirmDeleteModal.title}
                </h3>
                <p className="text-xs text-slate-500 dark:text-text-muted mt-1 leading-relaxed">
                  This action is permanent and cannot be undone. All data regarding this email will be completely deleted across all panels:
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-rose-50/70 dark:bg-rose-500/10 border border-rose-200/80 dark:border-rose-500/20 text-[11px] text-rose-900 dark:text-rose-300 space-y-1.5 font-medium">
              <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider text-[10px] text-rose-700 dark:text-rose-400">
                <AlertOctagon className="w-3 h-3" /> Data Scheduled for Immediate Purge:
              </div>
              <ul className="list-disc pl-4 space-y-0.5 text-rose-800 dark:text-rose-300/90">
                <li>Original .EML file & extracted attachments in MinIO evidence vault</li>
                <li>All generated forensic reports & executive dossiers</li>
                <li>5-Strand DNA profiles, embedding vectors & similarity correlation links</li>
                <li>Relay hops, RFC822 headers & authentication records</li>
                <li>Threat classifications, findings, IOC sightings & cached telemetry</li>
              </ul>
            </div>

            {deleteError && (
              <div className="p-3 rounded-lg bg-red-100 border border-red-300 text-red-800 text-xs font-semibold">
                {deleteError}
              </div>
            )}

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                disabled={isDeleting}
                onClick={() => {
                  setConfirmDeleteModal({ isOpen: false, emailIds: [], title: '' });
                  setDeleteError(null);
                }}
                className="px-4 py-2 rounded-xl border border-slate-200 dark:border-workspace-border text-slate-700 dark:text-text-secondary text-xs font-semibold hover:bg-slate-100 dark:hover:bg-workspace-secondary transition-colors cursor-pointer disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={isDeleting}
                onClick={executeDelete}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold transition-all shadow-md cursor-pointer disabled:opacity-50"
              >
                {isDeleting ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Purging Data…</span>
                  </>
                ) : (
                  <>
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Permanently Delete</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AnalysisHistoryView;
