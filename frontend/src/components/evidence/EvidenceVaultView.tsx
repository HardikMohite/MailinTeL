import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  FolderLock,
  RefreshCw,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  Search,
  FileCheck,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  X,
  Lock,
  Database,
  History,
} from 'lucide-react';
import {
  listEmails,
  getEvidenceMetadata,
  getEvidenceCustody,
  verifyEvidenceIntegrity,
  EmailDetailResponse,
  EvidenceObjectResponse,
  CustodyEventResponse,
  EvidenceVerificationResponse,
} from '../../services/api';

interface EvidenceVaultViewProps {
  onSelectEmail?: (emailId: string) => void;
}

const fmtDateTime = (iso: string) => new Date(iso).toLocaleString();

const verdictStyle = (status: EvidenceVerificationResponse['status']) => {
  switch (status) {
    case 'VERIFIED':
      return { badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', label: 'Verified Intact' };
    case 'TAMPERED':
      return { badge: 'bg-rose-500/15 text-rose-400 border-rose-500/30', label: 'Hash Mismatch / Tampered' };
    default:
      return { badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30', label: 'Object Unreachable' };
  }
};

export const EvidenceVaultView: React.FC<EvidenceVaultViewProps> = ({ onSelectEmail }) => {
  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [vaultFilter, setVaultFilter] = useState<'ALL' | 'VERIFIED' | 'CRITICAL' | 'SAFE'>('ALL');

  // Low-latency in-memory cache refs
  const metadataCacheRef = useRef<Record<string, EvidenceObjectResponse>>({});
  const custodyCacheRef = useRef<Record<string, CustodyEventResponse[]>>({});

  // Per-row expanded detail (custody trail + metadata), keyed by evidence_id
  const [expandedEvidenceId, setExpandedEvidenceId] = useState<string | null>(null);
  const [metadataByEvidence, setMetadataByEvidence] = useState<Record<string, EvidenceObjectResponse>>({});
  const [custodyByEvidence, setCustodyByEvidence] = useState<Record<string, CustodyEventResponse[]>>({});
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  // Per-row verification result, keyed by evidence_id
  const [verifyResults, setVerifyResults] = useState<Record<string, EvidenceVerificationResponse>>({});
  const [verifyingId, setVerifyingId] = useState<string | null>(null);

  useEffect(() => {
    loadEvidence();
  }, []);

  const loadEvidence = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listEmails(0, 100);
      setEmails(res.items || []);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Could not load the evidence vault from the backend.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (id: string, hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // High-speed background prefetch to ensure 0ms latency when expanding
  const prefetchDetail = async (evidenceId: string | null | undefined) => {
    if (!evidenceId) return;
    if (metadataCacheRef.current[evidenceId] && custodyCacheRef.current[evidenceId]) return;
    try {
      const [metadata, custody] = await Promise.all([
        getEvidenceMetadata(evidenceId),
        getEvidenceCustody(evidenceId),
      ]);
      metadataCacheRef.current[evidenceId] = metadata;
      custodyCacheRef.current[evidenceId] = custody;
      setMetadataByEvidence((prev) => ({ ...prev, [evidenceId]: metadata }));
      setCustodyByEvidence((prev) => ({ ...prev, [evidenceId]: custody }));
    } catch {
      // Background prefetch is non-blocking
    }
  };

  const handleToggleDetail = async (evidenceId: string | null | undefined) => {
    if (!evidenceId) return;
    if (expandedEvidenceId === evidenceId) {
      setExpandedEvidenceId(null);
      return;
    }
    setExpandedEvidenceId(evidenceId);

    // Fast-path: Check in-memory cache first for instant zero-latency render
    if (metadataCacheRef.current[evidenceId] && custodyCacheRef.current[evidenceId]) {
      setMetadataByEvidence((prev) => ({ ...prev, [evidenceId]: metadataCacheRef.current[evidenceId] }));
      setCustodyByEvidence((prev) => ({ ...prev, [evidenceId]: custodyCacheRef.current[evidenceId] }));
      return;
    }

    setDetailLoading(true);
    setDetailError(null);
    try {
      const [metadata, custody] = await Promise.all([
        getEvidenceMetadata(evidenceId),
        getEvidenceCustody(evidenceId),
      ]);
      metadataCacheRef.current[evidenceId] = metadata;
      custodyCacheRef.current[evidenceId] = custody;
      setMetadataByEvidence((prev) => ({ ...prev, [evidenceId]: metadata }));
      setCustodyByEvidence((prev) => ({ ...prev, [evidenceId]: custody }));
    } catch (err: any) {
      setDetailError(err.response?.data?.detail || err.message || 'Could not load custody details for this object.');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleVerify = async (evidenceId: string | null | undefined) => {
    if (!evidenceId) return;
    setVerifyingId(evidenceId);
    try {
      const result = await verifyEvidenceIntegrity(evidenceId);
      setVerifyResults((prev) => ({ ...prev, [evidenceId]: result }));
      // Invalidate cache for new verification custody event
      delete custodyCacheRef.current[evidenceId];
      // Refresh custody trail in background
      getEvidenceCustody(evidenceId)
        .then((custody) => {
          custodyCacheRef.current[evidenceId] = custody;
          setCustodyByEvidence((prev) => ({ ...prev, [evidenceId]: custody }));
        })
        .catch(() => {});
    } catch (err: any) {
      setVerifyResults((prev) => ({
        ...prev,
        [evidenceId]: {
          evidence_id: evidenceId,
          original_filename: '',
          stored_sha256: '',
          computed_sha256: null,
          is_valid: false,
          status: 'OBJECT_NOT_FOUND',
          verified_at: new Date().toISOString(),
          details: { error: err.response?.data?.detail || err.message || 'Verification request failed.' },
        },
      }));
    } finally {
      setVerifyingId(null);
    }
  };

  const filtered = useMemo(() => {
    return emails.filter((em) => {
      const score = em.threat_risk_score ?? 0;
      if (vaultFilter === 'CRITICAL' && score < 65) return false;
      if (vaultFilter === 'SAFE' && score >= 35) return false;
      if (vaultFilter === 'VERIFIED') {
        const evidenceId = em.evidence_id;
        if (!evidenceId || verifyResults[evidenceId]?.status !== 'VERIFIED') return false;
      }

      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        const matchSub = em.subject && em.subject.toLowerCase().includes(q);
        const matchSha = em.sha256_hash && em.sha256_hash.toLowerCase().includes(q);
        const matchId = em.id.toLowerCase().includes(q);
        const matchSender = (em.sender_address || em.sender_display_name)?.toLowerCase().includes(q);
        if (!matchSub && !matchSha && !matchId && !matchSender) return false;
      }
      return true;
    });
  }, [emails, searchQuery, vaultFilter, verifyResults]);

  const totalBytes = emails.reduce((acc, em) => acc + (em.email_size_bytes || 0), 0);
  const hashedCount = emails.filter((em) => em.sha256_hash).length;
  const criticalCount = emails.filter((em) => (em.threat_risk_score ?? 0) >= 65).length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Title + Description */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-workspace-card border border-workspace-border shadow-xs">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand/10 border border-brand/20 text-brand flex items-center justify-center shrink-0">
            <FolderLock className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-bold text-text-primary tracking-tight">Evidence Vault</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                MinIO WORM Immutable
              </span>
            </div>
            <p className="text-xs sm:text-sm text-text-muted mt-0.5">
              ISO/IEC 27037 chain-of-custody archive — cryptographic SHA-256 hashes, immutable retention, and zero-latency audit logs.
            </p>
          </div>
        </div>
        <button
          onClick={loadEvidence}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-workspace text-text-primary border border-workspace-border text-xs font-semibold hover:bg-workspace-card transition-colors disabled:opacity-50 self-start md:self-auto shadow-xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Vault
        </button>
      </div>

      {error && (
        <div className="px-4 py-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-xs text-rose-400 flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Metric Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-workspace-card border border-workspace-border shadow-xs flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-brand/10 border border-brand/20 text-brand flex items-center justify-center shrink-0">
            <FolderLock className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-text-muted font-medium">Preserved Evidence Objects</div>
            <div className="text-xl font-bold text-text-primary font-mono">{loading ? '—' : emails.length}</div>
          </div>
        </div>
        <div className="p-4 rounded-xl bg-workspace-card border border-workspace-border shadow-xs flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-text-muted font-medium">SHA-256 Hashes Sealed</div>
            <div className="text-xl font-bold text-emerald-400 font-mono">{loading ? '—' : hashedCount}</div>
          </div>
        </div>
        <div className="p-4 rounded-xl bg-workspace-card border border-workspace-border shadow-xs flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400 flex items-center justify-center shrink-0">
            <FileCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-text-muted font-medium">Total Preserved Volume</div>
            <div className="text-xl font-bold text-text-primary font-mono">{loading ? '—' : `${(totalBytes / 1024).toFixed(1)} KB`}</div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-workspace-card rounded-xl border border-workspace-border shadow-xs">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          <button
            onClick={() => setVaultFilter('ALL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
              vaultFilter === 'ALL'
                ? 'bg-slate-800 text-white border border-slate-700 shadow-xs'
                : 'text-text-muted hover:text-text-primary hover:bg-workspace'
            }`}
          >
            All Evidence ({emails.length})
          </button>
          <button
            onClick={() => setVaultFilter('CRITICAL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all flex items-center gap-1.5 ${
              vaultFilter === 'CRITICAL'
                ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-xs'
                : 'text-text-muted hover:text-red-400 hover:bg-red-500/10'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-red-400 inline-block animate-pulse" />
            Threat Objects ({criticalCount})
          </button>
          <button
            onClick={() => setVaultFilter('SAFE')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all flex items-center gap-1.5 ${
              vaultFilter === 'SAFE'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-xs'
                : 'text-text-muted hover:text-emerald-400 hover:bg-emerald-500/10'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
            Clean Records
          </button>
        </div>

        <div className="relative min-w-[240px] sm:w-80">
          <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search SHA-256 hash, subject, or ID…"
            className="w-full pl-9 pr-8 py-1.5 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary font-mono placeholder:font-sans focus:outline-none focus:border-brand"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Evidence Table */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-xs overflow-hidden">
        {loading ? (
          <div className="p-16 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-brand/30 border-t-brand rounded-full animate-spin mx-auto" />
            <p className="text-xs text-text-muted">Loading cryptographic evidence vault records…</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-16 text-center space-y-2">
            <FolderLock className="w-10 h-10 text-text-muted/40 mx-auto" />
            <p className="text-sm font-semibold text-text-primary">No evidence objects match this criteria</p>
            <p className="text-xs text-text-muted">
              {searchQuery ? 'Try clearing your search query' : 'Upload .eml files to preserve immutable forensic records.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-900/60 text-text-muted uppercase text-[11px] border-b border-workspace-border font-semibold">
                <tr>
                  <th className="px-5 py-3">Preserved Case / Subject</th>
                  <th className="px-4 py-3">SHA-256 Fingerprint</th>
                  <th className="px-3 py-3">Payload Size</th>
                  <th className="px-3 py-3">Sealed Date</th>
                  <th className="px-3 py-3">Integrity State</th>
                  <th className="px-5 py-3 text-right">Chain of Custody</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-workspace-border/60">
                {filtered.map((em) => {
                  const evidenceId = em.evidence_id;
                  const isExpanded = expandedEvidenceId === evidenceId;
                  const verification = evidenceId ? verifyResults[evidenceId] : undefined;
                  const metadata = evidenceId ? metadataByEvidence[evidenceId] : undefined;
                  const custody = evidenceId ? custodyByEvidence[evidenceId] : undefined;
                  const score = em.threat_risk_score ?? 0;
                  const isMalicious = score >= 65;

                  return (
                    <React.Fragment key={em.id}>
                      <tr
                        onMouseEnter={() => prefetchDetail(evidenceId)}
                        className={`hover:bg-slate-800/30 transition-colors ${isExpanded ? 'bg-slate-800/20' : ''}`}
                      >
                        <td className="px-5 py-3.5 min-w-0 max-w-xs">
                          <div className="font-medium text-text-primary truncate text-xs">
                            {em.subject || em.original_filename || 'Untitled forensic evidence'}
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-[10px] font-mono text-text-muted truncate">{em.id.slice(0, 8)}…</span>
                            {isMalicious ? (
                              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-red-500/15 text-red-400 border border-red-500/30">
                                THREAT ({score})
                              </span>
                            ) : (
                              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                                BENIGN ({score})
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3.5 text-text-secondary">
                          {em.sha256_hash ? (
                            <div className="flex items-center gap-1.5">
                              <span className="font-mono text-[11px] bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-slate-300 truncate max-w-[160px]" title={em.sha256_hash}>
                                {em.sha256_hash.slice(0, 16)}…
                              </span>
                              <button
                                onClick={() => handleCopy(em.id, em.sha256_hash!)}
                                className="p-1 rounded bg-workspace text-text-muted hover:text-brand border border-workspace-border transition-colors shrink-0"
                                title="Copy SHA-256 fingerprint"
                              >
                                {copiedId === em.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          ) : (
                            <span className="text-xs text-text-muted">Not recorded</span>
                          )}
                        </td>
                        <td className="px-3 py-3.5 text-text-secondary whitespace-nowrap text-xs font-mono">
                          {em.email_size_bytes ? `${(em.email_size_bytes / 1024).toFixed(1)} KB` : '—'}
                        </td>
                        <td className="px-3 py-3.5 text-text-muted whitespace-nowrap text-xs font-mono">
                          {em.created_at ? new Date(em.created_at).toLocaleDateString() : 'Preserved'}
                        </td>
                        <td className="px-3 py-3.5 whitespace-nowrap">
                          {!evidenceId ? (
                            <span className="text-[11px] text-text-muted">Unlinked object</span>
                          ) : verifyingId === evidenceId ? (
                            <span className="text-[11px] text-brand flex items-center gap-1.5 font-mono">
                              <RefreshCw className="w-3 h-3 animate-spin" /> Verifying…
                            </span>
                          ) : verification ? (
                            <span
                              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${
                                verdictStyle(verification.status).badge
                              }`}
                            >
                              {verification.status === 'VERIFIED' ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
                              <span>{verdictStyle(verification.status).label}</span>
                            </span>
                          ) : (
                            <button
                              onClick={() => handleVerify(evidenceId)}
                              className="text-[11px] font-semibold text-brand hover:text-brand-hover flex items-center gap-1"
                            >
                              <ShieldCheck className="w-3 h-3" />
                              <span>Verify Hash</span>
                            </button>
                          )}
                        </td>
                        <td className="px-5 py-3.5 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {evidenceId && (
                              <button
                                onClick={() => handleToggleDetail(evidenceId)}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-workspace border border-workspace-border text-text-primary text-xs font-semibold hover:bg-slate-800 transition-colors shadow-xs"
                              >
                                <History className="w-3 h-3 text-brand" />
                                <span>Custody Trail</span>
                                {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                              </button>
                            )}
                            {onSelectEmail && (
                              <button
                                onClick={() => onSelectEmail(em.id)}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-brand/10 hover:bg-brand text-brand hover:text-white border border-brand/20 text-xs font-semibold transition-all shadow-xs"
                              >
                                <span>Inspect</span>
                                <ArrowRight className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr>
                          <td colSpan={6} className="px-6 py-4 bg-slate-950/70 border-t border-b border-workspace-border animate-fade-in">
                            {detailLoading && !metadata && !custody ? (
                              <div className="text-xs text-text-muted py-3 flex items-center gap-2">
                                <RefreshCw className="w-3.5 h-3.5 animate-spin text-brand" />
                                <span>Loading verified custody trail from storage register…</span>
                              </div>
                            ) : detailError ? (
                              <div className="text-xs text-rose-400 py-2">{detailError}</div>
                            ) : (
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {/* Object Metadata */}
                                <div className="space-y-3">
                                  <div className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
                                    <Lock className="w-3.5 h-3.5 text-brand" />
                                    <span>Immutable Object Metadata</span>
                                  </div>
                                  {metadata ? (
                                    <div className="grid grid-cols-2 gap-3 text-xs p-3 rounded-xl bg-slate-900 border border-slate-800 font-mono">
                                      <div>
                                        <div className="text-[10px] text-text-muted font-sans font-medium">Evidence Format</div>
                                        <div className="font-semibold text-text-primary mt-0.5">{metadata.evidence_type}</div>
                                      </div>
                                      <div>
                                        <div className="text-[10px] text-text-muted font-sans font-medium">Retention Policy</div>
                                        <div className="font-semibold text-text-primary mt-0.5">{metadata.retention_status}</div>
                                      </div>
                                      <div>
                                        <div className="text-[10px] text-text-muted font-sans font-medium">Storage Immutability</div>
                                        <div className={`font-semibold mt-0.5 ${metadata.immutable ? 'text-emerald-400' : 'text-rose-400'}`}>
                                          {metadata.immutable ? 'LOCK_ENABLED (WORM)' : 'STANDARD'}
                                        </div>
                                      </div>
                                      <div>
                                        <div className="text-[10px] text-text-muted font-sans font-medium">Sealed Timestamp</div>
                                        <div className="font-semibold text-text-primary mt-0.5 truncate">{fmtDateTime(metadata.acquired_at)}</div>
                                      </div>
                                    </div>
                                  ) : (
                                    <div className="text-xs text-text-muted">Metadata unavailable.</div>
                                  )}
                                </div>

                                {/* Chain of Custody */}
                                <div className="space-y-3">
                                  <div className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
                                    <Database className="w-3.5 h-3.5 text-emerald-400" />
                                    <span>Chain of Custody Events</span>
                                  </div>
                                  {custody && custody.length > 0 ? (
                                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                                      {custody.map((ev) => (
                                        <div key={ev.id} className="p-2 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between gap-3 text-xs">
                                          <div className="flex items-center gap-2">
                                            <span className="w-1.5 h-1.5 rounded-full bg-brand" />
                                            <span className="text-text-primary font-medium">{ev.event_type.replace(/_/g, ' ')}</span>
                                          </div>
                                          <span className="text-text-muted font-mono text-[10px]">{fmtDateTime(ev.event_at)}</span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <div className="text-xs text-text-muted">No custody events logged yet.</div>
                                  )}
                                </div>

                                {verification && (
                                  <div className="md:col-span-2 pt-3 border-t border-slate-800 text-xs text-slate-400 flex items-center gap-2 font-mono">
                                    <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                                    <span>
                                      {verification.status === 'VERIFIED'
                                        ? 'Cryptographic integrity verified: SHA-256 matches immutable storage register exactly.'
                                        : verification.status === 'TAMPERED'
                                        ? 'ALERT: SHA-256 hash mismatch! The underlying object contents do not match the preservation seal.'
                                        : String(verification.details?.error || 'Verification target could not be retrieved.')}
                                    </span>
                                  </div>
                                )}
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default EvidenceVaultView;
