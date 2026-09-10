import React, { useState, useEffect, useMemo } from 'react';
import {
  FolderLock,
  RefreshCw,
  Copy,
  Check,
  ShieldCheck,
  Search,
  FileCheck,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  X,
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
      return { badge: 'bg-severity-safe-soft text-severity-safe border-severity-safe/20', label: 'Verified' };
    case 'TAMPERED':
      return { badge: 'bg-severity-critical-soft text-severity-critical border-severity-critical/20', label: 'Hash Mismatch' };
    default:
      return { badge: 'bg-severity-high-soft text-severity-high border-severity-high/20', label: 'Object Not Found' };
  }
};

export const EvidenceVaultView: React.FC<EvidenceVaultViewProps> = ({ onSelectEmail }) => {
  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

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

  const handleToggleDetail = async (evidenceId: string | null | undefined) => {
    if (!evidenceId) return;
    if (expandedEvidenceId === evidenceId) {
      setExpandedEvidenceId(null);
      return;
    }
    setExpandedEvidenceId(evidenceId);
    if (custodyByEvidence[evidenceId] && metadataByEvidence[evidenceId]) return;

    setDetailLoading(true);
    setDetailError(null);
    try {
      const [metadata, custody] = await Promise.all([
        getEvidenceMetadata(evidenceId),
        getEvidenceCustody(evidenceId),
      ]);
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
      // A verification run creates a new custody event — drop any cached
      // trail so the next expand re-fetches it with the new entry included.
      setCustodyByEvidence((prev) => {
        const next = { ...prev };
        delete next[evidenceId];
        return next;
      });
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
    const q = searchQuery.trim().toLowerCase();
    if (!q) return emails;
    return emails.filter(
      (em) =>
        (em.subject && em.subject.toLowerCase().includes(q)) ||
        (em.sha256_hash && em.sha256_hash.toLowerCase().includes(q)) ||
        em.id.toLowerCase().includes(q)
    );
  }, [emails, searchQuery]);

  const totalBytes = emails.reduce((acc, em) => acc + (em.email_size_bytes || 0), 0);
  const hashedCount = emails.filter((em) => em.sha256_hash).length;

  return (
    <div className="space-y-6">
      {/* Page Title + Description */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <FolderLock className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary tracking-tight">Evidence Vault</h1>
            <p className="text-sm text-text-muted mt-0.5">
              Chain-of-custody for every preserved original — SHA-256 hash, retention status, and access history.
            </p>
          </div>
        </div>
        <button
          onClick={loadEvidence}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-workspace-card text-text-primary border border-workspace-border text-sm font-medium hover:bg-workspace-secondary transition-colors disabled:opacity-50 self-start md:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="px-4 py-2.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-sm text-severity-high flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Metric Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-workspace-card border border-workspace-border shadow-sm flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <FolderLock className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-text-muted font-medium">Preserved Evidence Objects</div>
            <div className="text-xl font-bold text-text-primary">{loading ? '—' : emails.length}</div>
          </div>
        </div>
        <div className="p-4 rounded-xl bg-workspace-card border border-workspace-border shadow-sm flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-text-muted font-medium">SHA-256 Hashes Recorded</div>
            <div className="text-xl font-bold text-text-primary">{loading ? '—' : hashedCount}</div>
          </div>
        </div>
        <div className="p-4 rounded-xl bg-workspace-card border border-workspace-border shadow-sm flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <FileCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[11px] text-text-muted font-medium">Total Preserved Volume</div>
            <div className="text-xl font-bold text-text-primary">{loading ? '—' : `${(totalBytes / 1024).toFixed(1)} KB`}</div>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-4">
        <div className="relative">
          <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Find by subject, SHA-256 hash, or email ID…"
            className="w-full pl-9 pr-9 py-2 text-sm bg-workspace border border-workspace-border rounded-lg text-text-primary font-mono placeholder:font-sans focus:outline-none focus:border-brand"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Evidence Table */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-sm text-text-muted">Loading evidence vault…</div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center">
            {emails.length === 0 ? (
              <>
                <p className="text-sm font-semibold text-text-primary">No evidence preserved yet</p>
                <p className="text-sm text-text-muted mt-1">Upload a .eml file from Analyze Email to seal your first record.</p>
              </>
            ) : (
              <p className="text-sm text-text-muted">No evidence objects match this search.</p>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-workspace-header text-text-muted uppercase text-[11px] border-b border-workspace-border">
                <tr>
                  <th className="px-5 py-3 font-semibold">File / Subject</th>
                  <th className="px-3 py-3 font-semibold">SHA-256 Hash</th>
                  <th className="px-3 py-3 font-semibold">Size</th>
                  <th className="px-3 py-3 font-semibold">Preserved</th>
                  <th className="px-3 py-3 font-semibold">Integrity</th>
                  <th className="px-3 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-workspace-border">
                {filtered.map((em) => {
                  const evidenceId = em.evidence_id;
                  const isExpanded = expandedEvidenceId === evidenceId;
                  const verification = evidenceId ? verifyResults[evidenceId] : undefined;
                  const metadata = evidenceId ? metadataByEvidence[evidenceId] : undefined;
                  const custody = evidenceId ? custodyByEvidence[evidenceId] : undefined;

                  return (
                    <React.Fragment key={em.id}>
                      <tr className="hover:bg-workspace/60 transition-colors">
                        <td className="px-5 py-3.5 min-w-0 max-w-xs">
                          <div className="font-medium text-text-primary truncate">
                            {em.subject || em.original_filename || 'Untitled email'}
                          </div>
                          <div className="text-xs text-text-muted truncate mt-0.5">{em.id}</div>
                        </td>
                        <td className="px-3 py-3.5 text-text-secondary">
                          {em.sha256_hash ? (
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs truncate max-w-[180px]" title={em.sha256_hash}>
                                {em.sha256_hash}
                              </span>
                              <button
                                onClick={() => handleCopy(em.id, em.sha256_hash!)}
                                className="p-1 rounded bg-workspace text-text-muted hover:text-brand border border-workspace-border transition-colors shrink-0"
                                title="Copy SHA-256"
                              >
                                {copiedId === em.id ? <Check className="w-3 h-3 text-severity-safe" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          ) : (
                            <span className="text-xs text-text-muted">Not recorded</span>
                          )}
                        </td>
                        <td className="px-3 py-3.5 text-text-secondary whitespace-nowrap">
                          {em.email_size_bytes ? `${(em.email_size_bytes / 1024).toFixed(1)} KB` : '—'}
                        </td>
                        <td className="px-3 py-3.5 text-text-muted whitespace-nowrap">{fmtDateTime(em.created_at)}</td>
                        <td className="px-3 py-3.5 whitespace-nowrap">
                          {!evidenceId ? (
                            <span className="text-xs text-text-muted">No evidence object</span>
                          ) : verifyingId === evidenceId ? (
                            <span className="text-xs text-text-muted flex items-center gap-1.5">
                              <RefreshCw className="w-3 h-3 animate-spin" /> Verifying…
                            </span>
                          ) : verification ? (
                            <span
                              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${
                                verdictStyle(verification.status).badge
                              }`}
                            >
                              {verdictStyle(verification.status).label}
                            </span>
                          ) : (
                            <button
                              onClick={() => handleVerify(evidenceId)}
                              className="text-xs font-medium text-brand hover:text-brand-hover"
                            >
                              Run integrity check
                            </button>
                          )}
                        </td>
                        <td className="px-3 py-3.5">
                          <div className="flex items-center justify-end gap-2">
                            {evidenceId && (
                              <button
                                onClick={() => handleToggleDetail(evidenceId)}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-workspace border border-workspace-border text-text-primary text-xs font-medium hover:bg-workspace-secondary transition-colors"
                              >
                                Custody
                                {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                              </button>
                            )}
                            {onSelectEmail && (
                              <button
                                onClick={() => onSelectEmail(em.id)}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors"
                              >
                                Inspect
                                <ArrowRight className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr>
                          <td colSpan={6} className="px-5 py-4 bg-workspace border-t border-b border-workspace-border">
                            {detailLoading && !metadata && !custody ? (
                              <div className="text-xs text-text-muted py-2">Loading custody trail…</div>
                            ) : detailError ? (
                              <div className="text-xs text-severity-high py-2">{detailError}</div>
                            ) : (
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                                {/* Retention / Object metadata — real fields, no bucket/object-key infra detail (Design.md §37) */}
                                <div>
                                  <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mb-2">
                                    Object Metadata
                                  </div>
                                  {metadata ? (
                                    <div className="grid grid-cols-2 gap-2 text-xs">
                                      <div>
                                        <div className="text-[10px] text-text-muted">Evidence Type</div>
                                        <div className="font-medium text-text-primary mt-0.5">{metadata.evidence_type}</div>
                                      </div>
                                      <div>
                                        <div className="text-[10px] text-text-muted">Retention Status</div>
                                        <div className="font-medium text-text-primary mt-0.5">{metadata.retention_status}</div>
                                      </div>
                                      <div>
                                        <div className="text-[10px] text-text-muted">Immutable</div>
                                        <div className={`font-medium mt-0.5 ${metadata.immutable ? 'text-severity-safe' : 'text-severity-high'}`}>
                                          {metadata.immutable ? 'Yes' : 'No'}
                                        </div>
                                      </div>
                                      <div>
                                        <div className="text-[10px] text-text-muted">Acquired</div>
                                        <div className="font-medium text-text-primary mt-0.5">{fmtDateTime(metadata.acquired_at)}</div>
                                      </div>
                                    </div>
                                  ) : (
                                    <div className="text-xs text-text-muted">Metadata unavailable.</div>
                                  )}
                                </div>

                                {/* Chain of custody — Design.md §23 */}
                                <div>
                                  <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mb-2">
                                    Chain of Custody
                                  </div>
                                  {custody && custody.length > 0 ? (
                                    <div className="space-y-1.5 max-h-40 overflow-y-auto">
                                      {custody.map((ev) => (
                                        <div key={ev.id} className="flex items-center justify-between gap-2 text-xs">
                                          <span className="text-text-secondary">{ev.event_type.replace(/_/g, ' ')}</span>
                                          <span className="text-text-muted font-mono text-[11px]">{fmtDateTime(ev.event_at)}</span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <div className="text-xs text-text-muted">No custody events recorded yet.</div>
                                  )}
                                </div>

                                {verification && (
                                  <div className="md:col-span-2 pt-3 border-t border-workspace-border">
                                    <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wide mb-2">
                                      Last Verification
                                    </div>
                                    <div className="text-xs text-text-secondary">
                                      {verification.status === 'VERIFIED'
                                        ? 'Recomputed SHA-256 matched the stored hash exactly.'
                                        : verification.status === 'TAMPERED'
                                        ? 'Recomputed SHA-256 did not match the stored hash — the object may have been altered.'
                                        : String(verification.details?.error || 'The evidence object could not be retrieved from storage.')}
                                    </div>
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
