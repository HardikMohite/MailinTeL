import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  UserCheck,
  BrainCircuit,
  CheckCircle2,
  Zap,
  RefreshCw,
  Tag,
  Check,
  Edit3,
  X,
  Quote,
  Sliders,
} from 'lucide-react';
import {
  getEmailDisposition,
  submitEmailDisposition,
  EmailDispositionResponse,
  AnalystPrecedentItem,
} from '../../services/api';

interface AnalystDispositionPanelProps {
  emailId: string;
  onDispositionUpdated?: (disposition: EmailDispositionResponse) => void;
}

const VERDICT_OPTIONS = [
  {
    id: 'CONFIRMED_PHISHING',
    label: 'Confirmed Phishing',
    desc: 'Malicious credential harvesting, malware delivery, or phishing lure',
    badgeClass: 'border-red-500/50 bg-red-500/10 text-red-400 hover:border-red-500',
    activeClass: 'border-red-500 bg-red-500/20 text-red-300 ring-1 ring-red-500',
    summaryClass: 'border-red-500/40 bg-red-500/15 text-red-300',
  },
  {
    id: 'CONFIRMED_BEC',
    label: 'Confirmed BEC / Fraud',
    desc: 'Business email compromise, VIP impersonation, or wire transfer fraud',
    badgeClass: 'border-orange-500/50 bg-orange-500/10 text-orange-400 hover:border-orange-500',
    activeClass: 'border-orange-500 bg-orange-500/20 text-orange-300 ring-1 ring-orange-500',
    summaryClass: 'border-orange-500/40 bg-orange-500/15 text-orange-300',
  },
  {
    id: 'FALSE_POSITIVE',
    label: 'False Positive',
    desc: 'Benign email erroneously elevated by heuristic anomaly thresholds',
    badgeClass: 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400 hover:border-emerald-500',
    activeClass: 'border-emerald-500 bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500',
    summaryClass: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
  },
  {
    id: 'CONFIRMED_LEGITIMATE',
    label: 'Confirmed Legitimate',
    desc: 'Standard authenticated business communication verified safe',
    badgeClass: 'border-cyan-500/50 bg-cyan-500/10 text-cyan-400 hover:border-cyan-500',
    activeClass: 'border-cyan-500 bg-cyan-500/20 text-cyan-300 ring-1 ring-cyan-500',
    summaryClass: 'border-cyan-500/40 bg-cyan-500/15 text-cyan-300',
  },
  {
    id: 'UNDER_INVESTIGATION',
    label: 'Under Investigation',
    desc: 'Pending deeper sandbox execution or incident response triage',
    badgeClass: 'border-amber-500/50 bg-amber-500/10 text-amber-400 hover:border-amber-500',
    activeClass: 'border-amber-500 bg-amber-500/20 text-amber-300 ring-1 ring-amber-500',
    summaryClass: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
  },
];

const REMEDIATION_OPTIONS = [
  { id: 'BLOCK_SENDER', label: 'Perimeter Block: Sender Domain' },
  { id: 'BLACKLIST_IP', label: 'Firewall Blacklist: Relay IPs' },
  { id: 'BLOCK_URLS', label: 'Web Gateway: Blacklist Extracted URLs' },
  { id: 'CAMPAIGN_CLUSTER', label: 'Promote to Threat Campaign Cluster' },
];

const QUICK_TEMPLATES = [
  'Compromised legitimate third-party relay infrastructure sending spear-phishing lures.',
  'Urgent credential harvesting lure utilizing spoofed branding and click-tracking beacons.',
  'Sender and Reply-To mismatch indicating VIP executive impersonation / BEC vector.',
  'Legitimate verified internal operational communication; heuristic scores cleared.',
];

export const AnalystDispositionPanel: React.FC<AnalystDispositionPanelProps> = ({
  emailId,
  onDispositionUpdated,
}) => {
  const [data, setData] = useState<EmailDispositionResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [isEditing, setIsEditing] = useState<boolean>(false);
  const [selectedVerdict, setSelectedVerdict] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [remediationActions, setRemediationActions] = useState<string[]>([]);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchDisposition = async () => {
    if (!emailId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await getEmailDisposition(emailId);
      setData(res);
      if (res.is_resolved && res.verdict) {
        setSelectedVerdict(res.verdict);
        setNotes(res.analyst_notes || '');
        setRemediationActions(res.remediation_actions || []);
        setIsEditing(false);
      } else if (res.triage_tier === 'TIER_1_AUTO' || res.triage_tier === 'TIER_3_AUTO_CLEARED') {
        setIsEditing(false);
      } else {
        // TIER_2_HUMAN_GATED
        setIsEditing(true);
      }
    } catch (err: any) {
      console.error('Failed to load disposition:', err);
      setError(err?.response?.data?.detail || 'Failed to load disposition data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDisposition();
    setSuccessMessage(null);
  }, [emailId]);

  const handleToggleAction = (action: string) => {
    setRemediationActions((prev) =>
      prev.includes(action) ? prev.filter((a) => a !== action) : [...prev, action]
    );
  };

  const handleApplyPrecedent = (p: AnalystPrecedentItem) => {
    setSelectedVerdict(p.analyst_verdict);
    setNotes(
      `Precedent Match (Case ${p.precedent_email_id.slice(0, 8)} by ${p.reviewer_name}): ${p.analyst_notes || 'Confirmed pattern match.'}`
    );
    setIsEditing(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedVerdict) {
      setError('Please select a disposition verdict.');
      return;
    }
    if (!notes.trim()) {
      setError('Please provide analyst rationale to train platform memory.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const res = await submitEmailDisposition(emailId, {
        verdict: selectedVerdict,
        notes: notes.trim(),
        actions: remediationActions,
        flagged_iocs: [],
      });
      setData(res);
      setSuccessMessage('Analyst disposition recorded and vectorized into AI continuous memory.');
      setIsEditing(false);
      if (onDispositionUpdated) {
        onDispositionUpdated(res);
      }
    } catch (err: any) {
      console.error('Failed to submit disposition:', err);
      setError(err?.response?.data?.detail || 'Failed to submit analyst disposition.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading && !data) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
        <div className="flex items-center space-x-3 text-slate-400">
          <RefreshCw className="h-4 w-4 animate-spin text-cyan-400" />
          <span className="text-xs font-medium">Loading triage state & intelligence memory...</span>
        </div>
      </div>
    );
  }

  const currentVerdictMeta = VERDICT_OPTIONS.find((v) => v.id === (data?.verdict || selectedVerdict));

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 shadow-xl backdrop-blur-md space-y-4">
      {/* Panel Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3.5">
        <div className="flex items-center space-x-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 shadow-inner">
            <UserCheck className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-sm font-semibold text-slate-100">
                Human Analyst Layer &amp; Active Learning
              </h3>
              <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-medium text-cyan-300">
                Continuous Memory
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Confidence-gated triage, authoritative human disposition, and pgvector feedback loop.
            </p>
          </div>
        </div>

        {/* Header Triage Status Indicator */}
        {data && (
          <div className="flex items-center space-x-2">
            {data.is_resolved ? (
              <div className="flex items-center space-x-1.5 rounded-full border border-cyan-500/40 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-300">
                <CheckCircle2 className="h-3.5 w-3.5 text-cyan-400" />
                <span>Human Resolved ({data.reviewed_by_name || 'SOC Analyst'})</span>
              </div>
            ) : data.triage_tier === 'TIER_1_AUTO' ? (
              <div className="flex items-center space-x-1.5 rounded-full border border-purple-500/40 bg-purple-500/10 px-3 py-1 text-xs font-semibold text-purple-300">
                <Zap className="h-3.5 w-3.5 text-purple-400" />
                <span>Tier 1: Autonomous (High Confidence ≥85%)</span>
              </div>
            ) : data.triage_tier === 'TIER_2_HUMAN_GATED' ? (
              <div className="flex items-center space-x-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-3 py-1 text-xs font-semibold text-amber-300 ring-1 ring-amber-500/30 animate-pulse">
                <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                <span>Tier 2: Gated Human Review Required</span>
              </div>
            ) : (
              <div className="flex items-center space-x-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-300">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                <span>Tier 3: Autonomous Cleared</span>
              </div>
            )}
            <button
              onClick={fetchDisposition}
              className="rounded-lg border border-slate-700 bg-slate-800/80 p-1.5 text-slate-400 hover:border-slate-600 hover:text-slate-200"
              title="Refresh triage disposition"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        )}
      </div>

      {/* Success / Error Banners */}
      {successMessage && (
        <div className="flex items-center space-x-2 rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3 text-xs text-emerald-300">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{successMessage}</span>
        </div>
      )}
      {error && (
        <div className="flex items-center space-x-2 rounded-lg border border-red-500/30 bg-red-950/20 p-3 text-xs text-red-300">
          <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Learned Precedent Notification Banner (if AI recalled a past human decision) */}
      {data && data.precedents && data.precedents.length > 0 && (
        <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-3.5 text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 font-semibold text-cyan-300">
              <BrainCircuit className="h-4 w-4 shrink-0 text-cyan-400" />
              <span>Continuous Memory Match: Past Precedent Recalled ({data.precedents[0].similarity_score}% DNA Match)</span>
            </div>
            {!isEditing && (
              <button
                type="button"
                onClick={() => handleApplyPrecedent(data.precedents[0])}
                className="rounded border border-cyan-500/40 bg-cyan-500/10 px-2 py-1 text-[11px] font-semibold text-cyan-300 hover:bg-cyan-500/20"
              >
                Apply Precedent
              </button>
            )}
          </div>
          <p className="mt-1.5 text-slate-300 text-[11px]">
            <strong className="text-slate-200">Precedent by {data.precedents[0].reviewer_name}:</strong>{' '}
            {data.precedents[0].analyst_notes || 'Confirmed pattern match.'}
          </p>
        </div>
      )}

      {/* VIEW 1: RESOLVED STATE (Clean Executive Audit Summary) */}
      {data && data.is_resolved && !isEditing && (
        <div className="rounded-xl border border-cyan-500/20 bg-gradient-to-br from-slate-900/90 to-slate-950/90 p-4 space-y-3.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold border ${currentVerdictMeta?.summaryClass || 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'}`}>
                <Check className="w-3.5 h-3.5" />
                {currentVerdictMeta?.label || data.verdict?.replace(/_/g, ' ')}
              </span>
              <span className="text-[11px] text-slate-400">
                Authoritative disposition by <strong className="text-slate-200">{data.reviewed_by_name || 'SOC Analyst'}</strong>
              </span>
            </div>

            <button
              onClick={() => setIsEditing(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg border border-slate-700 bg-slate-800 text-xs font-semibold text-slate-200 hover:bg-slate-700 hover:border-slate-600 transition-colors"
            >
              <Edit3 className="w-3.5 h-3.5 text-cyan-400" />
              Modify Resolution
            </button>
          </div>

          {/* Forensic Assessment Rationale Quote */}
          {data.analyst_notes && (
            <div className="rounded-lg bg-slate-950/80 border border-slate-800/80 p-3 text-xs text-slate-200">
              <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider flex items-center gap-1.5 mb-1">
                <Quote className="h-3 w-3 text-cyan-400" />
                Analyst Forensic Rationale
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed italic">
                "{data.analyst_notes}"
              </p>
            </div>
          )}

          {/* Enforced Remediation Actions */}
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Remediations:</span>
              {data.remediation_actions && data.remediation_actions.length > 0 ? (
                data.remediation_actions.map((act) => {
                  const label = REMEDIATION_OPTIONS.find((r) => r.id === act)?.label || act;
                  return (
                    <span key={act} className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-500/30 text-[10px] text-cyan-300 font-medium">
                      <Check className="w-2.5 h-2.5" />
                      {label}
                    </span>
                  );
                })
              ) : (
                <span className="text-[10px] text-slate-500 italic">No per-host perimeter blocks enforced</span>
              )}
            </div>

            <div className="flex items-center gap-1 text-[10px] text-emerald-400/90 font-mono">
              <BrainCircuit className="w-3 h-3 text-emerald-400" />
              <span>Continuous Memory: Active in pgvector &amp; Redis</span>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 2: AUTONOMOUS HIGH CONFIDENCE (TIER 1) */}
      {data && !data.is_resolved && data.triage_tier === 'TIER_1_AUTO' && !isEditing && (
        <div className="rounded-xl border border-purple-500/30 bg-purple-950/15 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-purple-500/20 border border-purple-500/40 text-purple-300">
                <Zap className="w-4 h-4" />
              </div>
              <div>
                <div className="text-xs font-bold text-purple-200">
                  Autonomous Triage: Conclusive Threat Telemetry (Confidence ≥85%)
                </div>
                <div className="text-[11px] text-purple-300/80">
                  Overwhelming evidence verified without contradictory signals. Human review gating is bypassed.
                </div>
              </div>
            </div>

            <button
              onClick={() => setIsEditing(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg border border-purple-500/40 bg-purple-500/10 text-xs font-semibold text-purple-200 hover:bg-purple-500/20 transition-colors"
            >
              <Sliders className="w-3.5 h-3.5" />
              Manual Analyst Override
            </button>
          </div>

          <div className="rounded-lg bg-slate-950/60 border border-purple-500/20 p-2.5 text-[11px] text-slate-300 flex items-center justify-between">
            <span>
              Autonomous containment policies ready to execute. AI and heuristic models agree with &gt;85% certainty.
            </span>
            <span className="font-mono text-[10px] text-purple-300">TIER_1_AUTO</span>
          </div>
        </div>
      )}

      {/* VIEW 3: AUTONOMOUS CLEARED (TIER 3) */}
      {data && !data.is_resolved && data.triage_tier === 'TIER_3_AUTO_CLEARED' && !isEditing && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/15 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div>
                <div className="text-xs font-bold text-emerald-200">
                  Autonomous Triage: Cleared Benign Business Email
                </div>
                <div className="text-[11px] text-emerald-300/80">
                  Authentication passed and zero malicious indicators detected.
                </div>
              </div>
            </div>

            <button
              onClick={() => setIsEditing(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/20 transition-colors"
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              Flag for Review
            </button>
          </div>
        </div>
      )}

      {/* VIEW 4: ACTIVE REVIEW FORM (TIER 2 HUMAN GATED OR MANUAL OVERRIDE) */}
      {(isEditing || (data && !data.is_resolved && data.triage_tier === 'TIER_2_HUMAN_GATED')) && (
        <form onSubmit={handleSubmit} className="space-y-4 pt-1">
          {/* Conflict Diagnostics Alert (When Tier 2 is Gated) */}
          {data && data.triage_tier === 'TIER_2_HUMAN_GATED' && data.conflict_reasons?.length > 0 && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3.5 text-xs space-y-1.5">
              <div className="flex items-center space-x-2 text-amber-400 font-semibold">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>Signal Ambiguity Diagnostics (Why Human Input is Gated):</span>
              </div>
              <ul className="pl-6 list-disc text-slate-300 space-y-1 text-[11px]">
                {data.conflict_reasons.map((reason, idx) => (
                  <li key={idx} className="leading-relaxed">
                    {reason}
                  </li>
                ))}
              </ul>
              <p className="text-slate-400 italic text-[10px]">
                Your authoritative disposition will establish ground truth and train the platform memory to automate future similar encounters.
              </p>
            </div>
          )}

          {/* Form Cancel / Collapse Button if opened from Resolved or Tier 1 */}
          {(data?.is_resolved || data?.triage_tier === 'TIER_1_AUTO' || data?.triage_tier === 'TIER_3_AUTO_CLEARED') && (
            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => setIsEditing(false)}
                className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
              >
                <X className="w-3.5 h-3.5" />
                Cancel / Keep Current Status
              </button>
            </div>
          )}

          {/* Verdict Selection */}
          <div>
            <label className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-300">
              1. Authoritative Verdict Selection
            </label>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 md:grid-cols-3">
              {VERDICT_OPTIONS.map((opt) => {
                const isSelected = selectedVerdict === opt.id;
                return (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setSelectedVerdict(opt.id)}
                    className={`flex flex-col items-start rounded-lg border p-2.5 text-left transition-all ${
                      isSelected ? opt.activeClass : opt.badgeClass
                    }`}
                  >
                    <div className="flex w-full items-center justify-between">
                      <span className="text-xs font-bold">{opt.label}</span>
                      {isSelected && <Check className="h-3.5 w-3.5" />}
                    </div>
                    <span className="mt-1 text-[10px] text-slate-400 leading-tight line-clamp-2">
                      {opt.desc}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Assessment Notes & Rationale (AI Training Feedback) */}
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                2. Forensic Assessment Rationale (Trains Continuous Memory)
              </label>
              <span className="text-[10px] text-slate-500 font-mono">Vectorized into pgvector &amp; Redis</span>
            </div>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              placeholder="Document investigative observations and technical rationale (e.g. why legitimate auth was abused, specific lure tactics, or infrastructure compromise indicators)..."
              className="w-full rounded-lg border border-slate-700 bg-slate-950/80 p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-sans"
            />

            {/* Quick Rationale Templates */}
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] text-slate-500 flex items-center">
                <Tag className="mr-1 h-3 w-3" /> Templates:
              </span>
              {QUICK_TEMPLATES.map((tpl, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => setNotes(tpl)}
                  className="rounded border border-slate-800 bg-slate-800/50 px-2 py-0.5 text-[10px] text-slate-400 hover:border-slate-700 hover:text-slate-200 transition-colors truncate max-w-xs"
                  title={tpl}
                >
                  {tpl}
                </button>
              ))}
            </div>
          </div>

          {/* Remediation & Containment Actions */}
          <div>
            <label className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-300">
              3. Containment &amp; Remediation Enforcement
            </label>
            <div className="flex flex-wrap gap-2">
              {REMEDIATION_OPTIONS.map((act) => {
                const active = remediationActions.includes(act.id);
                return (
                  <button
                    key={act.id}
                    type="button"
                    onClick={() => handleToggleAction(act.id)}
                    className={`flex items-center space-x-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                      active
                        ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300 ring-1 ring-cyan-500/40'
                        : 'border-slate-700 bg-slate-800/60 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                    }`}
                  >
                    <div
                      className={`flex h-3.5 w-3.5 items-center justify-center rounded border ${
                        active ? 'border-cyan-400 bg-cyan-500 text-slate-950' : 'border-slate-600'
                      }`}
                    >
                      {active && <Check className="h-2.5 w-2.5 stroke-[3]" />}
                    </div>
                    <span>{act.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Submit Button */}
          <div className="flex items-center justify-between border-t border-slate-800/80 pt-3.5">
            <div className="text-[10px] text-slate-500">
              Audit logging: action is stamped with your analyst ID and timestamp in immutable system logs.
            </div>
            <div className="flex items-center gap-2">
              {isEditing && (data?.is_resolved || data?.triage_tier === 'TIER_1_AUTO') && (
                <button
                  type="button"
                  onClick={() => setIsEditing(false)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700 transition-colors"
                >
                  Cancel
                </button>
              )}
              <button
                type="submit"
                disabled={submitting}
                className="flex items-center space-x-2 rounded-lg border border-cyan-500 bg-cyan-600/30 px-4 py-2 text-xs font-semibold text-cyan-200 shadow-md transition-all hover:bg-cyan-600/50 hover:text-white disabled:opacity-50"
              >
                {submitting ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    <span>Vectorizing Memory...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-3.5 w-3.5" />
                    <span>Submit Disposition &amp; Train AI Memory</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
};
