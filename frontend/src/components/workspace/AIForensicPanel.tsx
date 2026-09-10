import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Cpu,
  CheckCircle2,
  ArrowRight,
  Activity,
} from 'lucide-react';
import {
  getAIThreatReasoning,
  AIThreatReasoningResponse,
  AIReasoningItem,
} from '../../services/api';

interface AIForensicPanelProps {
  emailId: string;
}

export const AIForensicPanel: React.FC<AIForensicPanelProps> = ({ emailId }) => {
  const [data, setData] = useState<AIThreatReasoningResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchExplanation = async () => {
    if (!emailId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await getAIThreatReasoning(emailId);
      setData(res);
    } catch (err: any) {
      console.error('Failed to fetch AI threat reasoning:', err);
      setError(err?.response?.data?.detail || 'Failed to generate threat reasoning.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExplanation();
  }, [emailId]);

  const getClassificationBadge = (cls: string) => {
    const c = (cls || '').toLowerCase();
    if (c === 'phishing' || c === 'fraud' || c === 'bec') {
      return {
        bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
        label: c.toUpperCase(),
        icon: ShieldAlert,
      };
    }
    if (c === 'suspicious' || c === 'impersonation') {
      return {
        bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
        label: c.toUpperCase(),
        icon: AlertTriangle,
      };
    }
    return {
      bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
      label: 'LEGITIMATE',
      icon: ShieldCheck,
    };
  };

  const badge = getClassificationBadge(data?.classification || 'legitimate');
  const BadgeIcon = badge.icon;

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden backdrop-blur-sm">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-slate-100">
                AI Forensic Threat Reasoning
              </h3>
              <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                <Cpu className="w-3 h-3 text-cyan-400" />
                Groq LPUs / RAG Grounded
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Selective forensic interpretation grounded strictly in verified headers, infrastructure, and pgvector memory
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {data && (
            <div
              className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${badge.bg}`}
            >
              <BadgeIcon className="w-3.5 h-3.5" />
              <span>{badge.label}</span>
              <span className="text-[10px] opacity-75 font-mono ml-1">
                ({Math.round(data.confidence * 100)}% conf)
              </span>
            </div>
          )}

          <button
            onClick={fetchExplanation}
            disabled={loading}
            title="Refresh AI Threat Reasoning"
            className="p-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Body Content */}
      {loading && !data && (
        <div className="py-12 flex flex-col items-center justify-center text-center">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mb-3" />
          <p className="text-sm text-slate-300 font-medium">
            Synthesizing forensic evidence via Groq RAG engine...
          </p>
          <p className="text-xs text-slate-500 mt-1">
            Grounding claims in headers, relay topology, IOC reputations, and pgvector clusters
          </p>
        </div>
      )}

      {error && (
        <div className="py-6 px-4 my-4 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={fetchExplanation}
            className="px-2 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-medium ml-3"
          >
            Retry
          </button>
        </div>
      )}

      {data && (
        <div className="mt-5 space-y-6">
          {/* Section 1: WHY FLAGGED (Reasoning list) */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                Why Flagged (Forensic Drivers)
              </h4>
              <span className="text-[11px] text-slate-500 font-mono">
                {data.reasoning.length} verified evidence points
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2.5">
              {data.reasoning.map((item: AIReasoningItem, idx: number) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2.5">
                      <span className="mt-0.5 text-xs font-mono text-cyan-400/80 font-semibold">
                        {idx + 1}.
                      </span>
                      <div>
                        <div className="text-xs font-semibold text-slate-200">
                          {item.finding}
                        </div>
                        <div className="text-xs text-slate-400 mt-1 leading-relaxed">
                          {item.evidence}
                        </div>
                      </div>
                    </div>
                    <span className="shrink-0 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">
                      {Math.round(item.confidence * 100)}% conf
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 2: Attack Intent & Social Engineering Tags */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            {/* Attack Intent */}
            <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800">
              <h5 className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-rose-400" />
                Attack Intent / Objectives
              </h5>
              <div className="flex flex-wrap gap-1.5">
                {data.attack_intent.map((intent: string, i: number) => (
                  <span
                    key={i}
                    className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-rose-500/10 border border-rose-500/20 text-rose-300"
                  >
                    {intent}
                  </span>
                ))}
              </div>
            </div>

            {/* Social Engineering */}
            <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800">
              <h5 className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                Social Engineering & Urgency Signals
              </h5>
              <div className="flex flex-wrap gap-1.5">
                {data.social_engineering_indicators.map((ind: string, i: number) => (
                  <span
                    key={i}
                    className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-amber-500/10 border border-amber-500/20 text-amber-300"
                  >
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Section 3: Recommended Actions */}
          <div className="p-4 rounded-lg bg-indigo-950/20 border border-indigo-900/30">
            <h5 className="text-[11px] font-mono uppercase tracking-wider text-indigo-300 mb-2.5 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
              Recommended SOC Response Steps
            </h5>
            <ul className="space-y-1.5">
              {data.recommended_actions.map((act: string, i: number) => (
                <li key={i} className="text-xs text-slate-300 flex items-start gap-2">
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{act}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
