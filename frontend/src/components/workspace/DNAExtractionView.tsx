import React, { useEffect, useState, useMemo } from 'react';
import {
  Dna,
  ShieldCheck,
  Globe,
  FileText,
  Network,
  Sparkles,
  CheckCircle2,
  Terminal,
  Activity,
  Cpu,
} from 'lucide-react';
import { JobRecord } from '../../services/api';

interface DNAExtractionViewProps {
  job: JobRecord | null;
  filename?: string;
  onCompleted?: () => void;
}

interface StrandStep {
  id: string;
  name: string;
  code: string;
  icon: React.FC<{ className?: string }>;
  description: string;
  targetProgress: number;
  color: string;
  glowColor: string;
  badgeBg: string;
}

const STRAND_STEPS: StrandStep[] = [
  {
    id: 'technical',
    name: 'Technical Strand',
    code: 'STRUCTURAL_GENOME',
    icon: ShieldCheck,
    description: 'Parsing RFC 822 MIME structure, DKIM-Signature cryptographic seals, SPF & DMARC alignment',
    targetProgress: 20,
    color: 'text-blue-600',
    glowColor: 'shadow-blue-500/20 border-blue-500/40',
    badgeBg: 'bg-blue-50 text-blue-700 border-blue-200',
  },
  {
    id: 'content',
    name: 'Content Strand',
    code: 'PSYCHOLINGUISTIC_VECTOR',
    icon: FileText,
    description: 'Tokenizing NLP urgency density, credential harvesting signals & brand spoofing indicators',
    targetProgress: 40,
    color: 'text-indigo-600',
    glowColor: 'shadow-indigo-500/20 border-indigo-500/40',
    badgeBg: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  },
  {
    id: 'infrastructure',
    name: 'Infrastructure Strand',
    code: 'TRANSIT_ROUTING_HOP',
    icon: Globe,
    description: 'Triangulating MTA relay latency, IP ASNs, BGP route telemetry & infrastructure geolocation',
    targetProgress: 60,
    color: 'text-sky-600',
    glowColor: 'shadow-sky-500/20 border-sky-500/40',
    badgeBg: 'bg-sky-50 text-sky-700 border-sky-200',
  },
  {
    id: 'behavioral',
    name: 'Behavioral Strand',
    code: 'CAMPAIGN_CORRELATION',
    icon: Network,
    description: 'Decompiling weaponized URLs, attachments & cross-referencing global phishing cluster graphs',
    targetProgress: 80,
    color: 'text-emerald-600',
    glowColor: 'shadow-emerald-500/20 border-emerald-500/40',
    badgeBg: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  },
  {
    id: 'synthesis',
    name: 'Genetic Vector Synthesis',
    code: 'EMBEDDING_1536D_SYNTHESIS',
    icon: Dna,
    description: 'Calculating 1536-dimensional semantic DNA embeddings & synthesizing tamper-evident forensic seal',
    targetProgress: 100,
    color: 'text-violet-600',
    glowColor: 'shadow-violet-500/20 border-violet-500/40',
    badgeBg: 'bg-violet-50 text-violet-700 border-violet-200',
  },
];

export const DNAExtractionView: React.FC<DNAExtractionViewProps> = ({
  job,
  filename,
  onCompleted,
}) => {
  const [animatedProgress, setAnimatedProgress] = useState<number>(10);
  const [tick, setTick] = useState<number>(0);

  // Smoothly interpolate progress toward job.progress or increment simulated sequencing
  useEffect(() => {
    const target = Math.max(job?.progress || 15, 15);
    const interval = setInterval(() => {
      setAnimatedProgress((prev) => {
        if (prev < target) {
          const step = Math.max(1, Math.floor((target - prev) * 0.3));
          return Math.min(target, prev + step);
        }
        if (job?.status === 'COMPLETED') {
          return 100;
        }
        // Small organic fluctuation during deep analysis
        if (prev < 95 && target < 95) {
          return Math.min(95, prev + 1);
        }
        return prev;
      });
      setTick((t) => t + 1);
    }, 180);

    return () => clearInterval(interval);
  }, [job?.progress, job?.status]);

  useEffect(() => {
    if (animatedProgress >= 100 && job?.status === 'COMPLETED' && onCompleted) {
      const timer = setTimeout(() => {
        onCompleted();
      }, 700);
      return () => clearTimeout(timer);
    }
  }, [animatedProgress, job?.status, onCompleted]);

  // Generate dynamic DNA helix nodes based on tick
  const helixPairs = useMemo(() => {
    const count = 16;
    const pairs = [];
    for (let i = 0; i < count; i++) {
      const phase = (tick * 0.15) + (i * 0.45);
      const sinVal = Math.sin(phase);
      const cosVal = Math.cos(phase);
      // Normalized depth & position
      const leftPercent = 50 + sinVal * 42;
      const rightPercent = 50 - sinVal * 42;
      const opacity = 0.4 + (cosVal + 1) * 0.3;
      const isFront = cosVal > 0;
      pairs.push({
        idx: i,
        leftPercent,
        rightPercent,
        opacity,
        isFront,
        baseA: ['A', 'G', 'T', 'C'][i % 4],
        baseB: ['T', 'C', 'A', 'G'][i % 4],
      });
    }
    return pairs;
  }, [tick]);

  const currentStrandIndex = useMemo(() => {
    if (animatedProgress >= 95) return 4;
    if (animatedProgress >= 75) return 3;
    if (animatedProgress >= 55) return 2;
    if (animatedProgress >= 30) return 1;
    return 0;
  }, [animatedProgress]);

  const activeStrand = STRAND_STEPS[currentStrandIndex];

  return (
    <div className="rounded-3xl border border-workspace-border bg-gradient-to-b from-workspace-card via-workspace to-workspace-card p-6 md:p-10 shadow-lg relative overflow-hidden animate-fade-in">
      {/* Background ambient forensic grid glow */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(37,99,235,0.08),rgba(255,255,255,0))] pointer-events-none" />

      {/* Top Header Status */}
      <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-workspace-border/80">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-2xl bg-brand-soft text-brand flex items-center justify-center shadow-xs border border-brand/20 animate-pulse">
            <Dna className="w-6 h-6 text-brand" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-extrabold uppercase tracking-widest text-brand px-2 py-0.5 rounded-md bg-brand-soft border border-brand/20">
                Live Sequencing Pipeline
              </span>
              <span className="text-[11px] font-mono text-text-muted">
                Thread: {job?.job_id ? `SEQ-${job.job_id.slice(0, 8)}` : 'ACTIVE-INGEST'}
              </span>
            </div>
            <h2 className="text-xl font-extrabold text-text-primary tracking-tight mt-1 flex items-center gap-2">
              Multi-Strand DNA Extraction
              <Sparkles className="w-4 h-4 text-amber-500 animate-spin" style={{ animationDuration: '6s' }} />
            </h2>
            <p className="text-xs text-text-muted mt-0.5">
              Target Artifact: <strong className="text-text-primary font-mono">{filename || 'RFC 822 Evidence Email'}</strong>
            </p>
          </div>
        </div>

        {/* Real-time Percentage & Stage Pill */}
        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-2xl font-black text-brand tabular-nums tracking-tight">
              {animatedProgress}%
            </div>
            <div className="text-[11px] text-text-muted font-medium">
              {animatedProgress >= 100 ? 'Sequencing Finalized' : 'Synthesizing Strands'}
            </div>
          </div>
          <div className="w-14 h-14 rounded-2xl border-2 border-brand/30 bg-workspace p-1 flex items-center justify-center">
            <div className="relative w-full h-full flex items-center justify-center">
              <Activity className="w-6 h-6 text-brand animate-pulse" />
            </div>
          </div>
        </div>
      </div>

      {/* Main Dual-Column: Interactive DNA Helix Animation + Strand Decompilation Board */}
      <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 py-8 items-center">
        {/* Left Col (5 cols): Interactive Rotating DNA Helix Canvas */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center p-6 rounded-2xl bg-workspace/60 border border-workspace-border/70 backdrop-blur-xs shadow-xs relative overflow-hidden">
          <div className="text-[11px] font-bold uppercase tracking-wider text-text-muted mb-4 flex items-center gap-1.5 self-start">
            <Cpu className="w-3.5 h-3.5 text-brand" />
            <span>Helical Base-Pair Sequencing</span>
          </div>

          {/* DNA Helix Visualization Strip */}
          <div className="w-full max-w-xs h-72 relative flex flex-col justify-between py-2 select-none">
            {helixPairs.map((p) => (
              <div key={p.idx} className="relative w-full h-3 flex items-center">
                {/* Connecting Base-Pair Rung */}
                <div
                  className="absolute h-[1.5px] bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 transition-all duration-150"
                  style={{
                    left: `${Math.min(p.leftPercent, p.rightPercent)}%`,
                    width: `${Math.abs(p.leftPercent - p.rightPercent)}%`,
                    opacity: p.opacity * 0.7,
                  }}
                />

                {/* Left Helix Strand Node (Alpha Strand) */}
                <div
                  className="absolute w-3 h-3 -ml-1.5 rounded-full bg-blue-500 shadow-sm transition-all duration-150 flex items-center justify-center"
                  style={{
                    left: `${p.leftPercent}%`,
                    opacity: p.opacity,
                    transform: `scale(${0.7 + p.opacity * 0.5})`,
                    zIndex: p.isFront ? 10 : 2,
                    boxShadow: p.isFront ? '0 0 8px rgba(37,99,235,0.8)' : 'none',
                  }}
                >
                  <span className="text-[7px] font-mono font-bold text-white select-none">
                    {p.baseA}
                  </span>
                </div>

                {/* Right Helix Strand Node (Beta Strand) */}
                <div
                  className="absolute w-3 h-3 -ml-1.5 rounded-full bg-violet-500 shadow-sm transition-all duration-150 flex items-center justify-center"
                  style={{
                    left: `${p.rightPercent}%`,
                    opacity: 1.2 - p.opacity * 0.5,
                    transform: `scale(${0.7 + (1.2 - p.opacity * 0.5) * 0.5})`,
                    zIndex: !p.isFront ? 10 : 2,
                    boxShadow: !p.isFront ? '0 0 8px rgba(139,92,246,0.8)' : 'none',
                  }}
                >
                  <span className="text-[7px] font-mono font-bold text-white select-none">
                    {p.baseB}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* Helix Live Telemetry Tag */}
          <div className="w-full mt-4 pt-3 border-t border-workspace-border/60 flex items-center justify-between text-[11px] text-text-muted">
            <span className="font-mono">Genomic Strands: 5/5</span>
            <span className="font-semibold text-brand flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-brand animate-ping" />
              Active Transduction
            </span>
          </div>
        </div>

        {/* Right Col (7 cols): 5-Strand Progression Stepper */}
        <div className="lg:col-span-7 space-y-3">
          <div className="text-[11px] font-bold uppercase tracking-wider text-text-muted mb-2 flex items-center justify-between">
            <span>Strand Extraction Progression</span>
            <span className="text-brand font-mono font-semibold">
              Phase {currentStrandIndex + 1} of 5 Active
            </span>
          </div>

          {STRAND_STEPS.map((step, idx) => {
            const isFinished = animatedProgress >= step.targetProgress;
            const isCurrent = currentStrandIndex === idx && !isFinished;
            const Icon = step.icon;

            return (
              <div
                key={step.id}
                className={`p-3.5 rounded-2xl border transition-all duration-300 ${
                  isFinished
                    ? 'bg-emerald-500/5 border-emerald-500/30'
                    : isCurrent
                    ? `bg-workspace-card border-brand shadow-sm ${step.glowColor}`
                    : 'bg-workspace/40 border-workspace-border/60 opacity-60'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 transition-colors ${
                      isFinished
                        ? 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                        : isCurrent
                        ? 'bg-brand text-white shadow-xs'
                        : 'bg-workspace text-text-muted border border-workspace-border'
                    }`}
                  >
                    {isFinished ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                    ) : (
                      <Icon className="w-4 h-4" />
                    )}
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-text-primary tracking-tight">
                          {step.name}
                        </span>
                        <span className={`text-[9.5px] font-mono px-1.5 py-0.2 rounded ${step.badgeBg}`}>
                          {step.code}
                        </span>
                      </div>
                      <span className="text-[11px] font-mono tabular-nums font-bold">
                        {isFinished ? (
                          <span className="text-emerald-600">COMPLETE</span>
                        ) : isCurrent ? (
                          <span className="text-brand animate-pulse">PROCESSING...</span>
                        ) : (
                          <span className="text-text-muted">QUEUED</span>
                        )}
                      </span>
                    </div>

                    <p className="text-[11.5px] text-text-muted mt-1 leading-snug">
                      {step.description}
                    </p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom Live Terminal Bar */}
      <div className="relative z-10 mt-2 p-3.5 rounded-2xl bg-workspace border border-workspace-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2.5 font-mono text-text-secondary truncate">
          <Terminal className="w-4 h-4 text-brand shrink-0" />
          <span className="text-text-muted">Status:</span>
          <span className="font-semibold text-text-primary truncate">
            {animatedProgress >= 100
              ? '✓ DNA Helix Compiled. Unlocking Multi-Strand Dossier...'
              : `Executing: ${activeStrand?.description || 'Ingesting email artifact...'}`}
          </span>
        </div>

        <div className="flex items-center gap-3 shrink-0 self-end sm:self-auto">
          <div className="h-2 w-32 rounded-full bg-workspace-card border border-workspace-border overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-blue-500 to-indigo-600 rounded-full transition-all duration-300 ease-out"
              style={{ width: `${animatedProgress}%` }}
            />
          </div>
          <span className="font-mono font-bold text-brand tabular-nums text-[11px]">
            {animatedProgress}%
          </span>
        </div>
      </div>
    </div>
  );
};

export default DNAExtractionView;
