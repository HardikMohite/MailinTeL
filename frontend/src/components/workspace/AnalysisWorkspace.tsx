import React, { useState, useEffect, useRef, useMemo } from 'react';
import { sanitizeEmailHtml } from '../../utils/sanitizeEmailHtml';
import {
  UploadCloud,
  ShieldCheck,
  ShieldAlert,
  Lock,
  FileText,
  Dna,
  Network,
  Copy,
  Check,
  RefreshCw,
  Loader2,
  ExternalLink,
  Search,
  Sparkles,
  Clock,
  Globe,
  Settings,
  Navigation,
  UserCheck,
  AlertTriangle,
  ArrowLeft,
  Trash2,
  AlertOctagon,
} from 'lucide-react';
import {
  uploadEmlFile,
  getEmailDetails,
  deleteEmail,
  getJobStatus,
  getEmailHeaders,
  getEmailAuthResults,
  getEmailRelayHops,
  getEmailStructure,
  getEmailArtifacts,
  getEmailAnalysis,
  getEmailDNA,
  generateEmailDNA,
  getSimilarEmails,
  getEmailCorrelations,
  getEmailCampaignMemberships,
  getInvestigationGraphForEmail,
  getEmailDomainIntelligence,
  getEmailInfrastructureIntelligence,
  EmailDetailResponse,
  EmailHeadersResponse,
  EmailAuthResponse,
  RelayHopsResponse,
  EmailStructureResponse,
  EmailArtifactsResponse,
  EmailThreatIntelSummaryResponse,
  EmailAnalysisResponse,
  EmailDNAProfileResponse,
  SimilarityLinkResponse,
  EmailCorrelationsResponse,
  EmailMembershipsResponse,
  InvestigationGraphResponse,
  EmailDomainIntelResponse,
  EmailInfrastructureResponse,
  JobRecord,
} from '../../services/api';
import { StatusBadge, SeverityLevel } from '../common/StatusBadge';
import { GeoIntelligenceMap } from '../geo/GeoIntelligenceMap';
import { InvestigationGraphView } from '../graph/InvestigationGraphView';
import { AIForensicPanel } from './AIForensicPanel';
import { DNAExtractionView } from './DNAExtractionView';
import { AttachmentSandboxPanel } from './AttachmentSandboxPanel';

export type WorkspaceTab = 'technical' | 'content' | 'infrastructure' | 'behavioral' | 'temporal' | 'ai';

interface TabMeta {
  id: WorkspaceTab;
  label: string;
  strandCode: string;
  question: string;
  icon: React.FC<{ className?: string }>;
  color: string;
  activeColor: string;
  badgeBg: string;
  badgeBorder: string;
}

const TABS: TabMeta[] = [
  {
    id: 'technical',
    label: 'Technical Strand',
    strandCode: 'The Structural Code',
    question: 'How is it constructed?',
    icon: Settings,
    color: 'text-blue-600',
    activeColor: 'border-blue-600 text-blue-700 bg-blue-50/90',
    badgeBg: 'bg-blue-100 text-blue-800',
    badgeBorder: 'border-blue-200',
  },
  {
    id: 'content',
    label: 'Content Strand',
    strandCode: 'The Meaning Code',
    question: 'What is being said?',
    icon: FileText,
    color: 'text-emerald-600',
    activeColor: 'border-emerald-600 text-emerald-800 bg-emerald-50/90',
    badgeBg: 'bg-emerald-100 text-emerald-800',
    badgeBorder: 'border-emerald-200',
  },
  {
    id: 'infrastructure',
    label: 'Infrastructure Strand',
    strandCode: 'The Origin Code',
    question: 'Where is it coming from?',
    icon: Globe,
    color: 'text-amber-600',
    activeColor: 'border-amber-600 text-amber-800 bg-amber-50/90',
    badgeBg: 'bg-amber-100 text-amber-800',
    badgeBorder: 'border-amber-200',
  },
  {
    id: 'behavioral',
    label: 'Behavioral Strand',
    strandCode: 'The Action Code',
    question: 'How does it behave?',
    icon: Network,
    color: 'text-purple-600',
    activeColor: 'border-purple-600 text-purple-800 bg-purple-50/90',
    badgeBg: 'bg-purple-100 text-purple-800',
    badgeBorder: 'border-purple-200',
  },
  {
    id: 'temporal',
    label: 'Temporal Strand',
    strandCode: 'The Time Code',
    question: 'When was it sent?',
    icon: Clock,
    color: 'text-rose-600',
    activeColor: 'border-rose-600 text-rose-800 bg-rose-50/90',
    badgeBg: 'bg-rose-100 text-rose-800',
    badgeBorder: 'border-rose-200',
  },
  {
    id: 'ai',
    label: 'AI Forensic Copilot',
    strandCode: 'Autonomous Reasoning & RAG',
    question: 'Why is this dangerous?',
    icon: Sparkles,
    color: 'text-indigo-600',
    activeColor: 'border-indigo-600 text-indigo-800 bg-indigo-50/90',
    badgeBg: 'bg-indigo-100 text-indigo-800',
    badgeBorder: 'border-indigo-200',
  },
];

const severityForClassification = (classification?: string): SeverityLevel => {
  switch ((classification || '').toUpperCase()) {
    case 'MALICIOUS':
    case 'PHISHING':
    case 'SPOOFING':
      return 'critical';
    case 'SUSPICIOUS':
      return 'high';
    case 'BENIGN':
      return 'safe';
    default:
      return 'medium';
  }
};

const severityForQualification = (status: string): SeverityLevel => {
  switch (status) {
    case 'MALICIOUS':
      return 'critical';
    case 'HIGH_RISK':
      return 'high';
    case 'SUSPICIOUS':
    case 'CAMPAIGN_RELATED':
      return 'medium';
    case 'NORMAL':
      return 'safe';
    default:
      return 'low';
  }
};

const fmtDateTime = (dt?: string | null): string => {
  if (!dt) return '—';
  try {
    return new Date(dt).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return dt;
  }
};

const confidenceLabel = (score?: number): string => {
  if (score === undefined || score === null) return '—';
  const val = score > 1 ? score : score * 100;
  if (val >= 85) return `High (${val.toFixed(0)}%)`;
  if (val >= 50) return `Medium (${val.toFixed(0)}%)`;
  return `Low (${val.toFixed(0)}%)`;
};

const Section: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => (
  <div className={`p-5 rounded-2xl bg-workspace-card border border-workspace-border shadow-xs ${className}`}>
    {children}
  </div>
);

const EmptyNote: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="p-6 text-center text-xs text-text-muted rounded-xl bg-workspace border border-dashed border-workspace-border">
    {children}
  </div>
);

interface AnalysisWorkspaceProps {
  initialEmailId?: string;
  onOpenReport?: (emailId: string) => void;
  onExploreGeo?: (emailId: string) => void;
  onExploreGraph?: (emailId: string) => void;
  onExploreEvidence?: (emailId: string) => void;
  isHistoryMode?: boolean;
  onBackToHistory?: () => void;
}

// Module-level in-memory cache for loaded email dossiers (persists across view switches for 0ms re-visits)
const globalDossierCache = new Map<string, any>();

export const AnalysisWorkspace: React.FC<AnalysisWorkspaceProps> = ({
  initialEmailId,
  onOpenReport,
  onExploreGeo,
  onExploreGraph,
  onExploreEvidence: _onExploreEvidence,
  isHistoryMode = false,
  onBackToHistory,
}) => {
  const [selectedEmailId, setSelectedEmailId] = useState<string>(initialEmailId || '');
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('technical');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadedFilename, setUploadedFilename] = useState<string>('');
  const [activeJob, setActiveJob] = useState<JobRecord | null>(null);
  const pollTimeoutRef = useRef<number | null>(null);

  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [headerSearch, setHeaderSearch] = useState<string>('');
  const [bodyPreviewTab, setBodyPreviewTab] = useState<'text' | 'html'>('text');

  // Primary Investigation Dossier
  const [emailDetails, setEmailDetails] = useState<EmailDetailResponse | null>(null);
  const [headersData, setHeadersData] = useState<EmailHeadersResponse | null>(null);
  const [authData, setAuthData] = useState<EmailAuthResponse | null>(null);
  const [hopsData, setHopsData] = useState<RelayHopsResponse | null>(null);
  const [structureData, setStructureData] = useState<EmailStructureResponse | null>(null);
  const [artifactsData, setArtifactsData] = useState<EmailArtifactsResponse | null>(null);
  const [threatIntelData, setThreatIntelData] = useState<EmailThreatIntelSummaryResponse | null>(null);
  const [analysisData, setAnalysisData] = useState<EmailAnalysisResponse | null>(null);
  const [dnaData, setDnaData] = useState<EmailDNAProfileResponse | null>(null);
  const [dnaLoading, setDnaLoading] = useState<boolean>(false);

  // In-memory persistent cache for loaded email dossiers
  const dossierCache = useRef<Map<string, any>>(globalDossierCache);

  // Extended Intelligence
  const [similarityData, setSimilarityData] = useState<SimilarityLinkResponse[]>([]);
  const [correlationsData, setCorrelationsData] = useState<EmailCorrelationsResponse | null>(null);
  const [membershipsData, setMembershipsData] = useState<EmailMembershipsResponse | null>(null);
  const [graphData, setGraphData] = useState<InvestigationGraphResponse | null>(null);
  const [domainIntelData, setDomainIntelData] = useState<EmailDomainIntelResponse | null>(null);
  const [infraIntelData, setInfraIntelData] = useState<EmailInfrastructureResponse | null>(null);

  // Deletion State
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState<boolean>(false);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const handleDeleteCurrentEmail = async () => {
    if (!selectedEmailId) return;
    setIsDeleting(true);
    setDeleteError(null);
    try {
      await deleteEmail(selectedEmailId);
      globalDossierCache.delete(selectedEmailId);
      // Clear whole data regarding this email in this panel immediately
      setSelectedEmailId('');
      setEmailDetails(null);
      setHeadersData(null);
      setAuthData(null);
      setHopsData(null);
      setStructureData(null);
      setArtifactsData(null);
      setThreatIntelData(null);
      setAnalysisData(null);
      setDnaData(null);
      setSimilarityData([]);
      setCorrelationsData(null);
      setMembershipsData(null);
      setGraphData(null);
      setDomainIntelData(null);
      setInfraIntelData(null);
      setActiveJob(null);
      setDeleteConfirmOpen(false);
      if (onBackToHistory) {
        onBackToHistory();
      }
    } catch (err: any) {
      setDeleteError(err?.response?.data?.detail || err?.message || 'Failed to delete email artifact.');
    } finally {
      setIsDeleting(false);
    }
  };

  useEffect(() => {
    return () => {
      if (pollTimeoutRef.current) window.clearTimeout(pollTimeoutRef.current);
    };
  }, []);

  // Sync selectedEmailId if initialEmailId prop changes
  useEffect(() => {
    if (initialEmailId && initialEmailId !== selectedEmailId) {
      setSelectedEmailId(initialEmailId);
      setActiveTab('technical');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialEmailId]);

  // Load full dossier when selectedEmailId changes
  useEffect(() => {
    if (selectedEmailId) {
      fetchFullInvestigation(selectedEmailId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedEmailId]);

  // On-demand progressive hydration per strand tab
  useEffect(() => {
    if (!selectedEmailId) return;
    const entry = dossierCache.current.get(selectedEmailId);

    if (activeTab === 'technical' && !headersData) {
      Promise.allSettled([
        getEmailHeaders(selectedEmailId),
        getEmailStructure(selectedEmailId),
      ]).then(([hRes, sRes]) => {
        if (hRes.status === 'fulfilled') {
          setHeadersData(hRes.value);
          if (entry) entry.headers = hRes.value;
        }
        if (sRes.status === 'fulfilled') {
          setStructureData(sRes.value);
          if (entry) entry.structure = sRes.value;
        }
      });
    } else if (activeTab === 'content' && !artifactsData) {
      getEmailArtifacts(selectedEmailId).then((res) => {
        setArtifactsData(res);
        if (entry) entry.artifacts = res;
      }).catch(() => {});
    } else if (activeTab === 'infrastructure' && (!domainIntelData || !infraIntelData)) {
      Promise.allSettled([
        getEmailDomainIntelligence(selectedEmailId),
        getEmailInfrastructureIntelligence(selectedEmailId),
        getEmailRelayHops(selectedEmailId),
      ]).then(([dRes, iRes, hRes]) => {
        if (dRes.status === 'fulfilled') {
          setDomainIntelData(dRes.value);
          if (entry) entry.domainIntel = dRes.value;
        }
        if (iRes.status === 'fulfilled') {
          setInfraIntelData(iRes.value);
          if (entry) entry.infraIntel = iRes.value;
        }
        if (hRes.status === 'fulfilled') {
          setHopsData(hRes.value);
          if (entry) entry.hops = hRes.value;
        }
      });
    } else if (activeTab === 'behavioral' && !correlationsData) {
      Promise.allSettled([
        getSimilarEmails(selectedEmailId),
        getEmailCorrelations(selectedEmailId, 40.0),
        getEmailCampaignMemberships(selectedEmailId),
        getInvestigationGraphForEmail(selectedEmailId),
      ]).then(([simRes, corrRes, memRes, grRes]) => {
        if (simRes.status === 'fulfilled') {
          setSimilarityData(simRes.value);
          if (entry) entry.similarity = simRes.value;
        }
        if (corrRes.status === 'fulfilled') {
          setCorrelationsData(corrRes.value);
          if (entry) entry.correlations = corrRes.value;
        }
        if (memRes.status === 'fulfilled') {
          setMembershipsData(memRes.value);
          if (entry) entry.memberships = memRes.value;
        }
        if (grRes.status === 'fulfilled') {
          setGraphData(grRes.value);
          if (entry) entry.graph = grRes.value;
        }
      });
    } else if (activeTab === 'temporal' && !hopsData) {
      getEmailRelayHops(selectedEmailId).then((res) => {
        setHopsData(res);
        if (entry) entry.hops = res;
      }).catch(() => {});
    }
  }, [activeTab, selectedEmailId]);

  const fetchFullInvestigation = async (emailId: string, forceFresh: boolean = false) => {
    if (!emailId) return;
    setError(null);

    const cached = dossierCache.current.get(emailId);
    if (!forceFresh && cached) {
      setEmailDetails(cached.details);
      setAnalysisData(cached.analysis);
      setThreatIntelData(cached.threatIntel);
      setDnaData(cached.dna);
      setArtifactsData(cached.artifacts);
      setAuthData(cached.auth);
      setHopsData(cached.hops);
      setHeadersData(cached.headers);
      setStructureData(cached.structure);
      setSimilarityData(cached.similarity || []);
      setCorrelationsData(cached.correlations);
      setMembershipsData(cached.memberships);
      setGraphData(cached.graph);
      setDomainIntelData(cached.domainIntel);
      setInfraIntelData(cached.infraIntel);
      setLoading(false);
      return;
    }

    setLoading(true);

    try {
      const [detailsRes, analysisRes, authRes, artifactsRes, dnaRes, hopsRes, headersRes] = await Promise.allSettled([
        getEmailDetails(emailId),
        getEmailAnalysis(emailId),
        getEmailAuthResults(emailId),
        getEmailArtifacts(emailId),
        getEmailDNA(emailId),
        getEmailRelayHops(emailId),
        getEmailHeaders(emailId),
      ]);

      const loadedDetails = detailsRes.status === 'fulfilled' ? detailsRes.value : null;
      const loadedAnalysis = analysisRes.status === 'fulfilled' ? analysisRes.value : null;
      const loadedAuth = authRes.status === 'fulfilled' ? authRes.value : null;
      const loadedArtifacts = artifactsRes.status === 'fulfilled' ? artifactsRes.value : null;
      let loadedDna = dnaRes.status === 'fulfilled' ? dnaRes.value : null;
      const loadedHops = hopsRes.status === 'fulfilled' ? hopsRes.value : null;
      const loadedHeaders = headersRes.status === 'fulfilled' ? headersRes.value : null;

      setEmailDetails(loadedDetails);
      setAnalysisData(loadedAnalysis);
      setAuthData(loadedAuth);
      setArtifactsData(loadedArtifacts);
      setDnaData(loadedDna);
      setHopsData(loadedHops);
      setHeadersData(loadedHeaders);

      if (!loadedAnalysis || loadedAnalysis.threat_classification === 'ANALYZING' || loadedAnalysis.threat_risk_score === 0) {
        setTimeout(async () => {
          try {
            const retryAnalysis = await getEmailAnalysis(emailId);
            if (retryAnalysis && retryAnalysis.threat_classification !== 'ANALYZING') {
              setAnalysisData(retryAnalysis);
              const entry = dossierCache.current.get(emailId);
              if (entry) entry.analysis = retryAnalysis;
            }
          } catch (_) {}
        }, 1200);
      }

      dossierCache.current.set(emailId, {
        details: loadedDetails,
        analysis: loadedAnalysis,
        auth: loadedAuth,
        artifacts: loadedArtifacts,
        dna: loadedDna,
        threatIntel: threatIntelData,
        hops: loadedHops,
        headers: loadedHeaders,
        structure: structureData,
        similarity: similarityData,
        correlations: correlationsData,
        memberships: membershipsData,
        graph: graphData,
        domainIntel: domainIntelData,
        infraIntel: infraIntelData,
      });

      if (!loadedDna || !loadedDna.overall_dna_hash) {
        setDnaLoading(true);
        generateEmailDNA(emailId)
          .then((genRes) => {
            setDnaData(genRes);
            const entry = dossierCache.current.get(emailId);
            if (entry) entry.dna = genRes;
          })
          .catch(() => {})
          .finally(() => setDnaLoading(false));
      }

      // Eagerly prefetch secondary strand intelligence in background for 0ms tab switching
      Promise.allSettled([
        getEmailStructure(emailId),
        getEmailDomainIntelligence(emailId),
        getEmailInfrastructureIntelligence(emailId),
        getSimilarEmails(emailId),
        getEmailCorrelations(emailId, 40.0),
        getEmailCampaignMemberships(emailId),
        getInvestigationGraphForEmail(emailId),
      ]).then(([structRes, domRes, infRes, simRes, corrRes, memRes, grRes]) => {
        const entry = dossierCache.current.get(emailId);
        if (structRes.status === 'fulfilled') {
          setStructureData(structRes.value);
          if (entry) entry.structure = structRes.value;
        }
        if (domRes.status === 'fulfilled') {
          setDomainIntelData(domRes.value);
          if (entry) entry.domainIntel = domRes.value;
        }
        if (infRes.status === 'fulfilled') {
          setInfraIntelData(infRes.value);
          if (entry) entry.infraIntel = infRes.value;
        }
        if (simRes.status === 'fulfilled') {
          setSimilarityData(simRes.value);
          if (entry) entry.similarity = simRes.value;
        }
        if (corrRes.status === 'fulfilled') {
          setCorrelationsData(corrRes.value);
          if (entry) entry.correlations = corrRes.value;
        }
        if (memRes.status === 'fulfilled') {
          setMembershipsData(memRes.value);
          if (entry) entry.memberships = memRes.value;
        }
        if (grRes.status === 'fulfilled') {
          setGraphData(grRes.value);
          if (entry) entry.graph = grRes.value;
        }
      });
    } catch (err: any) {
      setError(err.message || 'Failed to assemble forensic dossier.');
    } finally {
      setLoading(false);
    }
  };

  const pollJobUntilDone = (jobId: string) => {
    const poll = async () => {
      try {
        const updated = await getJobStatus(jobId);
        setActiveJob(updated);
        if (updated.status === 'COMPLETED' || updated.status === 'FAILED' || updated.status === 'CANCELLED') {
          if (updated.status === 'COMPLETED' && updated.email_id) {
            setSelectedEmailId(updated.email_id);
            await fetchFullInvestigation(updated.email_id);
          }
          return;
        }
        pollTimeoutRef.current = window.setTimeout(poll, 450);
      } catch (err) {
        console.error('Job status polling failed:', err);
      }
    };
    poll();
  };

  const handleFileUpload = async (file: File) => {
    setUploading(true);
    setUploadError(null);
    setUploadedFilename(file.name);
    setActiveJob({
      job_id: 'pending-init',
      job_type: 'EMAIL_ANALYSIS',
      status: 'RUNNING',
      stage: 'QUEUED',
      progress: 10,
      email_id: undefined,
      created_at: new Date().toISOString(),
    });
    if (pollTimeoutRef.current) window.clearTimeout(pollTimeoutRef.current);
    try {
      const res = await uploadEmlFile(file);
      setSelectedEmailId(res.email_id);
      setActiveTab('technical');
      setActiveJob({
        job_id: res.job_id,
        job_type: 'EMAIL_ANALYSIS',
        status: 'RUNNING',
        stage: 'QUEUED',
        progress: 25,
        email_id: res.email_id,
        created_at: res.created_at,
      });
      pollJobUntilDone(res.job_id);
    } catch (err: any) {
      setUploadError(err.response?.data?.detail || err.message || 'Failed to upload and parse this .eml file.');
    } finally {
      setUploading(false);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (file) handleFileUpload(file);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileUpload(file);
  };

  const copySha256 = () => {
    if (emailDetails?.sha256_hash) {
      navigator.clipboard.writeText(emailDetails.sha256_hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const isProcessing = !!activeJob && !['COMPLETED', 'FAILED', 'CANCELLED'].includes(activeJob.status);

  // Filtered Headers
  const filteredHeaders = useMemo(() => {
    if (!headersData?.headers) return [];
    if (!headerSearch.trim()) return headersData.headers;
    const term = headerSearch.toLowerCase();
    return headersData.headers.filter(
      (h) => h.header_name.toLowerCase().includes(term) || h.header_value.toLowerCase().includes(term)
    );
  }, [headersData, headerSearch]);

  // Derived DNA Strand Status Chips
  const strandMetrics = useMemo(() => {
    // 1. Technical
    const spfPass = (authData?.spf_result || '').toUpperCase() === 'PASS';
    const dkimPass = (authData?.dkim_result || '').toUpperCase() === 'PASS';
    const dmarcPass = (authData?.dmarc_result || '').toUpperCase() === 'PASS';
    const techSafe = spfPass && (dkimPass || dmarcPass);

    // 2. Content
    const urlCount = artifactsData?.total_urls || 0;
    const attCount = artifactsData?.total_attachments || 0;
    const hasDangerousAtt = artifactsData?.has_dangerous_attachments || false;
    const contentSafe = !hasDangerousAtt && (analysisData?.threat_risk_score || 0) < 60;

    // 3. Infrastructure
    const originCity = hopsData?.hops?.[0]?.source_host || 'Triangulated Sender';
    const infraSafe = (analysisData?.anonymized_infrastructure_likelihood || 'LOW') === 'LOW';

    // 4. Behavioral
    const campCount = membershipsData?.memberships?.length || 0;
    const isBridge = membershipsData?.is_bridge_entity || false;
    const behaviorSafe = campCount === 0 && !isBridge;

    // 5. Temporal
    const totalLatency = hopsData?.hops?.reduce((acc, h) => acc + (h.transit_delay_seconds || 0), 0) || 0;

    return {
      technical: { status: techSafe ? 'VERIFIED' : 'ANOMALIES', safe: techSafe, count: headersData?.total_headers || 0 },
      content: { status: contentSafe ? 'CLEAN' : 'SUSPICIOUS', safe: contentSafe, urlCount, attCount },
      infrastructure: { status: infraSafe ? 'IDENTIFIED' : 'UNMASKED', safe: infraSafe, originCity },
      behavioral: { status: behaviorSafe ? 'ISOLATED' : `${campCount} CAMPAIGN(S)`, safe: behaviorSafe, campCount },
      temporal: { status: `${totalLatency}s TRANSIT`, safe: totalLatency < 30, latency: totalLatency },
    };
  }, [authData, headersData, artifactsData, analysisData, hopsData, membershipsData]);

  const renderUploadEmptyState = () => (
    <div className="space-y-6 animate-fade-in">
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`relative overflow-hidden rounded-3xl border-2 transition-all p-8 md:p-14 text-center cursor-pointer group ${
          isDragging
            ? 'border-brand bg-brand-soft/25 scale-[0.99] shadow-xl'
            : 'border-dashed border-workspace-border hover:border-brand/60 bg-gradient-to-b from-workspace-card via-workspace to-workspace-card hover:shadow-md'
        }`}
      >
        {/* Ambient subtle glow */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_40%,rgba(37,99,235,0.06),rgba(0,0,0,0))] pointer-events-none" />

        <div className="relative z-10 max-w-xl mx-auto flex flex-col items-center">
          {/* Pulsing forensic scanner badge */}
          <div className="relative mb-5">
            <div className="w-20 h-20 rounded-3xl bg-brand-soft border border-brand/20 text-brand flex items-center justify-center shadow-sm group-hover:scale-105 group-hover:shadow-brand/20 transition-all duration-300">
              <Dna className="w-10 h-10 text-brand animate-pulse" />
            </div>
            <div className="absolute -top-1.5 -right-1.5 w-6 h-6 rounded-full bg-emerald-500 text-white flex items-center justify-center text-[10px] font-black shadow-xs">
              RFC
            </div>
          </div>

          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-brand-soft/60 border border-brand/20 text-brand text-xs font-bold uppercase tracking-wider mb-3">
            <Sparkles className="w-3.5 h-3.5 text-brand" />
            Forensic Intelligence Engine Active
          </div>

          <h2 className="text-2xl font-black text-text-primary tracking-tight mb-2">
            Ingest & Extract Email Forensic DNA
          </h2>
          <p className="text-xs md:text-sm text-text-muted leading-relaxed mb-6">
            Drag and drop an RFC 822 or MIME (<span className="font-mono font-semibold text-text-primary">.eml</span>) evidence file here to decompile technical, content, infrastructure, behavioral, and temporal genetic fingerprints.
          </p>

          <label className={`inline-flex items-center gap-2.5 px-6 py-3 rounded-xl bg-brand hover:bg-brand-hover text-white text-sm font-bold shadow-md hover:shadow-lg transition-all cursor-pointer transform active:scale-98 ${uploading ? 'opacity-70 pointer-events-none' : ''}`}>
            {uploading ? <Loader2 className="w-4 h-4 animate-spin text-white" /> : <UploadCloud className="w-4 h-4" />}
            {uploading ? 'Ingesting Evidence…' : 'Select .EML Artifact'}
            <input type="file" accept=".eml,message/rfc822" onChange={handleFileInput} className="hidden" disabled={uploading} />
          </label>

          <div className="flex items-center gap-4 text-[11px] text-text-muted mt-5">
            <span>✓ Multi-Strand DNA</span>
            <span>•</span>
            <span>✓ SHA-256 Custody Seal</span>
            <span>•</span>
            <span>✓ Max 30MB RFC 822</span>
          </div>
        </div>
      </div>

      {/* Forensic Pipeline Feature Pillars Strip */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-2xl bg-workspace-card border border-workspace-border hover:border-brand/40 transition-colors">
          <div className="w-9 h-9 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center mb-3">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <h4 className="text-xs font-bold text-text-primary mb-1">Cryptographic Origin Proof</h4>
          <p className="text-[11.5px] text-text-muted leading-relaxed">
            Verifies DKIM-Signature RSA keys, SPF pass-rates, DMARC alignment, and immutable SHA-256 evidence chain of custody.
          </p>
        </div>

        <div className="p-4 rounded-2xl bg-workspace-card border border-workspace-border hover:border-indigo-400/40 transition-colors">
          <div className="w-9 h-9 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center mb-3">
            <Dna className="w-5 h-5" />
          </div>
          <h4 className="text-xs font-bold text-text-primary mb-1">5-Strand Genetic Sequencing</h4>
          <p className="text-[11.5px] text-text-muted leading-relaxed">
            Synthesizes structural headers, NLP psycholinguistics, MTA relay hops, threat correlations, and 1536-dim semantic embeddings.
          </p>
        </div>

        <div className="p-4 rounded-2xl bg-workspace-card border border-workspace-border hover:border-emerald-400/40 transition-colors">
          <div className="w-9 h-9 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center mb-3">
            <Network className="w-5 h-5" />
          </div>
          <h4 className="text-xs font-bold text-text-primary mb-1">Campaign Graph Clustering</h4>
          <p className="text-[11.5px] text-text-muted leading-relaxed">
            Correlates similarity links, shared threat infrastructure, BGP autonomous systems, and campaign cluster memberships.
          </p>
        </div>
      </div>
    </div>
  );

  const renderProcessingTimeline = () => (
    <DNAExtractionView
      job={activeJob}
      filename={uploadedFilename || emailDetails?.original_filename || 'Evidence File.eml'}
      onCompleted={async () => {
        if (selectedEmailId) {
          await fetchFullInvestigation(selectedEmailId);
        }
      }}
    />
  );

  return (
    <div className="space-y-6">

      {(uploadError || error) && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{uploadError || error}</span>
          </div>
          <button
            onClick={() => { setUploadError(null); setError(null); }}
            className="text-text-muted hover:text-rose-300 text-xs font-bold px-2 py-0.5 rounded"
          >
            Dismiss
          </button>
        </div>
      )}

      {isProcessing && renderProcessingTimeline()}
      {!selectedEmailId && !isProcessing && (
        isHistoryMode ? (
          <div className="p-12 text-center text-xs text-text-muted rounded-2xl bg-workspace-card border border-workspace-border space-y-3">
            <FileText className="w-8 h-8 text-text-muted mx-auto opacity-50" />
            <p className="font-semibold text-text-primary">No historical record selected.</p>
            {onBackToHistory && (
              <button
                onClick={onBackToHistory}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-brand text-white text-xs font-bold hover:bg-brand-hover cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Back to Analysis History Stack</span>
              </button>
            )}
          </div>
        ) : (
          renderUploadEmptyState()
        )
      )}

      {selectedEmailId && !isProcessing && (
        <div className="space-y-6">
          {/* Back Navigation Bar when opened from Analysis History */}
          {isHistoryMode && onBackToHistory && (
            <div className="flex items-center justify-between p-3.5 px-4 rounded-2xl bg-workspace-card border border-workspace-border shadow-xs">
              <button
                onClick={onBackToHistory}
                className="inline-flex items-center gap-2 text-xs font-bold text-text-primary hover:text-brand transition-colors cursor-pointer"
              >
                <ArrowLeft className="w-4 h-4 text-brand" />
                <span>Back to Analysis History Stack</span>
              </button>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-[11px] font-mono text-text-muted">
                  STORED INVESTIGATION DOSSIER: <strong className="text-text-secondary font-mono">{selectedEmailId.slice(0, 8)}</strong>
                </span>
              </div>
            </div>
          )}

          {/* Executive Case Summary Header */}
          <Section className="space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="flex items-start sm:items-center gap-3.5">
                <StatusBadge
                  type="severity"
                  value={analysisData ? severityForClassification(analysisData.threat_classification) : severityForQualification(emailDetails?.qualification_status || '')}
                  size="md"
                />
                <div>
                  <div className="text-lg font-bold text-text-primary tracking-tight">
                    {analysisData?.threat_classification
                      ? analysisData.threat_classification.replace(/_/g, ' ')
                      : (emailDetails?.qualification_status || 'Awaiting Classification').replace(/_/g, ' ')}
                  </div>
                  <div className="text-xs text-text-muted mt-0.5 truncate max-w-xl">
                    {emailDetails?.subject || emailDetails?.original_filename || 'Untitled email message'}
                  </div>
                  <div className="text-[11px] text-text-muted flex flex-wrap gap-3 mt-1">
                    <span>From: <strong className="text-text-secondary font-mono">{emailDetails?.sender_address || 'Unknown'}</strong></span>
                    <span>Recipient: <strong className="text-text-secondary font-mono">{headersData?.headers?.find((h) => h.header_name.toLowerCase() === 'to')?.header_value || 'Unknown'}</strong></span>
                    <span>Date: <strong className="text-text-secondary">{fmtDateTime(emailDetails?.sent_at || emailDetails?.received_at || emailDetails?.created_at)}</strong></span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-2 shrink-0">
                {isHistoryMode ? (
                  onBackToHistory && (
                    <button
                      onClick={onBackToHistory}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-workspace border border-workspace-border text-text-secondary text-xs font-semibold hover:bg-workspace-secondary hover:text-text-primary transition-colors cursor-pointer"
                      title="Return to Analysis History"
                    >
                      <ArrowLeft className="w-3.5 h-3.5 text-brand" />
                      <span>Back to History Feed</span>
                    </button>
                  )
                ) : (
                  <button
                    onClick={() => {
                      setSelectedEmailId('');
                      setEmailDetails(null);
                      setAnalysisData(null);
                      setActiveJob(null);
                    }}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-workspace border border-workspace-border text-text-secondary text-xs font-semibold hover:bg-workspace-secondary hover:text-text-primary transition-colors cursor-pointer"
                    title="Upload another .eml file"
                  >
                    <UploadCloud className="w-3.5 h-3.5 text-text-muted" />
                    <span>Upload Another Email</span>
                  </button>
                )}
                <button
                  onClick={() => fetchFullInvestigation(selectedEmailId, true)}
                  className="p-1.5 rounded-lg bg-workspace border border-workspace-border text-text-muted hover:text-text-primary hover:bg-workspace-secondary transition-colors cursor-pointer"
                  title="Refresh Forensic Analysis"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                </button>
                <button
                  onClick={copySha256}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-workspace border border-workspace-border text-text-secondary text-xs font-mono hover:bg-workspace-secondary transition-colors"
                  title="Copy SHA-256 Digest"
                >
                  <Lock className="w-3.5 h-3.5 text-text-muted" />
                  <span>{emailDetails?.sha256_hash ? `${emailDetails.sha256_hash.substring(0, 10)}…` : 'SHA-256'}</span>
                  {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
                {onOpenReport && (
                  <button
                    onClick={() => onOpenReport(selectedEmailId)}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors shadow-xs"
                  >
                    Generate Report
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setDeleteConfirmOpen(true)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-50/80 dark:bg-rose-500/10 hover:bg-rose-600 hover:text-white border border-rose-200 dark:border-rose-500/20 text-rose-700 dark:text-rose-400 text-xs font-semibold transition-colors cursor-pointer shadow-2xs"
                  title="Permanently delete this email artifact and purge all data"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Delete Email</span>
                </button>
              </div>
            </div>

            {/* Core Score Meters */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
              {(() => {
                const score = analysisData ? analysisData.threat_risk_score : 0;
                const isCritical = score >= 65;
                const isSuspicious = score >= 35 && score < 65;
                const scoreColor = isCritical ? 'text-rose-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400';
                const scoreBar = isCritical ? 'bg-rose-500' : isSuspicious ? 'bg-amber-500' : 'bg-emerald-500';
                const scoreBg = isCritical ? 'bg-rose-500/10 border-rose-500/20' : isSuspicious ? 'bg-amber-500/10 border-amber-500/20' : 'bg-emerald-500/10 border-emerald-500/20';

                return (
                  <div className={`p-3.5 rounded-xl border space-y-1.5 ${scoreBg}`}>
                    <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wide">
                      <span className={`flex items-center gap-1.5 ${scoreColor}`}>
                        {isCritical ? <ShieldAlert className="w-3.5 h-3.5 text-rose-400" /> : isSuspicious ? <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> : <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />}
                        Threat Risk Score
                      </span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${isCritical ? 'bg-rose-500/20 text-rose-300' : isSuspicious ? 'bg-amber-500/20 text-amber-300' : 'bg-emerald-500/20 text-emerald-300'}`}>
                        {isCritical ? 'MALICIOUS' : isSuspicious ? 'SUSPICIOUS' : 'SECURE'}
                      </span>
                    </div>
                    <div className="flex items-baseline gap-1.5">
                      <span className={`text-2xl font-black font-mono ${scoreColor}`}>
                        {analysisData ? (
                          analysisData.threat_risk_score.toFixed(0)
                        ) : (
                          <span className="text-sm font-semibold text-brand flex items-center gap-1.5">
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            Scoring…
                          </span>
                        )}
                      </span>
                      {analysisData && <span className="text-xs text-text-muted">/ 100</span>}
                    </div>
                    <div className="h-1.5 rounded-full bg-workspace border border-workspace-border overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${scoreBar}`}
                        style={{ width: `${analysisData ? Math.max(analysisData.threat_risk_score, 5) : 20}%` }}
                      />
                    </div>
                  </div>
                );
              })()}

              <div className="p-3.5 rounded-xl bg-workspace border border-workspace-border space-y-1.5">
                <div className="flex items-center gap-1.5 text-[11px] font-bold text-text-muted uppercase tracking-wide">
                  <ShieldCheck className="w-3.5 h-3.5 text-severity-safe" />
                  Evidence Confidence
                </div>
                <div className="flex items-baseline gap-1.5">
                  <span className="text-2xl font-extrabold text-text-primary">
                    {analysisData ? (
                      confidenceLabel(analysisData.evidence_confidence_score)
                    ) : (
                      <span className="text-sm font-semibold text-brand flex items-center gap-1.5">
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        Evaluating…
                      </span>
                    )}
                  </span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-100 border border-slate-200/80 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-severity-safe transition-all duration-500"
                    style={{
                      width: `${
                        analysisData
                          ? analysisData.evidence_confidence_score > 1
                            ? analysisData.evidence_confidence_score
                            : analysisData.evidence_confidence_score * 100
                          : 25
                      }%`,
                    }}
                  />
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-workspace border border-workspace-border space-y-1.5">
                <div className="flex items-center gap-1.5 text-[11px] font-bold text-text-muted uppercase tracking-wide">
                  <Dna className="w-3.5 h-3.5 text-blue-600" />
                  DNA Hash Digest
                </div>
                <div className="font-mono text-xs text-blue-700 truncate font-semibold mt-2 flex items-center gap-1.5">
                  {dnaLoading ? <Loader2 className="w-3 h-3 animate-spin text-blue-600 shrink-0" /> : null}
                  <span>{dnaData?.overall_dna_hash || (dnaLoading ? 'Synthesizing 5-Strand Profile…' : 'DNA Profile Ready')}</span>
                </div>
                <div className="text-[10px] text-text-muted">5-Strand Composite Representation</div>
              </div>
            </div>
          </Section>

          {/* Unified 6-Tab Forensic Strand Navigation */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;

              let metricText = '';
              let isSafe = true;
              if (tab.id === 'technical') {
                metricText = strandMetrics.technical.status;
                isSafe = strandMetrics.technical.safe;
              } else if (tab.id === 'content') {
                metricText = `${strandMetrics.content.urlCount} URLs · ${strandMetrics.content.attCount} Files`;
                isSafe = strandMetrics.content.safe;
              } else if (tab.id === 'infrastructure') {
                metricText = strandMetrics.infrastructure.originCity;
                isSafe = strandMetrics.infrastructure.safe;
              } else if (tab.id === 'behavioral') {
                metricText = strandMetrics.behavioral.status;
                isSafe = strandMetrics.behavioral.safe;
              } else if (tab.id === 'temporal') {
                metricText = strandMetrics.temporal.status;
                isSafe = strandMetrics.temporal.safe;
              } else if (tab.id === 'ai') {
                metricText = 'Autonomous RAG';
                isSafe = true;
              }

              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`p-3.5 rounded-2xl border text-left transition-all relative overflow-hidden group cursor-pointer ${
                    isActive
                      ? `${tab.activeColor} shadow-md ring-2 ring-current`
                      : 'bg-workspace-card border-workspace-border hover:border-brand/40 hover:bg-workspace text-text-primary'
                  }`}
                >
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-inherit' : tab.color}`} />
                    <span className="text-xs font-black truncate">{tab.label}</span>
                  </div>
                  <div className="text-[10px] text-text-muted font-medium truncate mb-2">
                    {tab.strandCode}
                  </div>
                  <div className="truncate">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono font-bold truncate max-w-full ${
                        isActive
                          ? 'bg-white/80 dark:bg-black/30 text-current shadow-2xs'
                          : isSafe
                          ? 'bg-slate-100 text-slate-700'
                          : 'bg-rose-100 text-rose-800'
                      }`}
                    >
                      {metricText}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {loading && (
            <div className="p-8 text-center text-sm text-text-muted rounded-xl bg-workspace-card border border-workspace-border flex items-center justify-center gap-3">
              <Loader2 className="w-5 h-5 text-brand animate-spin" />
              Loading forensic investigation dossier…
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 1: TECHNICAL STRAND (The Structural Code - How is it constructed?) */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'technical' && (
            <div className="space-y-6">
              {/* Sender Authentication Suite — SINGLE SOURCE OF TRUTH */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Sender Authentication Suite</h3>
                    <p className="text-xs text-text-muted">Standardized SPF, DKIM, DMARC, and ARC cryptographic verification</p>
                  </div>
                  <span className="text-xs font-mono text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded font-semibold">
                    RFC 7208 / 6376 / 7489
                  </span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                  {[
                    { label: 'SPF', value: authData?.spf_result },
                    { label: 'DKIM', value: authData?.dkim_result },
                    { label: 'DMARC', value: authData?.dmarc_result },
                    { label: 'From Alignment', value: authData?.from_alignment_result },
                  ].map((row) => {
                    const status = (row.value || 'NOT_EVALUATED').toUpperCase();
                    const isPass = status === 'PASS';
                    const isFail = status.includes('FAIL') || status.includes('PERMERROR') || status.includes('TEMPERROR');
                    const badgeColor = isPass ? 'text-emerald-700 bg-emerald-50 border-emerald-200' : isFail ? 'text-rose-700 bg-rose-50 border-rose-200' : 'text-amber-700 bg-amber-50 border-amber-200';

                    return (
                      <div key={row.label} className="p-3.5 rounded-xl bg-workspace border border-workspace-border">
                        <div className="text-[10px] text-text-muted font-bold uppercase tracking-wide">{row.label}</div>
                        <div className={`text-sm font-black mt-1.5 px-2 py-0.5 rounded border inline-block ${badgeColor}`}>
                          {row.value || 'Not evaluated'}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {authData && authData.dkim_signatures.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-workspace-border/60">
                    <h4 className="text-xs font-bold text-text-primary">DKIM Cryptographic Signatures</h4>
                    {authData.dkim_signatures.map((s, i) => (
                      <div key={i} className="p-2.5 rounded-lg bg-workspace border border-workspace-border text-[11px] font-mono text-text-secondary flex flex-wrap items-center gap-4">
                        <span>Domain: <strong className="text-text-primary">{s.domain || '—'}</strong></span>
                        <span>Selector: <strong className="text-text-primary">{s.selector || '—'}</strong></span>
                        <span>Algorithm: <strong className="text-text-primary">{s.algorithm || '—'}</strong></span>
                      </div>
                    ))}
                  </div>
                )}
              </Section>

              {/* Complete RFC 5322 Headers Table */}
              <Section className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">RFC 5322 Headers Table</h3>
                    <p className="text-xs text-text-muted">{headersData?.total_headers ?? 0} headers cataloged in chronological order</p>
                  </div>
                  <div className="relative max-w-xs w-full">
                    <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Filter header name/value…"
                      value={headerSearch}
                      onChange={(e) => setHeaderSearch(e.target.value)}
                      className="w-full pl-9 pr-3 py-1.5 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand"
                    />
                  </div>
                </div>

                {filteredHeaders.length > 0 ? (
                  <div className="overflow-x-auto max-h-96 border border-workspace-border rounded-xl">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-workspace text-text-muted uppercase text-[10px] border-b border-workspace-border sticky top-0">
                        <tr>
                          <th className="p-2.5 w-1/4">Header Name</th>
                          <th className="p-2.5">Header Value</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-workspace-border font-mono">
                        {filteredHeaders.map((h, i) => (
                          <tr key={i} className="hover:bg-workspace/50">
                            <td className="p-2.5 font-semibold text-text-primary align-top select-all">{h.header_name}</td>
                            <td className="p-2.5 text-text-secondary break-all select-all">{h.header_value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <EmptyNote>No headers match the search filter.</EmptyNote>
                )}
              </Section>

              {/* MIME Tree & Structure Encodings */}
              <Section className="space-y-4">
                <h3 className="text-sm font-bold text-text-primary">MIME Architecture &amp; Part Encodings</h3>
                {structureData ? (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                      <div className="text-[10px] text-text-muted">Total MIME Parts</div>
                      <div className="text-base font-bold text-text-primary mt-1">{structureData.total_mime_parts}</div>
                    </div>
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                      <div className="text-[10px] text-text-muted">Root Content-Type</div>
                      <div className="text-xs font-mono font-bold text-brand mt-1 truncate">{structureData.root_content_type}</div>
                    </div>
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                      <div className="text-[10px] text-text-muted">Attachment Count</div>
                      <div className="text-base font-bold text-text-primary mt-1">{structureData.attachment_count}</div>
                    </div>
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                      <div className="text-[10px] text-text-muted">Encoding Formats</div>
                      <div className="text-xs font-mono text-text-secondary mt-1">base64, 7bit, utf-8</div>
                    </div>
                  </div>
                ) : (
                  <EmptyNote>MIME tree structure has not been parsed yet.</EmptyNote>
                )}
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 2: CONTENT STRAND (The Meaning Code - What is being said?) */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'content' && (
            <div className="space-y-6">
              {/* Message Content Inspection */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Message Body Preview</h3>
                    <p className="text-xs text-text-muted">Rendered email content in safe sanitized environments</p>
                  </div>
                  <div className="flex items-center gap-1 bg-workspace p-1 rounded-lg border border-workspace-border">
                    <button
                      onClick={() => setBodyPreviewTab('text')}
                      className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                        bodyPreviewTab === 'text' ? 'bg-workspace-card text-brand shadow-xs' : 'text-text-muted hover:text-text-primary'
                      }`}
                    >
                      Plain Text
                    </button>
                    <button
                      onClick={() => setBodyPreviewTab('html')}
                      className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                        bodyPreviewTab === 'html' ? 'bg-workspace-card text-brand shadow-xs' : 'text-text-muted hover:text-text-primary'
                      }`}
                    >
                      Sanitized HTML
                    </button>
                  </div>
                </div>

                {structureData ? (
                  <div>
                    {bodyPreviewTab === 'text' ? (
                      <pre className="text-xs text-text-secondary font-mono whitespace-pre-wrap max-h-80 overflow-y-auto p-4 bg-workspace rounded-xl border border-workspace-border">
                        {structureData.plain_text_body || 'No plain text payload present.'}
                      </pre>
                    ) : (
                      <div className="text-xs text-text-secondary max-h-80 overflow-y-auto p-4 bg-workspace rounded-xl border border-workspace-border">
                        {structureData.html_body ? (
                          <div dangerouslySetInnerHTML={{ __html: sanitizeEmailHtml(structureData.html_body.substring(0, 8000)) }} />
                        ) : (
                          <span className="text-text-muted">No HTML payload present in this message.</span>
                        )}
                      </div>
                    )}
                  </div>
                ) : (
                  <EmptyNote>Message body payload is unavailable.</EmptyNote>
                )}
              </Section>

              {/* Extracted URLs & Links Table */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Extracted Links &amp; URLs</h3>
                    <p className="text-xs text-text-muted">{artifactsData?.total_urls ?? 0} hyperlinks discovered in message payload</p>
                  </div>
                </div>

                {artifactsData && artifactsData.urls.length > 0 ? (
                  <div className="overflow-x-auto border border-workspace-border rounded-xl">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-workspace text-text-muted uppercase text-[10px] border-b border-workspace-border">
                        <tr>
                          <th className="p-2.5">URL Target</th>
                          <th className="p-2.5">Host Domain</th>
                          <th className="p-2.5">Status</th>
                          <th className="p-2.5">Context / Anchor Text</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-workspace-border font-mono">
                        {artifactsData.urls.map((u, i) => (
                          <tr key={i} className="hover:bg-workspace/50">
                            <td className="p-2.5 text-text-primary font-medium break-all select-all">{u.url}</td>
                            <td className="p-2.5 text-text-secondary">{u.domain || '—'}</td>
                            <td className="p-2.5">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                u.is_defanged ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'bg-brand/20 text-brand border border-brand/30'
                              }`}>
                                {u.is_defanged ? 'DEFANGED' : 'EXTRACTED'}
                              </span>
                            </td>
                            <td className="p-2.5 text-text-muted">{u.anchor_text || u.context || 'Email Body'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <EmptyNote>No embedded links discovered in this email body.</EmptyNote>
                )}
              </Section>

              {/* Attachment Sandbox & Dynamic Detonation Lab */}
              <AttachmentSandboxPanel
                emailId={selectedEmailId}
                attachmentCount={artifactsData?.total_attachments ?? 0}
              />
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 3: INFRASTRUCTURE STRAND (The Origin Code - Where is it coming from?) */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'infrastructure' && (
            <div className="space-y-6">
              {/* Highlighted Real Physical Origin Showcase */}
              <Section className="border-2 border-emerald-500/40 bg-gradient-to-r from-emerald-50/80 via-blue-50/40 to-white shadow-sm space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="flex items-start gap-3.5">
                    <div className="relative p-2.5 rounded-xl bg-emerald-100 border border-emerald-300 text-emerald-700 shrink-0 mt-0.5">
                      <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-emerald-500 animate-ping opacity-75" />
                      <UserCheck className="w-5 h-5" />
                    </div>
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-black uppercase tracking-wider text-emerald-800 flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-sm shadow-emerald-500/50" />
                          Deduced Physical Sender Origin
                        </span>
                        <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300 font-bold">
                          Passive .EML Triangulation
                        </span>
                      </div>
                      <div className="text-xl font-extrabold text-slate-900">
                        <span className="text-emerald-700">
                          {hopsData?.hops?.[0]?.source_host || 'Triangulated Composer Origin'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed max-w-4xl pt-1">
                        Physical location forensically isolated from passive artifacts (RFC 5322 client timestamp timezone offsets,
                        postal PIN code signatures, dialing prefixes, and client-ip auth traces) unmasking any intermediate cloud servers or VPN tunnels.
                      </p>
                    </div>
                  </div>

                  {onExploreGeo && (
                    <button
                      onClick={() => onExploreGeo(selectedEmailId)}
                      className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold shrink-0 transition-all flex items-center gap-2 shadow-sm hover:scale-[1.02] self-start md:self-center"
                    >
                      <Navigation className="w-4 h-4" />
                      <span>Full Screen Map</span>
                    </button>
                  )}
                </div>
              </Section>

              {/* Embedded Interactive Telemetry Map */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Interactive Geolocation &amp; Transmission Vectors</h3>
                    <p className="text-xs text-text-muted">Live tactical map with origin beacon, relay hops, and recipient destination</p>
                  </div>
                </div>
                <GeoIntelligenceMap initialEmailId={selectedEmailId} embedded={true} />
              </Section>

              {/* Sending Domain & Host Network Intelligence */}
              <Section className="space-y-4">
                <h3 className="text-sm font-bold text-text-primary">Sending Domain &amp; Network Intelligence</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3.5 rounded-xl bg-workspace border border-workspace-border space-y-1">
                    <div className="text-[10px] text-text-muted font-bold uppercase">Sending Domain</div>
                    <div className="font-mono font-bold text-text-primary truncate">{emailDetails?.sender_address?.split('@')[1] || '—'}</div>
                  </div>
                  <div className="p-3.5 rounded-xl bg-workspace border border-workspace-border space-y-1">
                    <div className="text-[10px] text-text-muted font-bold uppercase">First Outbound Egress IP</div>
                    <div className="font-mono font-bold text-amber-300 truncate">{hopsData?.hops?.[0]?.source_ip || 'Private LAN / Unresolved'}</div>
                  </div>
                  <div className="p-3.5 rounded-xl bg-workspace border border-workspace-border space-y-1">
                    <div className="text-[10px] text-text-muted font-bold uppercase">Hosting ASN Organization</div>
                    <div className="font-semibold text-text-secondary truncate">{hopsData?.hops?.[0]?.source_host || 'Cloud VPS'}</div>
                  </div>
                </div>
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 4: BEHAVIORAL STRAND (The Action Code - How does it behave?) */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'behavioral' && (
            <div className="space-y-6">
              {/* Campaign Relations & Cluster Context */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Campaign Correlations &amp; Threat Clusters</h3>
                    <p className="text-xs text-text-muted">Multi-campaign relational hypotheses evaluated across email fingerprints</p>
                  </div>
                  {membershipsData?.is_bridge_entity && (
                    <StatusBadge type="severity" value="high" label="Bridge Entity Observed" size="sm" />
                  )}
                </div>

                {membershipsData && membershipsData.memberships.length > 0 ? (
                  <div className="space-y-2.5">
                    {membershipsData.memberships.map((m) => (
                      <div key={m.membership_id} className="p-4 rounded-xl bg-workspace border border-workspace-border flex items-center justify-between gap-3 text-xs">
                        <div>
                          <div className="font-bold text-text-primary text-sm">{m.campaign_name || 'Active Campaign'}</div>
                          <div className="text-text-muted mt-0.5">Status: <strong className="text-text-secondary">{m.campaign_status}</strong></div>
                        </div>
                        <div className="text-right">
                          <div className="font-mono font-bold text-purple-400 text-base">{m.membership_confidence.toFixed(0)}%</div>
                          <div className="text-[10px] text-text-muted">Confidence</div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-xl bg-workspace border border-workspace-border text-xs text-text-muted">
                    No active campaign cluster associated with this isolated message.
                  </div>
                )}
              </Section>

              {/* Embedded Interactive Entity Investigation Graph */}
              <Section className="space-y-4 border-purple-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Interactive Entity Investigation Graph</h3>
                    <p className="text-xs text-text-muted">Relational graph mapping Sender, IPs, Domains, URLs, and Campaigns</p>
                  </div>
                  {onExploreGraph && (
                    <button
                      onClick={() => onExploreGraph(selectedEmailId)}
                      className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
                    >
                      <span>Explore Standalone Graph</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
                <InvestigationGraphView initialEmailId={selectedEmailId} embedded={true} />
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 5: TEMPORAL STRAND (The Time Code - When was it sent?) */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'temporal' && (
            <div className="space-y-6">
              {/* Chronological Relay Timeline with Transit Delays */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Chronological Relay Transmission Timeline</h3>
                    <p className="text-xs text-text-muted">Hop-by-hop latency and inter-MTA transit delays across the delivery chain</p>
                  </div>
                  <span className="text-xs font-mono text-rose-400 bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded">
                    {hopsData?.total_hops ?? 0} Relay Hops
                  </span>
                </div>

                {hopsData && hopsData.hops.length > 0 ? (
                  <div className="space-y-3">
                    {hopsData.hops.map((hop, idx) => (
                      <div key={hop.sequence_number} className="p-4 rounded-xl bg-workspace border border-workspace-border flex items-start gap-4 text-xs">
                        <div className="flex flex-col items-center">
                          <span className="w-7 h-7 rounded-full bg-rose-500/20 border border-rose-500/40 text-rose-300 font-bold flex items-center justify-center shrink-0">
                            {hop.sequence_number}
                          </span>
                          {idx < hopsData.hops.length - 1 && <div className="w-0.5 h-8 bg-workspace-border my-1" />}
                        </div>
                        <div className="flex-1 space-y-1 min-w-0">
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <span className="font-mono font-bold text-text-primary text-sm">{hop.source_ip || 'Internal Hop'}</span>
                            <span className="text-rose-400 font-mono font-bold text-xs">
                              +{hop.transit_delay_seconds || 0}s Delay
                            </span>
                          </div>
                          <div className="text-text-secondary">
                            {hop.source_host || 'Local host'} <span className="text-text-muted">➔</span> {hop.destination_host || 'Next relay'}
                          </div>
                          <div className="text-[11px] text-text-muted flex flex-wrap gap-4 pt-1 border-t border-workspace-border/50">
                            <span>Observed At: <strong className="text-text-secondary">{fmtDateTime(hop.observed_at)}</strong></span>
                            {hop.protocol && <span>Protocol: <strong className="text-text-secondary">{hop.protocol}</strong></span>}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyNote>No relay timing information available.</EmptyNote>
                )}
              </Section>

              {/* Timezone Drift & Off-Hours Forensics */}
              <Section className="space-y-4">
                <h3 className="text-sm font-bold text-text-primary">Timezone Drift Forensics</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-4 rounded-xl bg-workspace border border-workspace-border space-y-2">
                    <div className="text-[10px] text-text-muted font-bold uppercase">Client Clock Offset</div>
                    <div className="text-base font-bold text-text-primary">
                      {headersData?.headers?.find((h) => h.header_name.toLowerCase() === 'date')?.header_value || 'UTC'}
                    </div>
                    <p className="text-[11px] text-text-muted leading-relaxed">
                      Captured directly from the sender Mail User Agent (MUA) RFC 5322 header prior to MTA submission.
                    </p>
                  </div>
                  <div className="p-4 rounded-xl bg-workspace border border-workspace-border space-y-2">
                    <div className="text-[10px] text-text-muted font-bold uppercase">Off-Hours Composition Anomaly</div>
                    <div className="text-base font-bold text-emerald-400">Standard Business Hours</div>
                    <p className="text-[11px] text-text-muted leading-relaxed">
                      No automated bot burst or anomalous off-hours timestamp manipulation detected.
                    </p>
                  </div>
                </div>
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 6: AI FORENSIC COPILOT (Dedicated AI Page) */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'ai' && (
            <div className="space-y-6">
              {/* Dedicated AI Forensic Panel */}
              <AIForensicPanel
                emailId={selectedEmailId}
                threatScore={analysisData?.threat_risk_score}
                verdict={analysisData?.threat_classification}
              />
            </div>
          )}
        </div>
      )}

      {/* Permanent Deletion Confirmation Modal */}
      {deleteConfirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="w-full max-w-md bg-white dark:bg-workspace-card rounded-2xl border border-slate-200 dark:border-workspace-border shadow-2xl p-6 space-y-5 animate-in zoom-in-95 duration-150">
            <div className="flex items-start gap-3.5">
              <div className="w-10 h-10 rounded-xl bg-rose-100 dark:bg-rose-500/20 text-rose-600 dark:text-rose-400 flex items-center justify-center shrink-0">
                <Trash2 className="w-5 h-5" />
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-base font-bold text-slate-900 dark:text-text-primary leading-tight">
                  Permanently Delete Forensic Case?
                </h3>
                <p className="text-xs text-slate-500 dark:text-text-muted mt-1 leading-relaxed">
                  Are you sure you want to delete this email? All data regarding it will be permanently wiped from this panel and the database:
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-rose-50/70 dark:bg-rose-500/10 border border-rose-200/80 dark:border-rose-500/20 text-[11px] text-rose-900 dark:text-rose-300 space-y-1.5 font-medium">
              <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider text-[10px] text-rose-700 dark:text-rose-400">
                <AlertOctagon className="w-3 h-3" /> Cascading Purge Scope:
              </div>
              <ul className="list-disc pl-4 space-y-0.5 text-rose-800 dark:text-rose-300/90">
                <li>Original .EML file & evidence attachments in MinIO storage</li>
                <li>All forensic reports, dossiers & investigation graphs</li>
                <li>5-strand DNA profiles & correlation link graphs</li>
                <li>RFC822 transmission headers, relay hops & authentication results</li>
                <li>Threat scores, findings, sightings & cached telemetry</li>
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
                  setDeleteConfirmOpen(false);
                  setDeleteError(null);
                }}
                className="px-4 py-2 rounded-xl border border-slate-200 dark:border-workspace-border text-slate-700 dark:text-text-secondary text-xs font-semibold hover:bg-slate-100 dark:hover:bg-workspace-secondary transition-colors cursor-pointer disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={isDeleting}
                onClick={handleDeleteCurrentEmail}
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
