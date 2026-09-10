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
  AlertTriangle,
  Copy,
  Check,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  Circle,
  Loader2,
  Mail,
  Chrome,
  Layers,
  ExternalLink,
  ArrowRight,
  Search,
  MapPin,
  Sparkles,
  Users,
  Server,
  Clock,
} from 'lucide-react';
import {
  uploadEmlFile,
  getEmailDetails,
  listEmails,
  getJobStatus,
  getEmailHeaders,
  getEmailAuthResults,
  getEmailRelayHops,
  getEmailStructure,
  getEmailArtifacts,
  getEmailThreatIntelligence,
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
  JobStage,
} from '../../services/api';
import { StatusBadge, SeverityLevel } from '../common/StatusBadge';
import { GeoIntelligenceMap } from '../geo/GeoIntelligenceMap';
import { AIForensicPanel } from './AIForensicPanel';
import { AIAssistantDrawer } from './AIAssistantDrawer';
import { AnalystDispositionPanel } from './AnalystDispositionPanel';
import { DNAStrandAnimation } from '../common/DNAStrandAnimation';

type WorkspaceTab = 'overview' | 'indicators' | 'forensics' | 'correlation';

const TABS: { id: WorkspaceTab; label: string; icon: React.FC<{ className?: string }> }[] = [
  { id: 'overview', label: 'Overview', icon: ShieldCheck },
  { id: 'indicators', label: 'Threat Indicators (IOCs)', icon: ShieldAlert },
  { id: 'forensics', label: 'Forensics & Infrastructure', icon: FileText },
  { id: 'correlation', label: 'Campaign Correlation', icon: Network },
];

const PROCESSING_STEPS: { stage: JobStage; label: string }[] = [
  { stage: 'ACQUIRING_EVIDENCE', label: 'Evidence Received' },
  { stage: 'PARSING_EMAIL', label: 'Email Parsed' },
  { stage: 'EXTRACTING_IOCS', label: 'Indicators Extracted' },
  { stage: 'ANALYZING_THREATS', label: 'Threat Intelligence Checked' },
  { stage: 'GENERATING_DNA', label: 'Email DNA Generated' },
  { stage: 'GEO_LOCATING', label: 'Infrastructure Analysed' },
  { stage: 'CORRELATING_CAMPAIGN', label: 'Campaign Correlation Completed' },
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
    case 'QUALIFIED_FOR_INVESTIGATION':
      return 'low';
    default:
      return 'safe';
  }
};

const confidenceLabel = (score?: number | null): string => {
  if (score === undefined || score === null) return 'Not available';
  if (score >= 80) return 'High';
  if (score >= 50) return 'Medium';
  return 'Low';
};

const fmtDateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : 'N/A');
const fmtBytes = (bytes?: number | null) => (bytes ? `${(bytes / 1024).toFixed(1)} KB` : 'N/A');

const classifyUrlCategory = (urlStr: string, context?: string): { label: string; badgeClass: string } => {
  const urlLower = (urlStr || '').toLowerCase();
  const ctxUpper = (context || '').toUpperCase();
  if (ctxUpper === 'HEADER' || urlLower.includes('/un/') || urlLower.includes('unsubscribe')) {
    return { label: 'List-Unsubscribe Header', badgeClass: 'bg-slate-100 text-slate-700 border-slate-300' };
  } else if (urlLower.includes('/op/') || urlLower.includes('pixel') || (ctxUpper === 'IMAGE_SRC' && (urlLower.includes('.png') || urlLower.includes('.gif')))) {
    return { label: 'Open Tracking Beacon', badgeClass: 'bg-purple-100 text-purple-800 border-purple-300' };
  } else if (urlLower.includes('/cl/') || urlLower.includes('/track/') || urlLower.includes('click') || urlLower.includes('sendibt')) {
    return { label: 'ESP Click Redirect / Telemetry', badgeClass: 'bg-amber-100 text-amber-800 border-amber-300' };
  } else if (ctxUpper === 'IMAGE_SRC') {
    return { label: 'Embedded Remote Image', badgeClass: 'bg-sky-100 text-sky-800 border-sky-300' };
  } else if (ctxUpper === 'BUTTON_HREF') {
    return { label: 'Call-To-Action Button', badgeClass: 'bg-blue-100 text-blue-800 border-blue-300' };
  } else if (urlLower.includes('phish') || urlLower.includes('login') || urlLower.includes('verify')) {
    return { label: 'Phishing Campaign Target', badgeClass: 'bg-red-100 text-red-800 border-red-300' };
  }
  return { label: 'Body Hyperlink', badgeClass: 'bg-slate-100 text-slate-700 border-slate-300' };
};

const Section: React.FC<{ children: React.ReactNode; className?: string; style?: React.CSSProperties }> = ({ children, className = '', style }) => (
  <div
    style={{
      backgroundColor: '#F0F7FF',
      border: '1px solid #B9DCFA',
      borderRadius: '14px',
      boxShadow: '0 1px 4px rgba(23, 59, 112, 0.05)',
      ...style,
    }}
    className={`p-6 ${className}`}
  >
    {children}
  </div>
);

const EmptyNote: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="text-xs text-text-muted py-3">{children}</div>
);

interface AnalysisWorkspaceProps {
  initialEmailId?: string;
  onOpenReport?: (emailId: string) => void;
  onExploreGeo?: (emailId: string) => void;
  onExploreGraph?: (emailId: string) => void;
  onExploreEvidence?: (emailId: string) => void;
}

export const AnalysisWorkspace: React.FC<AnalysisWorkspaceProps> = ({
  initialEmailId,
  onOpenReport,
  onExploreGeo,
  onExploreGraph,
  onExploreEvidence,
}) => {
  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [selectedEmailId, setSelectedEmailId] = useState<string>(initialEmailId || '');
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('overview');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [activeJob, setActiveJob] = useState<JobRecord | null>(null);
  const pollTimeoutRef = useRef<number | null>(null);

  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [expandedDnaCategory, setExpandedDnaCategory] = useState<string | null>(null);
  const [expandedIndicator, setExpandedIndicator] = useState<string | null>(null);
  const [expandedUrl, setExpandedUrl] = useState<number | null>(null);
  const [headerSearch, setHeaderSearch] = useState<string>('');
  const [bodyPreviewTab, setBodyPreviewTab] = useState<'text' | 'html'>('text');
  const [isAssistantOpen, setIsAssistantOpen] = useState<boolean>(false);

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

  // Extended Intelligence
  const [similarityData, setSimilarityData] = useState<SimilarityLinkResponse[]>([]);
  const [correlationsData, setCorrelationsData] = useState<EmailCorrelationsResponse | null>(null);
  const [membershipsData, setMembershipsData] = useState<EmailMembershipsResponse | null>(null);
  const [graphData, setGraphData] = useState<InvestigationGraphResponse | null>(null);
  const [domainIntelData, setDomainIntelData] = useState<EmailDomainIntelResponse | null>(null);
  const [infraIntelData, setInfraIntelData] = useState<EmailInfrastructureResponse | null>(null);

  useEffect(() => {
    loadEmails();
    return () => {
      if (pollTimeoutRef.current) window.clearTimeout(pollTimeoutRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync selectedEmailId if initialEmailId prop changes from outside
  useEffect(() => {
    if (initialEmailId && initialEmailId !== selectedEmailId) {
      setSelectedEmailId(initialEmailId);
      setActiveTab('overview');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialEmailId]);

  // Whenever selectedEmailId is set or changed (including initial mount!), immediately load full dossier
  useEffect(() => {
    if (selectedEmailId) {
      fetchFullInvestigation(selectedEmailId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedEmailId]);

  const loadEmails = async () => {
    try {
      const res = await listEmails(0, 50);
      const uniqueItems = Array.from(
        new Map((res.items || []).map((item) => [item.id, item])).values()
      );
      setEmails(uniqueItems);
      if (uniqueItems.length > 0) {
        if (!selectedEmailId || !uniqueItems.some((e) => e.id === selectedEmailId)) {
          setSelectedEmailId(uniqueItems[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to load emails list:', err);
    }
  };

  const fetchFullInvestigation = async (emailId: string) => {
    if (!emailId) return;
    setLoading(true);
    setError(null);

    // Reset previous email state to avoid stale data flashing
    setEmailDetails(null);
    setAnalysisData(null);
    setThreatIntelData(null);
    setDnaData(null);
    setArtifactsData(null);
    setAuthData(null);
    setHopsData(null);
    setHeadersData(null);
    setStructureData(null);
    setSimilarityData([]);
    setCorrelationsData(null);
    setMembershipsData(null);
    setGraphData(null);
    setDomainIntelData(null);
    setInfraIntelData(null);

    try {
      // 1. Instant Fast-Path: Fetch core details and forensic analysis first (15-40ms)
      const [detailsRes, analysisRes] = await Promise.allSettled([
        getEmailDetails(emailId),
        getEmailAnalysis(emailId),
      ]);

      if (detailsRes.status === 'fulfilled') {
        setEmailDetails(detailsRes.value);
      } else {
        console.warn('getEmailDetails notice for', emailId, detailsRes.reason);
      }
      if (analysisRes.status === 'fulfilled') {
        setAnalysisData(analysisRes.value);
      } else {
        console.warn('getEmailAnalysis notice for', emailId, analysisRes.reason);
      }

      // Unblock UI immediately so user sees the Overview with zero delay
      setLoading(false);
    } catch (err: any) {
      console.error('Fast-path email load failed:', err);
      setError(err.message || 'Could not load details for this email.');
      setLoading(false);
    }

    // 2. Progressive Hydration: Fetch specialized forensic intelligence concurrently in the background
    getEmailThreatIntelligence(emailId)
      .then((res) => setThreatIntelData(res))
      .catch((e) => console.warn('Threat intel background load notice:', e?.message));

    setDnaLoading(true);
    getEmailDNA(emailId)
      .then((res) => {
        if (res && res.overall_dna_hash) {
          setDnaData(res);
          setDnaLoading(false);
        } else {
          // Auto-generate DNA if not generated yet
          generateEmailDNA(emailId)
            .then((genRes) => {
              setDnaData(genRes);
              setDnaLoading(false);
            })
            .catch(() => setDnaLoading(false));
        }
      })
      .catch(() => {
        // Auto-generate DNA on 404
        generateEmailDNA(emailId)
          .then((genRes) => {
            setDnaData(genRes);
            setDnaLoading(false);
          })
          .catch(() => setDnaLoading(false));
      });

    getEmailArtifacts(emailId)
      .then((res) => setArtifactsData(res))
      .catch((e) => console.warn('Artifacts background load notice:', e?.message));

    getEmailAuthResults(emailId)
      .then((res) => setAuthData(res))
      .catch((e) => console.warn('Auth results background load notice:', e?.message));

    getEmailRelayHops(emailId)
      .then((res) => setHopsData(res))
      .catch((e) => console.warn('Relay hops background load notice:', e?.message));

    getEmailHeaders(emailId)
      .then((res) => setHeadersData(res))
      .catch((e) => console.warn('Headers background load notice:', e?.message));

    getEmailStructure(emailId)
      .then((res) => setStructureData(res))
      .catch((e) => console.warn('Structure background load notice:', e?.message));

    getSimilarEmails(emailId)
      .then((res) => setSimilarityData(res))
      .catch((e) => console.warn('Similarity background load notice:', e?.message));

    getEmailCorrelations(emailId, 40.0)
      .then((res) => setCorrelationsData(res))
      .catch((e) => console.warn('Correlations background load notice:', e?.message));

    getEmailCampaignMemberships(emailId)
      .then((res) => setMembershipsData(res))
      .catch((e) => console.warn('Campaign memberships background load notice:', e?.message));

    getInvestigationGraphForEmail(emailId)
      .then((res) => setGraphData(res))
      .catch((e) => console.warn('Graph background load notice:', e?.message));

    getEmailDomainIntelligence(emailId)
      .then((res) => setDomainIntelData(res))
      .catch((e) => console.warn('Domain intel background load notice:', e?.message));

    getEmailInfrastructureIntelligence(emailId)
      .then((res) => setInfraIntelData(res))
      .catch((e) => console.warn('Infra intel background load notice:', e?.message));
  };

  const handleGenerateDNA = async () => {
    if (!selectedEmailId) return;
    setDnaLoading(true);
    try {
      const res = await generateEmailDNA(selectedEmailId);
      setDnaData(res);
    } catch (err: any) {
      console.error('Failed to generate DNA:', err);
    } finally {
      setDnaLoading(false);
    }
  };

  // Automatically generate and load Email DNA profile when landing on an email
  useEffect(() => {
    if (selectedEmailId && !dnaData && !dnaLoading) {
      handleGenerateDNA();
    }
  }, [selectedEmailId]);

  const pollJobUntilDone = (jobId: string) => {
    const poll = async () => {
      try {
        const updated = await getJobStatus(jobId);
        setActiveJob(updated);
        if (updated.status === 'COMPLETED' || updated.status === 'FAILED' || updated.status === 'CANCELLED') {
          if (updated.status === 'COMPLETED' && updated.email_id) {
            await loadEmails();
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
    setActiveJob(null);
    if (pollTimeoutRef.current) window.clearTimeout(pollTimeoutRef.current);
    try {
      const res = await uploadEmlFile(file);
      setSelectedEmailId(res.email_id);
      setActiveTab('overview');
      setActiveJob({
        job_id: res.job_id,
        job_type: 'EMAIL_ANALYSIS',
        status: 'PENDING',
        stage: 'QUEUED',
        progress: 0,
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

  const handleLoadDemoLure = () => {
    const demoContent = `From: "Payroll Department" <payroll-service@paypal-security-alert.xyz>
To: victim.employee@acme-corp.com
Subject: URGENT: Direct Deposit Account Verification Required
Date: Sun, 06 Sep 2026 12:00:00 +0000
Message-ID: <20260906120000.12345.payload@paypal-security-alert.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_MAILINTEL_DEMO"
Received: from mx.google.com by target.corp with SMTP; Sun, 06 Sep 2026 12:05:00 +0000
Received: from relay-hop2.nl (185.220.101.5) by mx.google.com with ESMTP; Sun, 06 Sep 2026 12:03:00 +0000
Received: from origin-mta.ru (195.154.12.34) by relay-hop2.nl with SMTP; Sun, 06 Sep 2026 12:01:00 +0000
Authentication-Results: mx.google.com; spf=fail (google.com: domain of payroll-service@paypal-security-alert.xyz does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=payroll-service@paypal-security-alert.xyz; dkim=none; dmarc=fail

--BOUNDARY_MAILINTEL_DEMO
Content-Type: text/html; charset="utf-8"

<html>
<body>
<h2>Urgent Action Required: Confirm Direct Deposit Banking Information</h2>
<p>Dear Employee,</p>
<p>Our automated payroll audit has identified an inconsistency in your direct deposit disbursement settings.</p>
<p>Please update your credentials immediately by clicking below:</p>
<p><a href="https://payroll-verification-portal.paypal-security-alert.xyz/auth/login">https://payroll-verification-portal.paypal-security-alert.xyz/auth/login</a></p>
<p>Failure to complete this within 24 hours will delay your incoming salary payment.</p>
</body>
</html>

--BOUNDARY_MAILINTEL_DEMO
Content-Type: application/pdf; name="Payroll_Disbursement_Audit.pdf"
Content-Disposition: attachment; filename="Payroll_Disbursement_Audit.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXrp/Og0MTGCjQgMCBvYmoKPDwKL1R5cGUgL1BhZ2VzCi9Db3VudCAxCj4+
ZW5kb2JqCg==
--BOUNDARY_MAILINTEL_DEMO--`;
    const blob = new Blob([demoContent], { type: 'message/rfc822' });
    const demoFile = new File([blob], 'URGENT_Payroll_Verification_Lure.eml', { type: 'message/rfc822' });
    handleFileUpload(demoFile);
  };

  const copySha256 = () => {
    if (emailDetails?.sha256_hash) {
      navigator.clipboard.writeText(emailDetails.sha256_hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const isProcessing = !!activeJob && !['COMPLETED', 'FAILED', 'CANCELLED'].includes(activeJob.status);
  const currentStageIndex = activeJob
    ? PROCESSING_STEPS.findIndex((s) => s.stage === activeJob.stage)
    : -1;

  const campaignConfidenceScore: number | null = membershipsData?.memberships?.length
    ? Math.max(...membershipsData.memberships.map((m) => m.membership_confidence))
    : correlationsData?.correlations?.length
    ? Math.max(...correlationsData.correlations.map((c) => c.composite_correlation_score))
    : null;

  // Build unified map of Domain Intelligence (consolidates artifactsData + domainIntelData)
  const unifiedDomains = useMemo(() => {
    const map = new Map<string, {
      domain: string;
      riskLevel?: string;
      isSuspiciousTld?: boolean;
      isPunycode?: boolean;
      isNrd?: boolean;
      isDynamicDns?: boolean;
      sourceContexts: string[];
      registrar?: string | null;
      domainAgeDays?: number | null;
      registeredAt?: string | null;
    }>();

    // 1. Add extracted IOC domains
    artifactsData?.domains?.forEach((d) => {
      map.set(d.domain.toLowerCase(), {
        domain: d.domain,
        isSuspiciousTld: d.is_suspicious_tld,
        isPunycode: d.is_punycode,
        sourceContexts: d.source_contexts || [],
      });
    });

    // 2. Enrich with domain intelligence (RDAP, age, risk level)
    domainIntelData?.domains?.forEach((d) => {
      const key = d.domain.toLowerCase();
      const existing = map.get(key) || {
        domain: d.domain,
        sourceContexts: ['intelligence_lookup'],
      };
      map.set(key, {
        ...existing,
        riskLevel: d.risk_level,
        isNrd: d.is_nrd,
        isDynamicDns: d.is_dynamic_dns,
        isPunycode: existing.isPunycode || d.is_punycode,
        registrar: d.registration_intel?.registrar,
        domainAgeDays: d.registration_intel?.domain_age_days,
        registeredAt: d.registration_intel?.registered_at,
      });
    });

    return Array.from(map.values());
  }, [artifactsData, domainIntelData]);

  // Build unified map of IP Intelligence for relay hops
  const ipIntelMap = useMemo(() => {
    const map = new Map<string, any>();
    infraIntelData?.ips?.forEach((ip) => {
      if (ip.ip_address) map.set(ip.ip_address.trim(), ip);
    });
    return map;
  }, [infraIntelData]);

  // Filtered headers
  const filteredHeaders = useMemo(() => {
    if (!headersData?.headers) return [];
    if (!headerSearch.trim()) return headersData.headers;
    const q = headerSearch.toLowerCase();
    return headersData.headers.filter(
      (h) => h.header_name.toLowerCase().includes(q) || h.header_value.toLowerCase().includes(q)
    );
  }, [headersData, headerSearch]);

  // Dynamic evaluation of the 5 Email DNA signals:
  // - If safe: text container pill is in GREEN (mint bg, emerald border & text, green checkmark)
  // - If unsafe: text container pill is in RED (soft red bg, rose border & text, red alert icon)
  // - The entire surrounding card is styled in the enterprise light-blue theme (#F8FBFF, border #C9E2FA)
  const evaluatedDnaSignals = useMemo(() => {
    const spfStatus = (authData?.spf_result || '').toLowerCase();
    const dkimStatus = (authData?.dkim_result || '').toLowerCase();
    const dmarcStatus = (authData?.dmarc_result || '').toLowerCase();
    const spfFail = spfStatus.includes('fail') || spfStatus.includes('temperror') || spfStatus.includes('permerror');
    const dkimFail = dkimStatus.includes('fail') || dkimStatus.includes('temperror') || dkimStatus.includes('permerror');
    const dmarcFail = dmarcStatus.includes('fail');
    const authFailed = spfFail || dkimFail || dmarcFail;

    const findings = (analysisData?.findings || []).map((f) =>
      `${f.title || ''} ${f.description || ''} ${f.finding_type || ''}`.toLowerCase()
    );
    const findingsStr = findings.join(' ');
    const classification = (analysisData?.threat_classification || '').toLowerCase();
    const isThreat = classification === 'malicious' || classification === 'phishing' || classification === 'suspicious';

    // 1. Sender & Authentication
    const hasSpoofing = findingsStr.includes('spoof') || findingsStr.includes('mismatch') || findingsStr.includes('impersonat');
    const senderIdentitySafe = !hasSpoofing;
    const emailAuthSafe = !authFailed;
    const noSpoofingSafe = !hasSpoofing;
    const noAuthIssuesSafe = !authFailed;
    const senderOverallSafe = senderIdentitySafe && emailAuthSafe && noSpoofingSafe && noAuthIssuesSafe;

    // 2. Content Analysis
    const hasUrgency = findingsStr.includes('urgent') || findingsStr.includes('deadline') || findingsStr.includes('pressure') || findingsStr.includes('immediate') || findingsStr.includes('coercion');
    const hasPhishPhrases = isThreat || findingsStr.includes('phish') || findingsStr.includes('credential') || findingsStr.includes('password') || findingsStr.includes('wire transfer');
    const hasSuspiciousWording = hasUrgency || hasPhishPhrases || findingsStr.includes('suspicious');
    const hasDangerousAttachment = (artifactsData?.attachments || []).some(
      (a) => a.is_dangerous || (a.filename && /\.(exe|scr|vbs|bat|cmd|ps1|js|iso|hta)$/i.test(a.filename))
    );
    const subjectSafe = !hasUrgency && !isThreat;
    const wordingSafe = !hasSuspiciousWording;
    const languageSafe = !hasUrgency;
    const phrasesSafe = !hasPhishPhrases && !hasDangerousAttachment;
    const contentOverallSafe = subjectSafe && wordingSafe && languageSafe && phrasesSafe;

    // 3. Semantic & Behavioral Features
    const hasMaliciousUrl = (threatIntelData?.malicious_ioc_count || 0) > 0 || (threatIntelData?.suspicious_ioc_count || 0) > 0;
    const hasTargetingBehavior = findingsStr.includes('targeted') || findingsStr.includes('spear') || findingsStr.includes('unusual targeting');
    const hasImpersonationSignals = findingsStr.includes('impersonat') || findingsStr.includes('lookalike') || findingsStr.includes('ceo fraud');
    const recipientPatternSafe = true;
    const linksSafe = !hasMaliciousUrl;
    const targetingSafe = !hasTargetingBehavior;
    const impersonationSafe = !hasImpersonationSignals;
    const behavioralOverallSafe = recipientPatternSafe && linksSafe && targetingSafe && impersonationSafe;

    // 4. Infrastructure Footprint
    const hasHopAnomaly = (hopsData?.hops || []).some(
      (h) => h.reliability === 'LOW' || h.reliability === 'UNVERIFIED'
    );
    const hasHostingAnomaly = findingsStr.includes('bulletproof') || findingsStr.includes('blacklisted ip') || findingsStr.includes('suspicious relay');
    const hasDomainWarnings = findingsStr.includes('domain age') || findingsStr.includes('newly registered') || (infraIntelData?.ips || []).some((ip) => ip.risk_level === 'HIGH' || ip.risk_level === 'CRITICAL');
    const infraSafe = !hasHopAnomaly && !hasHostingAnomaly;
    const domainSafe = !hasDomainWarnings;
    const hostingSafe = !hasHostingAnomaly;
    const originSafe = !hasHopAnomaly;
    const infrastructureOverallSafe = infraSafe && domainSafe && hostingSafe && originSafe;

    // 5. Temporal Profile
    const hasTemporalAnomaly = (hopsData?.hops || []).some(
      (h) => (h.transit_delay_seconds || 0) > 86400
    ) || findingsStr.includes('temporal anomaly') || findingsStr.includes('burst sending');
    const sendingTimeSafe = true;
    const timingPatternSafe = !hasTemporalAnomaly;
    const deliverySafe = !hasTemporalAnomaly;
    const temporalOverallSafe = sendingTimeSafe && timingPatternSafe && deliverySafe;

    return [
      {
        key: 'technical_fingerprint' as keyof EmailDNAProfileResponse,
        icon: Mail,
        title: 'Sender & Authentication',
        hint: 'Checks who sent the email and whether the sender appears genuine.',
        isSafe: senderOverallSafe,
        statusText: senderOverallSafe ? 'LOOKS SAFE' : 'SUSPICIOUS',
        tags: [
          { text: senderIdentitySafe ? 'Sender identity looks consistent' : 'Sender identity inconsistency detected', isSafe: senderIdentitySafe },
          { text: emailAuthSafe ? 'Email authentication passed' : 'Email authentication failed or misaligned', isSafe: emailAuthSafe },
          { text: noSpoofingSafe ? 'No obvious sender spoofing detected' : 'Sender spoofing / display name trick flagged', isSafe: noSpoofingSafe },
          { text: noAuthIssuesSafe ? 'No unusual authentication issues' : 'Authentication verification issues detected', isSafe: noAuthIssuesSafe },
        ],
      },
      {
        key: 'content_fingerprint' as keyof EmailDNAProfileResponse,
        icon: FileText,
        title: 'Content Analysis',
        hint: 'Checks the message subject and content for suspicious language or tricks.',
        isSafe: contentOverallSafe,
        statusText: contentOverallSafe ? 'CLEAN' : 'FLAGGED',
        tags: [
          { text: subjectSafe ? 'Subject looks normal' : 'Subject flagged with urgency or trick', isSafe: subjectSafe },
          { text: wordingSafe ? 'No suspicious wording detected' : 'Suspicious wording detected in content', isSafe: wordingSafe },
          { text: languageSafe ? 'No urgent or threatening language' : 'Urgent or coercive pressure tactics detected', isSafe: languageSafe },
          { text: phrasesSafe ? 'No obvious phishing phrases' : 'Phishing phrases identified in body', isSafe: phrasesSafe },
        ],
      },
      {
        key: 'behavioral_fingerprint' as keyof EmailDNAProfileResponse,
        icon: Users,
        title: 'Semantic & Behavioral Features',
        hint: 'Checks who the email is targeting and whether its behavior looks unusual.',
        isSafe: behavioralOverallSafe,
        statusText: behavioralOverallSafe ? 'NORMAL' : 'ANOMALOUS',
        tags: [
          { text: 'Recipient pattern looks normal', isSafe: recipientPatternSafe },
          { text: linksSafe ? 'No suspicious links detected' : 'Suspicious links or redirectors detected', isSafe: linksSafe },
          { text: targetingSafe ? 'No unusual targeting behavior' : 'Unusual recipient targeting detected', isSafe: targetingSafe },
          { text: impersonationSafe ? 'No obvious impersonation signals' : 'Impersonation or spoofed identity signals', isSafe: impersonationSafe },
        ],
      },
      {
        key: 'infrastructure_fingerprint' as keyof EmailDNAProfileResponse,
        icon: Server,
        title: 'Infrastructure Footprint',
        hint: 'Checks where the email came from and whether its sending infrastructure is trustworthy.',
        isSafe: infrastructureOverallSafe,
        statusText: infrastructureOverallSafe ? 'GOOD' : 'HIGH RISK',
        tags: [
          { text: infraSafe ? 'Sending infrastructure looks trustworthy' : 'Sending infrastructure flagged as untrusted', isSafe: infraSafe },
          { text: domainSafe ? 'Sender domain has no major warning signs' : 'Sender domain flagged with security warnings', isSafe: domainSafe },
          { text: hostingSafe ? 'No suspicious hosting pattern detected' : 'Suspicious hosting or relay pattern detected', isSafe: hostingSafe },
          { text: originSafe ? 'Origin appears consistent' : 'Origin routing inconsistency detected', isSafe: originSafe },
        ],
      },
      {
        key: 'temporal_fingerprint' as keyof EmailDNAProfileResponse,
        icon: Clock,
        title: 'Temporal Profile',
        hint: 'Checks when the email was sent and whether its timing looks unusual.',
        isSafe: temporalOverallSafe,
        statusText: temporalOverallSafe ? 'NORMAL' : 'ANOMALOUS',
        tags: [
          { text: 'Sending time looks normal', isSafe: sendingTimeSafe },
          { text: timingPatternSafe ? 'No unusual timing pattern' : 'Unusual delivery timing pattern detected', isSafe: timingPatternSafe },
          { text: deliverySafe ? 'Delivery behavior appears typical' : 'Delivery latency or routing delay abnormal', isSafe: deliverySafe },
        ],
      },
    ];
  }, [analysisData, authData, hopsData, artifactsData, threatIntelData, infraIntelData]);

  const renderProcessingTimeline = () => {
    if (!activeJob) return null;
    return (
      <Section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-text-primary">Analyzing Submitted Email</h3>
            <p className="text-xs text-text-muted mt-0.5">
              Forensic pipeline executing — results update live as each analysis phase finishes.
            </p>
          </div>
          {activeJob.status === 'FAILED' && (
            <StatusBadge type="severity" value="critical" label="Analysis Failed" size="sm" />
          )}
        </div>
        <div className="space-y-1">
          {PROCESSING_STEPS.map((step, idx) => {
            const done = currentStageIndex > idx || activeJob.status === 'COMPLETED';
            const current = !done && currentStageIndex === idx && isProcessing;
            return (
              <div key={step.stage} className="flex items-center gap-3 py-1.5">
                {done ? (
                  <CheckCircle2 className="w-4 h-4 text-severity-safe shrink-0" />
                ) : current ? (
                  <Loader2 className="w-4 h-4 text-brand shrink-0 animate-spin" />
                ) : (
                  <Circle className="w-4 h-4 text-text-muted/50 shrink-0" />
                )}
                <span className={`text-xs ${done ? 'text-text-primary font-medium' : current ? 'text-brand font-semibold' : 'text-text-muted'}`}>
                  {step.label}
                </span>
              </div>
            );
          })}
        </div>
        {activeJob.status === 'FAILED' && activeJob.error && (
          <div className="px-3.5 py-2.5 rounded-lg bg-severity-critical-soft border border-severity-critical/20 text-xs text-severity-critical">
            {activeJob.error}
          </div>
        )}
      </Section>
    );
  };

  const renderUploadEmptyState = () => (
    <div className="space-y-6">
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`p-12 text-center rounded-xl border-2 border-dashed transition-colors ${
          isDragging ? 'border-brand bg-brand-soft' : 'border-workspace-border bg-workspace-card'
        }`}
      >
        <UploadCloud className={`w-9 h-9 mx-auto mb-3 ${isDragging ? 'text-brand' : 'text-text-muted'}`} />
        <h3 className="font-bold text-sm text-text-primary">Drop a .eml file to begin forensic analysis</h3>
        <p className="text-xs text-text-muted mt-1 max-w-md mx-auto">
          MailinteL parses RFC822 headers, verifies authentication (SPF/DKIM/DMARC), extracts IOCs,
          generates an Email DNA fingerprint, and correlates with threat campaigns.
        </p>
        <div className="mt-5 flex items-center justify-center gap-3">
          <label className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-white text-sm font-semibold hover:bg-brand-hover cursor-pointer transition-colors">
            <UploadCloud className="w-4 h-4" />
            Choose .eml File
            <input type="file" accept=".eml,message/rfc822" onChange={handleFileInput} disabled={uploading} className="hidden" />
          </label>
          <button
            onClick={handleLoadDemoLure}
            disabled={uploading}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-workspace text-text-secondary border border-workspace-border text-sm font-medium hover:bg-workspace-secondary transition-colors disabled:opacity-50"
          >
            Try a Sample Phishing Email
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="w-9 h-9 rounded-lg bg-brand-soft text-brand flex items-center justify-center">
              <UploadCloud className="w-4 h-4" />
            </div>
            <StatusBadge type="state" value="available" size="sm" />
          </div>
          <div className="text-sm font-bold text-text-primary">.eml Upload</div>
          <p className="text-xs text-text-muted">Deep forensic breakdown of submitted email files.</p>
        </div>
        <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-2.5 opacity-80">
          <div className="flex items-center justify-between">
            <div className="w-9 h-9 rounded-lg bg-workspace text-text-muted flex items-center justify-center">
              <Mail className="w-4 h-4" />
            </div>
            <StatusBadge type="state" value="planned" size="sm" />
          </div>
          <div className="text-sm font-bold text-text-primary">Mailbox Integration</div>
          <p className="text-xs text-text-muted">Connect Google Workspace or Microsoft 365.</p>
        </div>
        <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-2.5 opacity-80">
          <div className="flex items-center justify-between">
            <div className="w-9 h-9 rounded-lg bg-workspace text-text-muted flex items-center justify-center">
              <Chrome className="w-4 h-4" />
            </div>
            <StatusBadge type="state" value="coming_soon" size="sm" />
          </div>
          <div className="text-sm font-bold text-text-primary">Browser Extension</div>
          <p className="text-xs text-text-muted">Direct analysis of currently open webmail messages.</p>
        </div>
        <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-2.5 opacity-80">
          <div className="flex items-center justify-between">
            <div className="w-9 h-9 rounded-lg bg-workspace text-text-muted flex items-center justify-center">
              <Layers className="w-4 h-4" />
            </div>
            <StatusBadge type="state" value="planned" size="sm" />
          </div>
          <div className="text-sm font-bold text-text-primary">SIEM / SOC Webhook</div>
          <p className="text-xs text-text-muted">Automated ingestion from incident queues.</p>
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Top Action Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-text-primary tracking-tight">Forensic Analysis Workspace</h1>
          <p className="text-sm text-text-muted mt-0.5">
            Inspect authentication, indicators, chronological relay hops, DNA fingerprints, and campaign clustering.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-white text-sm font-semibold hover:bg-brand-hover cursor-pointer transition-colors disabled:opacity-50">
            <UploadCloud className="w-4 h-4" />
            {uploading ? 'Uploading…' : 'Analyze .eml'}
            <input type="file" accept=".eml,message/rfc822" onChange={handleFileInput} disabled={uploading} className="hidden" />
          </label>
          {emails.length > 0 && (
            <select
              value={selectedEmailId}
              onChange={(e) => {
                setSelectedEmailId(e.target.value);
                setActiveTab('overview');
                fetchFullInvestigation(e.target.value);
              }}
              className="px-3 py-2 text-sm bg-workspace-card border border-workspace-border rounded-lg text-text-primary font-medium focus:outline-none focus:border-brand max-w-xs"
            >
              {emails.map((em) => (
                <option key={em.id} value={em.id}>
                  {em.subject ? em.subject.substring(0, 48) : em.original_filename || em.id}
                </option>
              ))}
            </select>
          )}
          <button
            onClick={() => selectedEmailId && fetchFullInvestigation(selectedEmailId)}
            disabled={loading || !selectedEmailId}
            className="p-2 text-text-muted hover:text-brand hover:bg-workspace-card border border-transparent hover:border-workspace-border rounded-lg transition-colors disabled:opacity-40"
            title="Refresh Dossier"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          {selectedEmailId && (
            <button
              onClick={() => setIsAssistantOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 text-xs font-semibold shadow-sm transition-all"
              title="Open Grounded AI Case Assistant"
            >
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Ask Assistant</span>
            </button>
          )}
        </div>
      </div>

      {uploadError && (
        <div className="px-4 py-2.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-sm text-severity-high flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{uploadError}</span>
        </div>
      )}
      {error && (
        <div className="px-4 py-2.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-sm text-severity-high flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Processing Timeline when pipeline is actively running */}
      {activeJob && isProcessing && renderProcessingTimeline()}

      {!selectedEmailId && !isProcessing && renderUploadEmptyState()}

      {selectedEmailId && !isProcessing && (
        <div className="space-y-6">
          {/* Streamlined 4-Tab Navigation Bar */}
          <div className="flex items-center gap-2 border-b border-workspace-border overflow-x-auto">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`inline-flex items-center gap-2 px-4 py-3 text-sm font-semibold whitespace-nowrap border-b-2 transition-colors ${
                    isActive
                      ? 'border-brand text-brand'
                      : 'border-transparent text-text-muted hover:text-text-primary'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-brand' : 'text-text-muted'}`} />
                  {tab.label}
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
          {/* TAB 1: OVERVIEW */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Executive Classification Banner & Quick Navigation */}
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

                  {/* Contextual Jump Actions */}
                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                      onClick={() => setActiveTab('indicators')}
                      className="px-3.5 py-2 rounded-lg bg-workspace text-text-secondary border border-workspace-border text-xs font-semibold hover:bg-workspace-secondary transition-colors"
                    >
                      View IOCs
                    </button>
                    {onOpenReport && (
                      <button
                        onClick={() => onOpenReport(selectedEmailId)}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors"
                      >
                        Full Forensic Report
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                {/* 3 Core Investigative Score Meters */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                  {/* Score 1: Threat Risk */}
                  <div
                    style={{
                      backgroundColor: '#FFFFFF',
                      border: '1px solid #C4DFF9',
                      borderRadius: '12px',
                    }}
                    className="p-4 space-y-2 shadow-2xs"
                  >
                    <div className="flex items-center gap-2 text-[11px] font-bold text-text-muted uppercase tracking-wide">
                      <ShieldAlert className="w-3.5 h-3.5 text-severity-high" />
                      Threat Risk Score
                    </div>
                    <div className="flex items-baseline gap-1.5">
                      <span
                        className="text-2xl font-bold text-text-primary"
                        style={{ fontFamily: 'Calibri, "Segoe UI", sans-serif' }}
                      >
                        {analysisData ? analysisData.threat_risk_score.toFixed(0) : '—'}
                      </span>
                      <span className="text-xs text-text-muted">/ 100</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-severity-high"
                        style={{ width: `${analysisData ? analysisData.threat_risk_score : 0}%` }}
                      />
                    </div>
                  </div>

                  {/* Score 2: Evidence Confidence */}
                  <div
                    style={{
                      backgroundColor: '#FFFFFF',
                      border: '1px solid #C4DFF9',
                      borderRadius: '12px',
                    }}
                    className="p-4 space-y-2 shadow-2xs"
                  >
                    <div className="flex items-center gap-2 text-[11px] font-bold text-text-muted uppercase tracking-wide">
                      <ShieldCheck className="w-3.5 h-3.5 text-severity-safe" />
                      Evidence Confidence
                    </div>
                    <div className="flex items-baseline gap-1.5">
                      <span
                        className="text-2xl font-bold text-text-primary"
                        style={{ fontFamily: 'Calibri, "Segoe UI", sans-serif' }}
                      >
                        {confidenceLabel(analysisData?.evidence_confidence_score)}
                      </span>
                      {analysisData && (
                        <span className="text-xs text-text-muted">{analysisData.evidence_confidence_score.toFixed(0)}%</span>
                      )}
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-severity-safe"
                        style={{ width: `${analysisData?.evidence_confidence_score || 0}%` }}
                      />
                    </div>
                  </div>

                  {/* Score 3: Campaign Correlation */}
                  <div
                    style={{
                      backgroundColor: '#FFFFFF',
                      border: '1px solid #C4DFF9',
                      borderRadius: '12px',
                    }}
                    className="p-4 space-y-2 shadow-2xs"
                  >
                    <div className="flex items-center gap-2 text-[11px] font-bold text-text-muted uppercase tracking-wide">
                      <Network className="w-3.5 h-3.5 text-brand" />
                      Campaign Correlation
                    </div>
                    <div className="flex items-baseline gap-1.5">
                      <span
                        className="text-2xl font-bold text-text-primary"
                        style={{ fontFamily: 'Calibri, "Segoe UI", sans-serif' }}
                      >
                        {campaignConfidenceScore !== null ? confidenceLabel(campaignConfidenceScore) : 'No relation'}
                      </span>
                      {campaignConfidenceScore !== null && (
                        <span className="text-xs text-text-muted">{campaignConfidenceScore.toFixed(0)}%</span>
                      )}
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
                      <div className="h-full rounded-full bg-brand" style={{ width: `${campaignConfidenceScore || 0}%` }} />
                    </div>
                  </div>
                </div>
              </Section>

              {/* Executive Summary & Threat Likelihoods */}
              {analysisData?.summary && (
                <Section className="space-y-3">
                  <h3 className="text-sm font-bold text-text-primary">Executive Summary</h3>
                  <p className="text-xs text-text-secondary leading-relaxed">{analysisData.summary}</p>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs">
                    <div
                      style={{ backgroundColor: '#FFFFFF', border: '1px solid #C4DFF9', borderRadius: '10px' }}
                      className="p-3 space-y-1 shadow-2xs"
                    >
                      <div className="text-[11px] text-text-muted font-medium">Compromised Account Likelihood</div>
                      <div className="font-semibold text-text-primary">{analysisData.compromised_account_likelihood}</div>
                    </div>
                    <div
                      style={{ backgroundColor: '#FFFFFF', border: '1px solid #C4DFF9', borderRadius: '10px' }}
                      className="p-3 space-y-1 shadow-2xs"
                    >
                      <div className="text-[11px] text-text-muted font-medium">Spoofed Domain Likelihood</div>
                      <div className="font-semibold text-text-primary">{analysisData.spoofed_domain_likelihood}</div>
                    </div>
                    <div
                      style={{ backgroundColor: '#FFFFFF', border: '1px solid #C4DFF9', borderRadius: '10px' }}
                      className="p-3 space-y-1 shadow-2xs"
                    >
                      <div className="text-[11px] text-text-muted font-medium">Anonymized Infrastructure</div>
                      <div className="font-semibold text-text-primary">{analysisData.anonymized_infrastructure_likelihood}</div>
                    </div>
                  </div>
                </Section>
              )}

              {/* Key Forensic Findings */}
              <Section className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-text-primary">Key Forensic Findings</h3>
                  <span className="text-xs text-text-muted">{analysisData?.findings.length || 0} findings flagged</span>
                </div>
                {analysisData && analysisData.findings.length > 0 ? (
                  <div className="space-y-2.5">
                    {analysisData.findings.map((f, idx) => (
                      <div
                        key={idx}
                        style={{ backgroundColor: '#FFFFFF', border: '1px solid #C4DFF9', borderRadius: '11px' }}
                        className="p-3.5 flex items-start gap-3 shadow-2xs"
                      >
                        <AlertTriangle className="w-4 h-4 text-severity-high mt-0.5 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-xs text-text-primary">{f.title}</span>
                            <StatusBadge type="severity" value={f.severity.toLowerCase()} label={`${f.severity} (${f.confidence.toFixed(0)}%)`} size="sm" />
                          </div>
                          <p className="text-[11px] text-text-secondary mt-1">{f.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyNote>No malicious forensic indicators or anomalies were flagged for this email.</EmptyNote>
                )}
              </Section>

              {/* AI Forensic Threat Reasoning Panel (Groq-Powered RAG) */}
              <AIForensicPanel
                emailId={selectedEmailId}
                threatScore={analysisData?.threat_risk_score}
                verdict={analysisData?.threat_classification}
              />

              {/* Human Analyst Layer & Active Learning Disposition Panel */}
              <AnalystDispositionPanel
                emailId={selectedEmailId}
                onDispositionUpdated={() => fetchFullInvestigation(selectedEmailId)}
              />

              {/* Evidence Preservation Bar */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-brand" />
                    <h3 className="text-sm font-bold text-text-primary">Evidence Integrity &amp; Preservation</h3>
                  </div>
                  {onExploreEvidence && (
                    <button
                      onClick={() => onExploreEvidence(selectedEmailId)}
                      className="inline-flex items-center gap-1.5 text-xs font-semibold text-brand hover:underline"
                    >
                      Inspect in Evidence Vault
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                  <div
                    style={{ backgroundColor: '#FFFFFF', border: '1px solid #C4DFF9', borderRadius: '10px' }}
                    className="p-3 shadow-2xs md:col-span-2"
                  >
                    <div className="text-[10px] text-text-muted uppercase font-bold tracking-wide">SHA-256 Hash</div>
                    <div className="flex items-center justify-between gap-2 mt-1">
                      <span className="font-mono text-text-primary break-all text-[11px]">
                        {emailDetails?.sha256_hash || 'Pending hash calculation'}
                      </span>
                      {emailDetails?.sha256_hash && (
                        <button
                          onClick={copySha256}
                          className="p-1 rounded bg-blue-50 border border-[#C4DFF9] text-text-muted hover:text-brand shrink-0"
                          title="Copy SHA-256"
                        >
                          {copiedHash ? <Check className="w-3.5 h-3.5 text-severity-safe" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      )}
                    </div>
                  </div>
                  <div
                    style={{ backgroundColor: '#FFFFFF', border: '1px solid #C4DFF9', borderRadius: '10px' }}
                    className="p-3 shadow-2xs"
                  >
                    <div className="text-[10px] text-text-muted uppercase font-bold tracking-wide">Ingested &amp; Size</div>
                    <div className="mt-1 text-text-primary font-semibold">
                      {fmtBytes(emailDetails?.email_size_bytes)}
                    </div>
                    <div className="text-[10px] text-text-muted">{fmtDateTime(emailDetails?.created_at)}</div>
                  </div>
                  <div
                    style={{ backgroundColor: '#FFFFFF', border: '1px solid #C4DFF9', borderRadius: '10px' }}
                    className="p-3 shadow-2xs"
                  >
                    <div className="text-[10px] text-text-muted uppercase font-bold tracking-wide">Evidence ID / Source</div>
                    <div className="mt-1 text-text-primary font-mono truncate text-[11px]">
                      {emailDetails?.evidence_id || 'Not assigned'}
                    </div>
                    <div className="text-[10px] text-text-muted">{emailDetails?.source_type || 'EML_UPLOAD'}</div>
                  </div>
                </div>
              </Section>

              {/* Email DNA Fingerprint - Light-Blue Container with Dynamic Safe (Green) / Unsafe (Red) Text Containers */}
              <div
                style={{
                  backgroundColor: '#F0F7FF',
                  border: '1px solid #B9DCFA',
                  borderRadius: '14px',
                  boxShadow: '0 1px 4px rgba(23, 59, 112, 0.05)',
                }}
                className="p-5 sm:p-6 space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-full bg-blue-50 border border-blue-200/80 flex items-center justify-center text-blue-600 shrink-0">
                      <Dna className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-slate-900">Email DNA Profiling</h3>
                      <p className="text-xs text-slate-500 mt-0.5">
                        We check five signals to explain whether this email looks safe or suspicious.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 self-start sm:self-center">
                    {dnaData?.overall_dna_hash && (
                      <span className="text-[11px] font-mono text-slate-700 px-3 py-1 rounded-lg bg-white/90 border border-[#C9E2FA] shadow-2xs">
                        DNA ID: {dnaData.overall_dna_hash.substring(0, 16)}…
                      </span>
                    )}
                    <button
                      onClick={handleGenerateDNA}
                      disabled={dnaLoading}
                      className="p-1.5 rounded-lg border border-[#C9E2FA] bg-white text-slate-400 hover:text-blue-600 hover:bg-blue-50/50 transition-colors disabled:opacity-50"
                      title="Regenerate / Refresh Email DNA"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${dnaLoading ? 'animate-spin text-blue-600' : ''}`} />
                    </button>
                  </div>
                </div>

                {dnaLoading || !dnaData ? (
                  <DNAStrandAnimation
                    label="Processing / In Progress"
                    subtext="Extracting structural MIME hierarchies, header sequence hashes, and behavioral DNA patterns..."
                  />
                ) : (
                  <div className="space-y-3">
                    {evaluatedDnaSignals.map((sig) => {
                      const Icon = sig.icon;
                      const isExpanded = expandedDnaCategory === sig.key;
                      const dataObj = ((dnaData && dnaData[sig.key]) || {}) as Record<string, any>;
                      const entries = Object.entries(dataObj).filter(([_, v]) => v !== null && v !== undefined && v !== '');

                      return (
                        <div
                          key={sig.key}
                          className={`rounded-2xl border bg-white p-4 sm:p-5 shadow-2xs transition-all ${
                            sig.isSafe
                              ? 'border-[#C9E2FA]/80 hover:border-[#96C8F5]'
                              : 'border-rose-200/90 hover:border-rose-300'
                          }`}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex items-start gap-3.5 min-w-0">
                              <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shrink-0 mt-0.5">
                                <Icon className="w-5 h-5" />
                              </div>
                              <div className="min-w-0">
                                <div className="text-sm font-bold text-slate-900 leading-snug">
                                  {sig.title}
                                </div>
                                <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                                  {sig.hint}
                                </p>
                              </div>
                            </div>

                            <div className="flex items-center gap-2.5 shrink-0">
                              <div
                                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold shadow-2xs transition-colors ${
                                  sig.isSafe
                                    ? 'bg-[#F0FDF4] border border-emerald-300 text-emerald-700'
                                    : 'bg-rose-50 border border-rose-300 text-rose-700'
                                }`}
                              >
                                {sig.isSafe ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                                ) : (
                                  <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                                )}
                                <span>{sig.statusText}</span>
                              </div>

                              <button
                                type="button"
                                onClick={() => setExpandedDnaCategory(isExpanded ? null : sig.key)}
                                className="p-1 rounded-lg hover:bg-slate-50 text-slate-400 hover:text-slate-600 transition-colors"
                                title={isExpanded ? 'Collapse' : 'Expand technical parameters'}
                              >
                                <ChevronDown
                                  className={`w-4 h-4 text-blue-600 transition-transform duration-200 ${
                                    isExpanded ? 'rotate-180' : ''
                                  }`}
                                />
                              </button>
                            </div>
                          </div>

                          {/* Natural Language Signal Pills: GREEN if safe, RED if unsafe */}
                          <div className="mt-3.5 flex flex-wrap gap-2 pt-1 border-t border-slate-100/80">
                            {sig.tags.map((tag, idx) => (
                              <span
                                key={idx}
                                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium shadow-2xs transition-all ${
                                  tag.isSafe
                                    ? 'bg-[#F0FDF4] border border-emerald-300 text-emerald-800'
                                    : 'bg-rose-50 border border-rose-300 text-rose-800'
                                }`}
                              >
                                {tag.isSafe ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                                ) : (
                                  <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                                )}
                                <span>{tag.text}</span>
                              </span>
                            ))}
                          </div>

                          {/* Optional Expanded Detailed Features */}
                          {isExpanded && entries.length > 0 && (
                            <div className="mt-3.5 pt-3.5 border-t border-slate-100">
                              <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                                Technical Profile Attributes ({entries.length})
                              </div>
                              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                                {entries.map(([k, val]) => (
                                  <div
                                    key={k}
                                    className="p-2.5 rounded-xl bg-blue-50/40 border border-blue-100/70 text-xs"
                                  >
                                    <div className="text-[10px] text-slate-500 font-semibold uppercase">
                                      {k.replace(/_/g, ' ')}
                                    </div>
                                    <div className="text-slate-800 font-medium break-all mt-0.5 text-[11px]">
                                      {typeof val === 'boolean'
                                        ? val
                                          ? 'Yes / Verified'
                                          : 'No / None'
                                        : typeof val === 'object'
                                        ? JSON.stringify(val)
                                        : String(val)}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 2: THREAT INDICATORS (IOCs) */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'indicators' && (
            <div className="space-y-6">
              {/* Multi-Provider Consensus */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Threat Intelligence Consensus</h3>
                    <p className="text-xs text-text-muted">Aggregated verdicts across configured threat feeds</p>
                  </div>
                  {threatIntelData && (
                    <StatusBadge
                      type="severity"
                      value={severityForClassification(threatIntelData.overall_threat_level)}
                      label={threatIntelData.overall_threat_level}
                      size="sm"
                    />
                  )}
                </div>

                {threatIntelData && threatIntelData.indicators.length > 0 ? (
                  <div className="grid grid-cols-3 gap-3 text-center text-xs">
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                      <div className="text-text-muted">Indicators Analyzed</div>
                      <div className="text-lg font-bold text-text-primary mt-1">{threatIntelData.total_iocs_analyzed}</div>
                    </div>
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                      <div className="text-text-muted">Malicious</div>
                      <div className="text-lg font-bold text-severity-critical mt-1">{threatIntelData.malicious_ioc_count}</div>
                    </div>
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                      <div className="text-text-muted">Suspicious</div>
                      <div className="text-lg font-bold text-severity-high mt-1">{threatIntelData.suspicious_ioc_count}</div>
                    </div>
                  </div>
                ) : (
                  <EmptyNote>No threat indicators have been checked against threat intelligence providers.</EmptyNote>
                )}

                {/* Indicators List */}
                <div className="space-y-2">
                  {(threatIntelData?.indicators || []).map((ind) => {
                    const key = `${ind.indicator_type}:${ind.indicator_value}`;
                    const isExpanded = expandedIndicator === key;
                    return (
                      <div key={key} className="rounded-xl border border-workspace-border overflow-hidden bg-workspace">
                        <button
                          onClick={() => setExpandedIndicator(isExpanded ? null : key)}
                          className="w-full flex items-center justify-between p-3.5 hover:bg-workspace-secondary transition-colors text-left"
                        >
                          <div className="min-w-0">
                            <div className="text-xs font-mono font-semibold text-text-primary truncate">{ind.indicator_value}</div>
                            <div className="text-[11px] text-text-muted">{ind.indicator_type} · {ind.provider_count} provider(s) queried</div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <StatusBadge type="severity" value={severityForClassification(ind.consensus_verdict)} label={ind.consensus_verdict} size="sm" />
                            {isExpanded ? <ChevronUp className="w-4 h-4 text-text-muted" /> : <ChevronDown className="w-4 h-4 text-text-muted" />}
                          </div>
                        </button>
                        {isExpanded && (
                          <div className="p-3.5 border-t border-workspace-border bg-workspace-card space-y-2.5">
                            <div className="flex flex-wrap gap-3 text-[11px] text-text-muted">
                              <span>Consensus Score: <strong className="text-text-secondary">{ind.consensus_threat_score.toFixed(0)}/100</strong></span>
                              <span>Confidence: <strong className="text-text-secondary">{ind.consensus_confidence.toFixed(0)}%</strong></span>
                              {ind.aggregated_tags.length > 0 && <span>Tags: <strong className="text-text-secondary">{ind.aggregated_tags.join(', ')}</strong></span>}
                            </div>
                            <div className="space-y-1.5">
                              {ind.provider_reports.map((p, i) => (
                                <div key={i} className="flex items-center justify-between text-[11px] p-2 rounded-lg bg-workspace">
                                  <span className="text-text-secondary font-medium">{p.provider}</span>
                                  <span className="text-text-muted">{p.verdict} · score {p.threat_score.toFixed(0)} · confidence {p.confidence.toFixed(0)}%</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </Section>

              {/* Extracted URLs with Deep Forensic Intelligence */}
              <Section className="space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">
                      Extracted URLs ({artifactsData?.total_urls ?? 0})
                    </h3>
                    <p className="text-xs text-text-muted">
                      Automated classification, tracking telemetry, and threat intelligence verdicts
                    </p>
                  </div>
                  <span className="text-xs text-text-muted font-mono">Defanged representations</span>
                </div>

                {artifactsData && artifactsData.urls.length > 0 ? (
                  <div className="space-y-2.5">
                    {artifactsData.urls.map((u, idx) => {
                      const rawUrl = (u as any).url || u.defanged_url;
                      const category = classifyUrlCategory(rawUrl, u.context);
                      const isExpanded = expandedUrl === idx;

                      // Cross-reference with threat intelligence indicators
                      const matchIntel = threatIntelData?.indicators?.find(
                        (ind) =>
                          ind.indicator_type === 'URL' &&
                          (ind.indicator_value.toLowerCase() === rawUrl.toLowerCase() ||
                            ind.indicator_value.toLowerCase() === u.defanged_url.toLowerCase() ||
                            rawUrl.toLowerCase().includes(ind.indicator_value.toLowerCase()) ||
                            ind.indicator_value.toLowerCase().includes(rawUrl.toLowerCase()))
                      );

                      const verdict = matchIntel?.consensus_verdict || (rawUrl.includes('phish') ? 'SUSPICIOUS' : 'BENIGN');
                      const score = matchIntel?.consensus_threat_score ?? 0;
                      const confidence = matchIntel?.consensus_confidence ? Math.round(matchIntel.consensus_confidence * 100) : 80;

                      return (
                        <div key={idx} className="rounded-xl border border-workspace-border overflow-hidden bg-workspace transition-all">
                          <div
                            onClick={() => setExpandedUrl(isExpanded ? null : idx)}
                            className="p-3.5 hover:bg-workspace-secondary cursor-pointer transition-colors flex items-center justify-between gap-3"
                          >
                            <div className="min-w-0 space-y-1.5 flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border ${category.badgeClass}`}>
                                  {category.label}
                                </span>
                                <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-workspace-card border border-workspace-border text-text-muted">
                                  {u.context || 'BODY_LINK'}
                                </span>
                                {u.domain && (
                                  <span className="text-[10px] font-mono text-text-secondary font-semibold">
                                    Host: {u.domain}
                                  </span>
                                )}
                              </div>
                              <div className="font-mono text-xs text-text-primary truncate max-w-2xl" title={u.defanged_url}>
                                {u.defanged_url}
                              </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <StatusBadge
                                type="severity"
                                value={severityForClassification(verdict)}
                                label={verdict}
                                size="sm"
                              />
                              {isExpanded ? <ChevronUp className="w-4 h-4 text-text-muted" /> : <ChevronDown className="w-4 h-4 text-text-muted" />}
                            </div>
                          </div>

                          {isExpanded && (
                            <div className="p-3.5 border-t border-workspace-border bg-workspace-card space-y-2.5 text-xs">
                              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-text-muted">
                                <div>Verdict: <strong className="text-text-primary">{verdict}</strong></div>
                                <div>Threat Score: <strong className="text-text-primary">{score}/100</strong></div>
                                <div>Confidence: <strong className="text-text-primary">{confidence}%</strong></div>
                                <div>Classification: <strong className="text-text-primary">{category.label}</strong></div>
                              </div>
                              <div className="p-2 rounded-lg bg-workspace font-mono text-[11px] text-text-secondary break-all">
                                <span className="text-text-muted select-none font-bold">Defanged: </span>{u.defanged_url}
                              </div>
                              {matchIntel && matchIntel.provider_reports && matchIntel.provider_reports.length > 0 && (
                                <div className="space-y-1 pt-1">
                                  <div className="text-[10px] font-bold text-text-muted uppercase tracking-wide">Threat Feed Attribution</div>
                                  {matchIntel.provider_reports.map((p, pIdx) => (
                                    <div key={pIdx} className="flex items-center justify-between text-[11px] p-2 rounded-md bg-workspace border border-workspace-border">
                                      <span className="font-medium text-text-secondary">{p.provider}</span>
                                      <span className="text-text-muted">{p.verdict} · {p.details || `Score: ${p.threat_score}`}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <EmptyNote>No URLs were found in this email.</EmptyNote>
                )}
              </Section>

              {/* Unified Domains & DNS Intelligence (Consolidated into ONE authoritative card) */}
              <Section className="space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Domains &amp; DNS Intelligence ({unifiedDomains.length})</h3>
                    <p className="text-xs text-text-muted">Domain registration, age, punycode, and risk evaluation</p>
                  </div>
                </div>

                {unifiedDomains.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {unifiedDomains.map((d, idx) => (
                      <div key={idx} className="p-3.5 rounded-xl bg-workspace border border-workspace-border text-xs space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono font-semibold text-text-primary truncate">{d.domain}</span>
                          {d.riskLevel && (
                            <StatusBadge
                              type="severity"
                              value={severityForClassification(d.riskLevel === 'CRITICAL' || d.riskLevel === 'HIGH' ? 'MALICIOUS' : d.riskLevel === 'MEDIUM' ? 'SUSPICIOUS' : 'BENIGN')}
                              label={d.riskLevel}
                              size="sm"
                            />
                          )}
                        </div>

                        <div className="flex flex-wrap gap-1.5 text-[10px]">
                          {d.isNrd && <span className="px-1.5 py-0.5 rounded bg-severity-high-soft text-severity-high font-semibold">Newly Registered (NRD)</span>}
                          {d.isDynamicDns && <span className="px-1.5 py-0.5 rounded bg-severity-high-soft text-severity-high font-semibold">Dynamic DNS</span>}
                          {d.isSuspiciousTld && <span className="px-1.5 py-0.5 rounded bg-severity-high-soft text-severity-high font-semibold">Suspicious TLD</span>}
                          {d.isPunycode && <span className="px-1.5 py-0.5 rounded bg-severity-high-soft text-severity-high font-semibold">Punycode</span>}
                          {d.sourceContexts.map((ctx, cIdx) => (
                            <span key={cIdx} className="px-1.5 py-0.5 rounded bg-workspace-card border border-workspace-border text-text-muted">{ctx}</span>
                          ))}
                        </div>

                        {(d.registrar || d.domainAgeDays !== null || d.registeredAt) && (
                          <div className="grid grid-cols-2 gap-2 text-[11px] text-text-muted pt-1 border-t border-workspace-border/60">
                            <span>Registrar: <strong className="text-text-secondary">{d.registrar || 'Unknown'}</strong></span>
                            <span>Age: <strong className="text-text-secondary">{d.domainAgeDays !== null && d.domainAgeDays !== undefined ? `${d.domainAgeDays} days` : 'Unknown'}</strong></span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyNote>No domains were observed in this email.</EmptyNote>
                )}
              </Section>

              {/* Attachments */}
              <Section className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-text-primary">File Attachments ({artifactsData?.total_attachments ?? 0})</h3>
                  <span className="text-xs text-text-muted">Payload analysis</span>
                </div>
                {artifactsData && artifactsData.attachments.length > 0 ? (
                  <div className="space-y-2">
                    {artifactsData.attachments.map((a, idx) => (
                      <div key={idx} className="p-3.5 rounded-xl bg-workspace border border-workspace-border text-xs flex items-center justify-between gap-3">
                        <div className="min-w-0 space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-text-primary truncate">{a.filename}</span>
                            {a.is_dangerous && <StatusBadge type="severity" value="critical" label="Dangerous Executable" size="sm" />}
                            {a.has_double_extension && <span className="text-[10px] px-1.5 py-0.5 rounded bg-severity-high-soft text-severity-high">Double Extension</span>}
                          </div>
                          <div className="text-[11px] text-text-muted font-mono">{a.content_type} · {(a.size_bytes / 1024).toFixed(1)} KB</div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyNote>No file attachments were included in this email.</EmptyNote>
                )}
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 3: FORENSICS & INFRASTRUCTURE */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'forensics' && (
            <div className="space-y-6">
              {/* Email Authentication Results */}
              <Section className="space-y-4">
                <h3 className="text-sm font-bold text-text-primary">Sender Authentication Suite</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                  {[
                    { label: 'SPF', value: authData?.spf_result },
                    { label: 'DKIM', value: authData?.dkim_result },
                    { label: 'DMARC', value: authData?.dmarc_result },
                    { label: 'From Alignment', value: authData?.from_alignment_result },
                  ].map((row) => (
                    <div key={row.label} className="p-3.5 rounded-xl bg-workspace border border-workspace-border">
                      <div className="text-[10px] text-text-muted font-bold uppercase tracking-wide">{row.label}</div>
                      <div className={`text-base font-bold mt-1 ${row.value === 'PASS' ? 'text-severity-safe' : row.value ? 'text-severity-high' : 'text-text-muted'}`}>
                        {row.value || 'Not evaluated'}
                      </div>
                    </div>
                  ))}
                </div>

                {authData && authData.dkim_signatures.length > 0 && (
                  <div className="space-y-2 pt-1">
                    <h4 className="text-xs font-bold text-text-primary">DKIM Cryptographic Signatures</h4>
                    {authData.dkim_signatures.map((s, i) => (
                      <div key={i} className="p-2.5 rounded-lg bg-workspace border border-workspace-border text-[11px] font-mono text-text-secondary flex items-center gap-4">
                        <span>Domain: <strong className="text-text-primary">{s.domain || '—'}</strong></span>
                        <span>Selector: <strong className="text-text-primary">{s.selector || '—'}</strong></span>
                        <span>Algorithm: <strong className="text-text-primary">{s.algorithm || '—'}</strong></span>
                      </div>
                    ))}
                  </div>
                )}
              </Section>

              {/* Reconstructed Transmission Path & Relay IP Intelligence */}
              <Section className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Reconstructed Transmission Path</h3>
                    <p className="text-xs text-text-muted">Chronological Received header relay hops enriched with network intelligence</p>
                  </div>
                  <span className="text-xs text-text-muted">{hopsData?.total_hops ?? 0} total hops</span>
                </div>

                {/* Relay Hops Timeline */}
                {hopsData && hopsData.hops.length > 0 ? (
                  <div className="space-y-3">
                    {hopsData.hops.map((hop) => {
                      const ipEnrichment = hop.source_ip ? ipIntelMap.get(hop.source_ip.trim()) : null;

                      return (
                        <div key={hop.sequence_number} className="p-4 rounded-xl bg-workspace border border-workspace-border flex items-start gap-3.5">
                          <span className="w-6 h-6 rounded-full bg-brand text-white font-bold text-[11px] flex items-center justify-center shrink-0 mt-0.5">
                            {hop.sequence_number}
                          </span>
                          <div className="flex-1 text-xs space-y-1.5">
                            <div className="flex items-center justify-between gap-2 flex-wrap">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-text-primary font-mono text-sm">{hop.source_ip || 'Unresolved IP'}</span>
                                {ipEnrichment?.risk_level && (
                                  <StatusBadge
                                    type="severity"
                                    value={severityForClassification(ipEnrichment.risk_level === 'CRITICAL' || ipEnrichment.risk_level === 'HIGH' ? 'MALICIOUS' : ipEnrichment.risk_level === 'MEDIUM' ? 'SUSPICIOUS' : 'BENIGN')}
                                    label={ipEnrichment.risk_level}
                                    size="sm"
                                  />
                                )}
                              </div>
                              <span className="text-[10px] px-2 py-0.5 rounded-md bg-workspace-card border border-workspace-border text-text-muted font-medium">
                                {hop.reliability} reliability
                              </span>
                            </div>

                            <div className="text-text-secondary text-[11px]">
                              {hop.source_host || 'Unknown host'} <span className="text-text-muted">→</span> {hop.destination_host || 'next hop'}
                            </div>

                            {(ipEnrichment || hop.protocol || hop.tls_info) && (
                              <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] text-text-muted border-t border-workspace-border/50">
                                {ipEnrichment?.asn && (
                                  <span>ASN: <strong className="text-text-secondary">{ipEnrichment.asn}</strong></span>
                                )}
                                {(ipEnrichment?.hosting_provider || ipEnrichment?.asn_org) && (
                                  <span>Org: <strong className="text-text-secondary">{ipEnrichment.hosting_provider || ipEnrichment.asn_org}</strong></span>
                                )}
                                {(ipEnrichment?.city_name || ipEnrichment?.country_name) && (
                                  <span className="flex items-center gap-1">
                                    <MapPin className="w-3 h-3 text-text-muted" />
                                    <strong className="text-text-secondary">{ipEnrichment.city_name ? `${ipEnrichment.city_name}, ` : ''}{ipEnrichment.country_name}</strong>
                                  </span>
                                )}
                                {hop.protocol && <span>{hop.protocol}{hop.tls_info ? ` (${hop.tls_info})` : ''}</span>}
                              </div>
                            )}

                            {ipEnrichment?.risk_tags && ipEnrichment.risk_tags.length > 0 && (
                              <div className="flex flex-wrap gap-1.5 pt-1">
                                {ipEnrichment.risk_tags.map((tag: string, tIdx: number) => (
                                  <span key={tIdx} className="px-2 py-0.5 rounded bg-workspace-card border border-workspace-border text-[10px] text-severity-high font-semibold">
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <EmptyNote>No relay hops could be reconstructed for this email.</EmptyNote>
                )}

                {/* Interactive Leaflet Transmission Route Map */}
                <div className="pt-2">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <h4 className="text-xs font-bold text-text-primary uppercase tracking-wide">
                        Physical Transmission Route &amp; Relay Nodes
                      </h4>
                      <p className="text-[11px] text-text-muted">
                        Live geographic routing from sender origin to recipient mail server with city-level zoom
                      </p>
                    </div>
                    {onExploreGeo && (
                      <button
                        onClick={() => onExploreGeo(selectedEmailId)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-workspace text-text-secondary border border-workspace-border text-xs font-semibold hover:bg-workspace-secondary transition-colors"
                      >
                        Full Screen Map
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                  <GeoIntelligenceMap initialEmailId={selectedEmailId} embedded={true} />
                </div>
              </Section>

              {/* Message Content Inspection */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-text-primary">Message Body &amp; MIME Structure</h3>
                  <div className="flex items-center gap-1 bg-workspace p-1 rounded-lg border border-workspace-border">
                    <button
                      onClick={() => setBodyPreviewTab('text')}
                      className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                        bodyPreviewTab === 'text' ? 'bg-workspace-card text-brand shadow-sm' : 'text-text-muted hover:text-text-primary'
                      }`}
                    >
                      Plain Text
                    </button>
                    <button
                      onClick={() => setBodyPreviewTab('html')}
                      className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                        bodyPreviewTab === 'html' ? 'bg-workspace-card text-brand shadow-sm' : 'text-text-muted hover:text-text-primary'
                      }`}
                    >
                      Sanitized HTML
                    </button>
                  </div>
                </div>

                {structureData ? (
                  <div className="space-y-3">
                    <div className="flex flex-wrap gap-4 text-[11px] text-text-muted">
                      <span>MIME Parts: <strong className="text-text-secondary">{structureData.total_mime_parts}</strong></span>
                      <span>Attachments: <strong className="text-text-secondary">{structureData.attachment_count}</strong></span>
                      <span>Content-Type: <strong className="text-text-secondary font-mono">{structureData.root_content_type}</strong></span>
                    </div>

                    {bodyPreviewTab === 'text' ? (
                      <pre className="text-xs text-text-secondary font-mono whitespace-pre-wrap max-h-80 overflow-y-auto p-4 bg-workspace rounded-xl border border-workspace-border">
                        {structureData.plain_text_body || 'No plain text payload present.'}
                      </pre>
                    ) : (
                      <div className="text-xs text-text-secondary max-h-80 overflow-y-auto p-4 bg-workspace rounded-xl border border-workspace-border">
                        {structureData.html_body ? (
                          <div
                            dangerouslySetInnerHTML={{
                              __html: sanitizeEmailHtml(structureData.html_body.substring(0, 5000)),
                            }}
                          />
                        ) : (
                          <span className="text-text-muted">No HTML payload present in this message.</span>
                        )}
                      </div>
                    )}
                  </div>
                ) : (
                  <EmptyNote>Message structure has not been parsed for this email yet.</EmptyNote>
                )}
              </Section>

              {/* Raw RFC822 Headers Table */}
              <Section className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Raw RFC822 Headers</h3>
                    <p className="text-xs text-text-muted">{headersData?.total_headers ?? 0} total headers recorded</p>
                  </div>
                  <div className="relative max-w-xs w-full">
                    <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Filter headers…"
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
                  <EmptyNote>No matching headers found.</EmptyNote>
                )}
              </Section>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB 4: CAMPAIGN CORRELATION & GRAPH */}
          {/* ========================================================================= */}
          {!loading && activeTab === 'correlation' && (
            <div className="space-y-6">
              {/* Campaign Memberships */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Campaign Memberships</h3>
                    <p className="text-xs text-text-muted">Multi-campaign hypotheses evaluated across email fingerprints</p>
                  </div>
                  {membershipsData?.is_bridge_entity && (
                    <StatusBadge type="severity" value="high" label="Bridge Entity Observed" size="sm" />
                  )}
                </div>

                {membershipsData && membershipsData.memberships.length > 0 ? (
                  <div className="space-y-2.5">
                    {membershipsData.memberships.map((m) => (
                      <div key={m.membership_id} className="p-4 rounded-xl bg-workspace border border-workspace-border flex items-center justify-between gap-3 text-xs">
                        <div className="min-w-0">
                          <div className="font-semibold text-text-primary text-sm truncate">{m.campaign_name || 'Unnamed campaign'}</div>
                          <div className="text-text-muted mt-0.5">Status: <strong className="text-text-secondary">{m.campaign_status}</strong></div>
                        </div>
                        <div className="text-right">
                          <div className="font-mono font-bold text-brand text-base">{m.membership_confidence.toFixed(0)}%</div>
                          <div className="text-[10px] text-text-muted">Confidence</div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyNote>No campaign memberships have been linked to this email.</EmptyNote>
                )}
              </Section>

              {/* Correlated Emails */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-text-primary">Correlated Emails</h3>
                    <p className="text-xs text-text-muted">Composite similarity above threshold</p>
                  </div>
                  <span className="text-xs text-text-muted">{correlationsData?.total_correlated_emails ?? 0} correlated</span>
                </div>

                {correlationsData && correlationsData.correlations.length > 0 ? (
                  <div className="space-y-3">
                    {correlationsData.correlations.map((c, i) => (
                      <div key={i} className="p-4 rounded-xl bg-workspace border border-workspace-border space-y-2 text-xs">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-text-primary truncate text-sm">{c.target_subject || c.target_email_id}</span>
                          <span className="font-mono font-bold text-brand shrink-0">{c.composite_correlation_score.toFixed(0)}/100</span>
                        </div>
                        <div className="text-text-secondary text-[11px]">{c.primary_link_reason}</div>
                        <div className="flex flex-wrap gap-1.5">
                          {c.signals.map((s, sIdx) => (
                            <span key={sIdx} className="px-2 py-0.5 rounded-md bg-workspace-card border border-workspace-border text-[10px] font-mono text-text-muted">
                              {s.signal_type} ({s.confidence.toFixed(0)}%)
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyNote>No correlated emails found matching this threat profile.</EmptyNote>
                )}
              </Section>

              {/* Similarity Links */}
              <Section className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-text-primary">Similarity Links ({similarityData.length})</h3>
                  <span className="text-xs text-text-muted">Structural and content matches</span>
                </div>
                {similarityData.length > 0 ? (
                  <div className="space-y-2.5">
                    {similarityData.map((link) => (
                      <div key={link.id} className="p-3.5 rounded-xl bg-workspace border border-workspace-border flex items-center justify-between text-xs">
                        <div>
                          <div className="font-semibold text-text-primary">Related Email: {link.related_email_id}</div>
                          <div className="text-text-muted mt-0.5">{link.similarity_type}</div>
                        </div>
                        <span className="font-mono font-bold text-brand">{(link.similarity_score * 100).toFixed(0)}%</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyNote>No content or structural similarity links recorded.</EmptyNote>
                )}
              </Section>

              {/* Investigation Graph Link Card */}
              {graphData && graphData.total_nodes > 0 && (
                <Section className="space-y-4 border-brand/20">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-brand-soft text-brand flex items-center justify-center shrink-0">
                        <Network className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-text-primary">Entity Investigation Graph</h3>
                        <p className="text-xs text-text-muted">{graphData.total_nodes} connected nodes · {graphData.total_edges} relational edges</p>
                      </div>
                    </div>
                    {onExploreGraph && (
                      <button
                        onClick={() => onExploreGraph(selectedEmailId)}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors shrink-0"
                      >
                        Explore Visual Graph
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-xs">
                    {Object.entries(graphData.statistics || {}).map(([type, count]) => (
                      <div key={type} className="p-3 rounded-xl bg-workspace border border-workspace-border">
                        <div className="text-[10px] text-text-muted font-semibold">{type}</div>
                        <div className="text-base font-bold text-brand mt-0.5">{count}</div>
                      </div>
                    ))}
                  </div>
                </Section>
              )}
            </div>
          )}
        </div>
      )}

      {/* Slide-Over Investigation Assistant Drawer (RAG Case Q&A) */}
      <AIAssistantDrawer
        emailId={selectedEmailId}
        emailSubject={emailDetails?.subject || undefined}
        isOpen={isAssistantOpen}
        onClose={() => setIsAssistantOpen(false)}
      />
    </div>
  );
};

export default AnalysisWorkspace;
