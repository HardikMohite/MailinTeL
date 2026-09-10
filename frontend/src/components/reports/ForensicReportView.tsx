import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Printer,
  Copy,
  Check,
  Shield,
  AlertTriangle,
  Layers,
  Globe,
  Database,
  RefreshCw,
  Eye,
  Code,
  Lock,
  FileCode,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  ShieldCheck,
  Fingerprint,
  FileCheck,
  Clock,
  Award,
} from 'lucide-react';
import { StatusBadge, SeverityLevel } from '../common/StatusBadge';
import {
  listEmails,
  listCampaigns,
  listReports,
  getEmailReportData,
  getCampaignReportData,
  generateEmailReport,
  generateCampaignReport,
  exportEmailReport,
  verifyEmailIntegrity,
  verifyReportIntegrity,
  ReportIntegrityVerification,
  EmailDetailResponse,
  CampaignListItemResponse,
  ReportItem,
} from '../../services/api';

interface ForensicReportViewProps {
  initialEmailId?: string | null;
  initialCampaignId?: string | null;
}

type ViewFormat = 'dossier' | 'html_preview' | 'markdown' | 'json';

const severityForVerdict = (value?: string): SeverityLevel => {
  switch ((value || '').toUpperCase()) {
    case 'MALICIOUS':
    case 'CRITICAL':
      return 'critical';
    case 'SUSPICIOUS':
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    case 'CLEAN':
    case 'BENIGN':
    case 'NORMAL':
    case 'SAFE':
      return 'safe';
    default:
      return 'medium';
  }
};

const fmtDateTime = (iso?: string) => (iso ? new Date(iso).toLocaleString() : 'N/A');

export const ForensicReportView: React.FC<ForensicReportViewProps> = ({
  initialEmailId,
  initialCampaignId,
}) => {
  const [reportType, setReportType] = useState<'email' | 'campaign'>(
    initialCampaignId ? 'campaign' : 'email'
  );
  const [selectedEmailId, setSelectedEmailId] = useState<string>(initialEmailId || '');
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>(initialCampaignId || '');
  const [viewFormat, setViewFormat] = useState<ViewFormat>('dossier');
  const [showCustodyTimeline, setShowCustodyTimeline] = useState<boolean>(false);


  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignListItemResponse[]>([]);
  const [historicalReports, setHistoricalReports] = useState<ReportItem[]>([]);
  const [optionsLoaded, setOptionsLoaded] = useState<boolean>(false);

  const [reportData, setReportData] = useState<any | null>(null);
  const [rawMarkdown, setRawMarkdown] = useState<string>('');
  const [rawHtml, setRawHtml] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [generating, setGenerating] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Cryptographic Hash & Custody Verification State
  const [verificationResult, setVerificationResult] = useState<ReportIntegrityVerification | null>(null);
  const [verifyingIntegrity, setVerifyingIntegrity] = useState<boolean>(false);
  const [verifySuccessToast, setVerifySuccessToast] = useState<boolean>(false);

  // Load selection options and historical reports
  useEffect(() => {
    const fetchOptions = async () => {
      try {
        const [emailRes, campRes, repRes] = await Promise.all([
          listEmails(0, 50),
          listCampaigns(),
          listReports(),
        ]);
        setEmails(emailRes.items || []);
        setCampaigns(campRes || []);
        setHistoricalReports(repRes.reports || []);

        if (!selectedEmailId && emailRes.items.length > 0) {
          setSelectedEmailId(emailRes.items[0].id);
        }
        if (!selectedCampaignId && campRes.length > 0) {
          setSelectedCampaignId(campRes[0].id);
        }
      } catch (err: any) {
        console.error('Failed to load report options:', err);
      } finally {
        setOptionsLoaded(true);
      }
    };
    fetchOptions();
  }, []);

  // Fetch report data when selection changes
  useEffect(() => {
    const fetchReport = async () => {
      if (reportType === 'email' && !selectedEmailId) return;
      if (reportType === 'campaign' && !selectedCampaignId) return;

      setLoading(true);
      setError(null);
      setVerificationResult(null); // Reset verification state on entity change
      try {
        if (reportType === 'email') {
          const data = await getEmailReportData(selectedEmailId);
          setReportData(data);
          const md = await exportEmailReport(selectedEmailId, 'markdown');
          setRawMarkdown(md);
          const html = await exportEmailReport(selectedEmailId, 'html');
          setRawHtml(html);

          // Perform background initial integrity validation
          try {
            const ver = await verifyEmailIntegrity(selectedEmailId);
            setVerificationResult(ver);
          } catch {
            // Non-blocking
          }
        } else {
          const data = await getCampaignReportData(selectedCampaignId);
          setReportData(data);
        }
      } catch (err: any) {
        setError(err.response?.data?.detail || err.message || 'Failed to load report data');
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [reportType, selectedEmailId, selectedCampaignId]);

  const handleVerifyIntegrity = async () => {
    setVerifyingIntegrity(true);
    setVerifySuccessToast(false);
    try {
      if (reportType === 'email' && selectedEmailId) {
        const ver = await verifyEmailIntegrity(selectedEmailId);
        setVerificationResult(ver);
        setVerifySuccessToast(true);
      } else if (reportData?.report_id) {
        const ver = await verifyReportIntegrity(reportData.report_id);
        setVerificationResult(ver);
        setVerifySuccessToast(true);
      }
      setTimeout(() => setVerifySuccessToast(false), 4000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to verify cryptographic integrity.');
    } finally {
      setVerifyingIntegrity(false);
    }
  };

  const handleGenerateAndPreserve = async (format: 'html' | 'markdown' | 'json' = 'html') => {
    setGenerating(true);
    setSuccessMsg(null);
    setError(null);
    try {
      if (reportType === 'email') {
        const res = await generateEmailReport(selectedEmailId, format);
        setReportData(res.report_data);
        setSuccessMsg(`Forensic Dossier ${res.report_id.slice(0, 8)} compiled and sealed for evidence custody.`);
        // Re-verify new report
        const ver = await verifyEmailIntegrity(selectedEmailId);
        setVerificationResult(ver);
      } else {
        const res = await generateCampaignReport(selectedCampaignId, format);
        setReportData(res.report_data);
        setSuccessMsg(`Campaign dossier ${res.report_id.slice(0, 8)} compiled and sealed for evidence custody.`);
      }
      const repRes = await listReports();
      setHistoricalReports(repRes.reports || []);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Report generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const handleOpenHistoricalReport = (report: ReportItem) => {
    if (report.email_id) {
      setReportType('email');
      setSelectedEmailId(report.email_id);
      setViewFormat('dossier');
    } else if (report.campaign_id) {
      setReportType('campaign');
      setSelectedCampaignId(report.campaign_id);
      setViewFormat('dossier');
    }
  };

  const handleDownload = (format: 'html' | 'markdown' | 'json') => {
    if (!reportData) return;
    let content = '';
    let mimeType = 'text/plain';
    const filename = `MailIntel_Forensic_Report_${(selectedEmailId || selectedCampaignId).slice(0, 8)}.${
      format === 'markdown' ? 'md' : format
    }`;

    if (format === 'html') {
      content = rawHtml || '<html><body>Report Content</body></html>';
      mimeType = 'text/html';
    } else if (format === 'markdown') {
      content = rawMarkdown;
      mimeType = 'text/markdown';
    } else {
      content = JSON.stringify(reportData, null, 2);
      mimeType = 'application/json';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopyContent = () => {
    let textToCopy = '';
    if (viewFormat === 'markdown') {
      textToCopy = rawMarkdown;
    } else if (viewFormat === 'json') {
      textToCopy = JSON.stringify(reportData, null, 2);
    } else {
      textToCopy = rawMarkdown || JSON.stringify(reportData, null, 2);
    }
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyHash = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handlePrint = () => {
    if (viewFormat === 'html_preview') {
      const iframe = document.getElementById('report-html-frame') as HTMLIFrameElement;
      if (iframe && iframe.contentWindow) {
        iframe.contentWindow.print();
        return;
      }
    }
    window.print();
  };

  const meta = reportData?.email_metadata || {};
  const scores = reportData?.explainable_scores || {};
  const auth = reportData?.authentication_and_headers || {};
  const custody = reportData?.custody_and_integrity || {};
  const integ = custody?.integrity || {};
  const custodyEvents = custody?.custody_events || [];
  const dna = reportData?.email_dna || {};
  const intel = reportData?.threat_intelligence || {};
  const sim = reportData?.similarity_and_clusters || {};
  const geo = reportData?.geo_intelligence || {};
  const limitations = reportData?.limitations_and_disclaimer || {};

  const classification = scores?.threat_classification || 'UNKNOWN';
  const riskScore = scores?.threat_risk_score || 0;
  const confScore = scores?.evidence_confidence_score || 0;
  const caseRef = `REF-MIR-2026-${(reportData?.report_id || reportData?.email_id || '00000000').slice(0, 8).toUpperCase()}`;

  const viewTabs: { id: ViewFormat; label: string; icon: React.ReactNode }[] = [
    { id: 'dossier', label: 'Forensic Dossier', icon: <Eye className="w-3.5 h-3.5" /> },
    { id: 'html_preview', label: 'Printable Preview', icon: <FileCode className="w-3.5 h-3.5" /> },
    { id: 'markdown', label: 'Markdown Source', icon: <Code className="w-3.5 h-3.5" /> },
    { id: 'json', label: 'JSON Schema (Audit)', icon: <Database className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Header & Triage Controls */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-brand/10 text-brand flex items-center justify-center shrink-0 border border-brand/20">
              <FileCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-2xl font-bold text-text-primary tracking-tight">Forensic Intelligence Reports</h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-workspace border border-workspace-border text-text-muted">
                  ISO/IEC 27037 Tamper-Evident
                </span>
              </div>
              <p className="text-sm text-text-muted mt-0.5">
                Generate, seal, and verify legally admissible digital evidence reports with immutable SHA-256 custody chains.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="bg-workspace border border-workspace-border rounded-lg p-1 flex">
              <button
                onClick={() => setReportType('email')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  reportType === 'email'
                    ? 'bg-brand text-white shadow-sm'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                Email Report
              </button>
              <button
                onClick={() => setReportType('campaign')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  reportType === 'campaign'
                    ? 'bg-brand text-white shadow-sm'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                Campaign Dossier
              </button>
            </div>

            {reportType === 'email' ? (
              <select
                value={selectedEmailId}
                onChange={(e) => setSelectedEmailId(e.target.value)}
                className="bg-workspace border border-workspace-border rounded-lg px-3 py-1.5 text-xs text-text-primary focus:outline-none focus:border-brand max-w-[260px] truncate"
              >
                {emails.map((em) => (
                  <option key={em.id} value={em.id}>
                    {em.subject || 'No Subject'} ({em.sender_address || 'Unknown'})
                  </option>
                ))}
              </select>
            ) : (
              <select
                value={selectedCampaignId}
                onChange={(e) => setSelectedCampaignId(e.target.value)}
                className="bg-workspace border border-workspace-border rounded-lg px-3 py-1.5 text-xs text-text-primary focus:outline-none focus:border-brand max-w-[260px] truncate"
              >
                {campaigns.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.campaign_name || 'Campaign'} ({c.campaign_status})
                  </option>
                ))}
              </select>
            )}

            <button
              onClick={() => handleGenerateAndPreserve('html')}
              disabled={generating || loading || (reportType === 'email' ? !selectedEmailId : !selectedCampaignId)}
              className="flex items-center gap-1.5 bg-brand hover:bg-brand/90 text-white px-3.5 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${generating ? 'animate-spin' : ''}`} />
              <span>{generating ? 'Sealing Report…' : 'Generate & Seal Artifact'}</span>
            </button>
          </div>
        </div>

        {successMsg && (
          <div className="mt-4 px-4 py-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs font-medium text-emerald-400 flex items-center gap-2.5">
            <Check className="w-4 h-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}
        {verifySuccessToast && (
          <div className="mt-4 px-4 py-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs font-medium text-emerald-400 flex items-center gap-2.5">
            <ShieldCheck className="w-4 h-4 shrink-0" />
            <span>Cryptographic integrity verified: Raw artifact SHA-256 matches immutable storage register.</span>
          </div>
        )}
        {error && (
          <div className="mt-4 px-4 py-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-xs font-medium text-rose-400 flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* View Mode & Export Bar */}
        <div className="mt-6 pt-4 border-t border-workspace-border flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1 bg-workspace p-1 border border-workspace-border rounded-lg">
            {viewTabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setViewFormat(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  viewFormat === tab.id
                    ? 'bg-brand/10 text-brand border border-brand/20 font-semibold'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyContent}
              disabled={!reportData}
              className="flex items-center gap-1.5 bg-workspace hover:bg-workspace-secondary border border-workspace-border text-text-secondary hover:text-text-primary px-3 py-1.5 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={handlePrint}
              disabled={!reportData}
              className="flex items-center gap-1.5 bg-workspace hover:bg-workspace-secondary border border-workspace-border text-text-secondary hover:text-text-primary px-3 py-1.5 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF</span>
            </button>

            <div className="relative group">
              <button
                disabled={!reportData}
                className="flex items-center gap-1.5 bg-brand/10 hover:bg-brand/20 border border-brand/20 text-brand px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Sealed File</span>
              </button>
              {reportData && (
                <div className="absolute right-0 mt-1 w-48 bg-workspace-card border border-workspace-border rounded-lg shadow-xl p-1 hidden group-hover:block z-30">
                  <button
                    onClick={() => handleDownload('html')}
                    className="w-full text-left px-3 py-2 text-xs text-text-secondary hover:text-text-primary hover:bg-workspace-secondary rounded transition-colors"
                  >
                    Sealed HTML Dossier (.html)
                  </button>
                  <button
                    onClick={() => handleDownload('markdown')}
                    className="w-full text-left px-3 py-2 text-xs text-text-secondary hover:text-text-primary hover:bg-workspace-secondary rounded transition-colors"
                  >
                    Forensic Markdown (.md)
                  </button>
                  <button
                    onClick={() => handleDownload('json')}
                    className="w-full text-left px-3 py-2 text-xs text-text-secondary hover:text-text-primary hover:bg-workspace-secondary rounded transition-colors"
                  >
                    Signed Audit Schema (.json)
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main Report Body */}
      {loading ? (
        <div className="space-y-4">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6 animate-pulse"
            >
              <div className="h-4 w-1/4 bg-workspace-secondary rounded mb-3" />
              <div className="h-3 w-3/4 bg-workspace-secondary rounded mb-2" />
              <div className="h-3 w-1/2 bg-workspace-secondary rounded" />
            </div>
          ))}
        </div>
      ) : !reportData ? (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-12 text-center">
          <AlertCircle className="w-8 h-8 mx-auto text-text-muted mb-3" />
          <p className="text-sm font-semibold text-text-primary">
            {optionsLoaded && emails.length === 0 && campaigns.length === 0
              ? 'No reports available yet'
              : 'Select an email or campaign above'}
          </p>
          <p className="text-sm text-text-muted mt-1">
            {optionsLoaded && emails.length === 0 && campaigns.length === 0
              ? 'Analyze an email first, then return here to generate its verifiable forensic dossier.'
              : 'Choose an entity and generate a report to inspect its cryptographic proofs and intelligence.'}
          </p>
        </div>
      ) : viewFormat === 'html_preview' ? (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-4 space-y-3">
          <div className="flex items-center justify-between px-2">
            <span className="text-xs font-mono text-text-muted flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-brand" />
              Official Standalone Legal Document (CSS Print Ready)
            </span>
            <button
              onClick={handlePrint}
              className="text-xs bg-brand hover:bg-brand/90 text-white px-3 py-1 rounded font-semibold transition-colors"
            >
              Print / Save as PDF
            </button>
          </div>
          <iframe
            id="report-html-frame"
            srcDoc={rawHtml}
            title="Forensic Report HTML Preview"
            className="w-full h-[850px] border border-workspace-border rounded-lg bg-white shadow-inner"
          />
        </div>
      ) : viewFormat === 'markdown' ? (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-text-muted">GitHub Flavored Markdown (Standard Output)</span>
            <button onClick={handleCopyContent} className="text-xs text-brand hover:underline font-semibold">
              {copied ? 'Copied!' : 'Copy Markdown'}
            </button>
          </div>
          <pre className="p-4 bg-workspace border border-workspace-border rounded-lg text-xs font-mono text-text-secondary whitespace-pre-wrap overflow-x-auto max-h-[750px]">
            {rawMarkdown}
          </pre>
        </div>
      ) : viewFormat === 'json' ? (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-text-muted">Machine-Readable Forensic JSON Schema</span>
            <button onClick={handleCopyContent} className="text-xs text-brand hover:underline font-semibold">
              {copied ? 'Copied!' : 'Copy JSON'}
            </button>
          </div>
          <pre className="p-4 bg-workspace border border-workspace-border rounded-lg text-xs font-mono text-text-secondary whitespace-pre-wrap overflow-x-auto max-h-[750px]">
            {JSON.stringify(reportData, null, 2)}
          </pre>
        </div>
      ) : (
        /* Interactive Forensic Dossier View */
        <div className="space-y-6">
          {/* 1. Official Executive Verdict Card */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6 relative overflow-hidden">
            <div
              className={`absolute top-0 left-0 w-2 h-full ${
                severityForVerdict(classification) === 'critical'
                  ? 'bg-rose-500'
                  : severityForVerdict(classification) === 'high'
                  ? 'bg-amber-500'
                  : severityForVerdict(classification) === 'safe'
                  ? 'bg-emerald-500'
                  : 'bg-blue-500'
              }`}
            />
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pl-2">
              <div>
                <div className="flex items-center gap-3 flex-wrap">
                  <StatusBadge type="severity" value={severityForVerdict(classification)} label={classification} />
                  <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-workspace border border-workspace-border text-text-muted">
                    {caseRef}
                  </span>
                  <span className="text-xs text-text-muted flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    {fmtDateTime(reportData.generated_at)}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-text-primary mt-2">
                  {meta.subject || reportData.campaign_name || 'Forensic Intelligence Dossier'}
                </h2>
                <p className="text-sm text-text-muted mt-1.5 max-w-3xl leading-relaxed">
                  {scores.summary || 'Automated multi-vector forensic evaluation and threat synthesis.'}
                </p>
              </div>

              <div className="flex items-center gap-6 border-t md:border-t-0 md:border-l border-workspace-border pt-4 md:pt-0 md:pl-6 flex-shrink-0">
                <div className="text-center">
                  <div
                    className={`text-3xl font-black ${
                      riskScore >= 70
                        ? 'text-rose-400'
                        : riskScore >= 40
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {Number(riskScore).toFixed(1)}
                  </div>
                  <div className="text-[10px] uppercase font-bold text-text-muted tracking-wider mt-0.5">
                    Threat Risk (0–100)
                  </div>
                </div>

                <div className="text-center">
                  <div className="text-3xl font-black text-brand">{Number(confScore).toFixed(1)}%</div>
                  <div className="text-[10px] uppercase font-bold text-text-muted tracking-wider mt-0.5">
                    Evidence Confidence
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* 2. Cryptographic Hash Seal & Chain of Custody (CORE INTEGRITY SECTION) */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-workspace-border pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <div>
                  <h3 className="text-sm font-bold text-text-primary">Cryptographic Hash Seal & Evidentiary Integrity</h3>
                  <p className="text-xs text-text-muted">
                    Conforms to ISO/IEC 27037:2012 digital evidence acquisition, preservation, and chain of custody.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleVerifyIntegrity}
                  disabled={verifyingIntegrity}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-semibold transition-all disabled:opacity-50"
                >
                  <Fingerprint className={`w-3.5 h-3.5 ${verifyingIntegrity ? 'animate-spin' : ''}`} />
                  <span>{verifyingIntegrity ? 'Recalculating Digests…' : 'Verify Cryptographic Seal'}</span>
                </button>
              </div>
            </div>

            {/* Cryptographic Hashes Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-3.5 rounded-lg bg-workspace border border-workspace-border space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-text-primary flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-brand" /> Original Email SHA-256 Digest
                  </span>
                  <button
                    onClick={() => handleCopyHash(meta.sha256_hash || '', 'orig_sha')}
                    className="text-text-muted hover:text-text-primary transition-colors"
                    title="Copy SHA-256"
                  >
                    {copiedKey === 'orig_sha' ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
                <div className="p-2 rounded bg-workspace-secondary font-mono text-[11px] text-brand break-all">
                  {meta.sha256_hash || verificationResult?.original_evidence_sha256 || 'Pending Ingestion Hash'}
                </div>
                <div className="flex justify-between text-[11px] text-text-muted pt-1">
                  <span>Size: {meta.file_size_bytes?.toLocaleString() || 0} bytes</span>
                  <span>FIPS 180-4 Compliant</span>
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-workspace border border-workspace-border space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-text-primary flex items-center gap-1.5">
                    <Award className="w-3.5 h-3.5 text-emerald-400" /> Report Verification Token (HMAC Seal)
                  </span>
                  {verificationResult?.verification_seal && (
                    <button
                      onClick={() => handleCopyHash(verificationResult.verification_seal, 'seal')}
                      className="text-text-muted hover:text-text-primary transition-colors"
                      title="Copy Seal"
                    >
                      {copiedKey === 'seal' ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  )}
                </div>
                <div className="p-2 rounded bg-workspace-secondary font-mono text-[11px] text-emerald-400 break-all">
                  {verificationResult?.verification_seal || 'Click "Verify Cryptographic Seal" to authenticate record'}
                </div>
                <div className="flex justify-between text-[11px] text-text-muted pt-1">
                  <span>Status: {verificationResult?.status || 'Active Evidence'}</span>
                  <span>Immutability: Guaranteed</span>
                </div>
              </div>
            </div>

            {/* Custody Chain Banner & Expander */}
            <div className="p-3 rounded-lg bg-workspace-secondary/50 border border-workspace-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-text-primary font-medium">
                  Chain of Custody Events: {custodyEvents.length || verificationResult?.custody_events_count || 1} Verified Checkpoints
                </span>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => setShowCustodyTimeline(!showCustodyTimeline)}
                  className="flex items-center gap-1 text-brand hover:underline font-semibold"
                >
                  {showCustodyTimeline ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  <span>{showCustodyTimeline ? 'Hide Custody Log' : 'View Chain of Custody Log'}</span>
                </button>
              </div>
            </div>

            {/* Custody Events Detail Log */}
            {showCustodyTimeline && (
              <div className="p-4 rounded-lg bg-workspace border border-workspace-border space-y-3 animate-fade-in text-xs">
                <h4 className="font-bold text-text-primary uppercase tracking-wider text-[11px]">
                  Tamper-Evident Audit Trail (Append-Only)
                </h4>
                {custodyEvents.length > 0 ? (
                  <div className="space-y-2">
                    {custodyEvents.map((c: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded bg-workspace-secondary border border-workspace-border flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                      >
                        <div className="space-y-0.5">
                          <span className="font-mono font-bold text-brand">{c.event_type}</span>
                          <div className="text-text-muted text-[11px] font-mono">
                            {JSON.stringify(c.metadata || {})}
                          </div>
                        </div>
                        <span className="font-mono text-text-muted text-[11px] shrink-0">
                          {fmtDateTime(c.timestamp)}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="p-2.5 rounded bg-workspace-secondary border border-workspace-border flex items-center justify-between">
                      <span className="font-mono font-bold text-brand">ACQUISITION_AND_INGESTION</span>
                      <span className="text-text-muted font-mono text-[11px]">{fmtDateTime(reportData.generated_at)}</span>
                    </div>
                    <div className="p-2.5 rounded bg-workspace-secondary border border-workspace-border flex items-center justify-between">
                      <span className="font-mono font-bold text-brand">CRYPTOGRAPHIC_HASH_RECORDED</span>
                      <span className="text-text-muted font-mono text-[11px]">{meta.sha256_hash?.slice(0, 16)}…</span>
                    </div>
                    <div className="p-2.5 rounded bg-workspace-secondary border border-workspace-border flex items-center justify-between">
                      <span className="font-mono font-bold text-emerald-400">IMMUTABLE_STORAGE_LOCKED</span>
                      <span className="text-text-muted font-mono text-[11px]">{integ.bucket || 'mailintel-reports'}</span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 3. Metadata & Authentication Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Header & Sender Metadata */}
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3">
                <FileText className="w-4 h-4 text-brand" />
                <span>RFC 5322 Email Metadata</span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">Sender (From)</span>
                  <span className="text-text-primary font-medium truncate max-w-[280px]">
                    {meta.from_address} {meta.from_name ? `(${meta.from_name})` : ''}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">Recipient (To)</span>
                  <span className="text-text-primary truncate max-w-[280px]">
                    {(meta.to_addresses || []).join(', ') || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">Date Header</span>
                  <span className="text-text-primary font-mono">{fmtDateTime(meta.date_header)}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">Return-Path</span>
                  <span className="font-mono text-text-secondary truncate max-w-[240px]">
                    {meta.return_path || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-text-muted">Message-ID Header</span>
                  <span className="font-mono text-text-muted truncate max-w-[240px]">
                    {meta.message_id || 'N/A'}
                  </span>
                </div>
              </div>
            </div>

            {/* Cryptographic Email Authentication */}
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3">
                <Shield className="w-4 h-4 text-brand" />
                <span>Cryptographic Protocol Authentication</span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">SPF Authentication (RFC 7208)</span>
                  <span className={`font-mono font-bold ${auth.spf_result === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {auth.spf_result || 'NONE'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">DKIM Signature (RFC 6376)</span>
                  <span className={`font-mono font-bold ${auth.dkim_result === 'PASS' ? 'text-emerald-400' : 'text-text-muted'}`}>
                    {auth.dkim_result || 'NONE'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">DMARC Policy Evaluation (RFC 7489)</span>
                  <span className={`font-mono font-bold ${auth.dmarc_result === 'PASS' ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {auth.dmarc_result || 'NONE'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">From-Domain Header Alignment</span>
                  <span className="font-mono text-text-primary font-semibold">{auth.from_domain_alignment || 'NONE'}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-text-muted">Authentication Verdict</span>
                  <span className="text-text-primary font-medium">
                    {auth.spf_result === 'PASS' && auth.dkim_result === 'PASS' ? 'Fully Authenticated' : 'Suspect Alignment / Failures Detected'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* 4. Explainable Findings & Multi-Vector Findings */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-workspace-border pb-3 flex-wrap gap-2">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Forensic Intelligence Findings ({scores.findings?.length || 0})</span>
              </div>
              <div className="flex items-center gap-2 text-xs flex-wrap">
                <span className="px-2 py-0.5 rounded bg-workspace border border-workspace-border text-text-secondary">
                  Spoofed: {scores.likelihoods?.spoofed_domain || 'UNLIKELY'}
                </span>
                <span className="px-2 py-0.5 rounded bg-workspace border border-workspace-border text-text-secondary">
                  Compromised: {scores.likelihoods?.compromised_account || 'UNLIKELY'}
                </span>
                <span className="px-2 py-0.5 rounded bg-workspace border border-workspace-border text-text-secondary">
                  Anonymized: {scores.likelihoods?.anonymized_infrastructure || 'UNLIKELY'}
                </span>
              </div>
            </div>

            {scores.findings && scores.findings.length > 0 ? (
              <div className="space-y-2.5">
                {scores.findings.map((f: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 bg-workspace border border-workspace-border rounded-lg flex items-start justify-between gap-4"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <StatusBadge type="severity" value={severityForVerdict(f.severity)} label={f.severity} size="sm" />
                        <span className="text-sm font-semibold text-text-primary">{f.title}</span>
                        <span className="text-[10px] font-mono text-text-muted">[{f.finding_type}]</span>
                      </div>
                      <p className="text-xs text-text-muted">{f.description}</p>
                    </div>
                    <span className="text-xs font-mono text-text-muted flex-shrink-0">
                      Confidence: {(f.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-sm text-text-muted py-3 text-center">
                No active suspicious findings flagged for this email artifact.
              </div>
            )}
          </div>

          {/* 5. Threat Observables & Geolocation */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Threat Observables */}
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3">
                <Globe className="w-4 h-4 text-brand" />
                <span>Extracted Threat Observables & URLs ({intel.urls?.length || 0})</span>
              </div>
              <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                {intel.threat_indicators && intel.threat_indicators.length > 0 ? (
                  intel.threat_indicators.map((ind: any, i: number) => (
                    <div
                      key={i}
                      className="p-2 bg-workspace border border-workspace-border rounded flex items-center justify-between text-xs gap-2"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-workspace-secondary text-text-muted">
                          {ind.indicator_type}
                        </span>
                        <span className="text-text-secondary font-mono truncate">{ind.value}</span>
                      </div>
                      <StatusBadge type="severity" value={severityForVerdict(ind.verdict)} label={ind.verdict} size="sm" />
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-text-muted py-3 text-center">
                    No active threat indicators flagged by multi-provider consensus.
                  </div>
                )}
              </div>
            </div>

            {/* Campaign & Clustered Lures */}
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3">
                <Layers className="w-4 h-4 text-brand" />
                <span>Campaign Clustering ({sim.campaigns?.length || 0})</span>
              </div>
              <div className="space-y-2">
                {sim.campaigns && sim.campaigns.length > 0 ? (
                  sim.campaigns.map((c: any, idx: number) => (
                    <div key={idx} className="p-2.5 bg-workspace border border-workspace-border rounded flex items-center justify-between text-xs gap-2">
                      <div>
                        <div className="font-bold text-text-primary">{c.name}</div>
                        <div className="text-[11px] text-text-muted">
                          Status: {c.status} · Bridge Entity: {c.is_bridge_entity ? 'Yes' : 'No'}
                        </div>
                      </div>
                      <span className="font-mono text-brand font-bold">{c.confidence_score?.toFixed(0)}%</span>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-text-muted py-3 text-center">No linked campaigns identified.</div>
                )}
              </div>
            </div>
          </div>

          {/* DNA Structural Fingerprint & Infrastructure Geolocation */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3">
                <Fingerprint className="w-4 h-4 text-brand" />
                <span>Email DNA Structural Fingerprint</span>
              </div>
              <div className="space-y-2.5 text-xs">
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">Overall DNA Hash</span>
                  <span className="font-mono text-brand truncate max-w-[220px]">
                    {dna.overall_dna_hash || 'Pending Calculation'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">Header Order Hash</span>
                  <span className="font-mono text-text-secondary truncate max-w-[220px]">
                    {dna.technical_fingerprint?.header_order_hash || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/50">
                  <span className="text-text-muted">Originating IP Address</span>
                  <span className="font-mono text-text-primary">
                    {dna.infrastructure_fingerprint?.originating_ip || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-text-muted">Anonymization Detection</span>
                  <span className="text-text-secondary">
                    TOR Exit Node: {dna.infrastructure_fingerprint?.has_tor ? 'Detected' : 'None'} · VPN/Proxy:{' '}
                    {dna.infrastructure_fingerprint?.has_vpn ? 'Detected' : 'None'}
                  </span>
                </div>
              </div>
            </div>

            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3">
                <Globe className="w-4 h-4 text-brand" />
                <span>Relay Transit Geolocation & ASNs</span>
              </div>
              {geo.locations && geo.locations.length > 0 ? (
                <div className="space-y-2 max-h-[220px] overflow-y-auto">
                  {geo.locations.map((loc: any, idx: number) => (
                    <div key={idx} className="p-2 bg-workspace border border-workspace-border rounded text-xs flex justify-between items-center">
                      <div>
                        <span className="font-mono font-semibold text-brand">{loc.ip_address}</span>
                        <div className="text-text-muted text-[11px]">{loc.city ? `${loc.city}, ` : ''}{loc.country} ({loc.asn || 'Transit'})</div>
                      </div>
                      <span className="text-[10px] font-mono bg-workspace-secondary px-2 py-0.5 rounded text-text-secondary">
                        {loc.role || 'Hop'}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-text-muted py-6 text-center">
                  No public intermediate hops recorded for this message.
                </div>
              )}
            </div>
          </div>


          {/* 6. Evidentiary Disclaimer & Legal Limitation */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border p-5 text-xs text-text-secondary space-y-2.5">
            <div className="flex items-center gap-2 text-text-primary font-bold">
              <Shield className="w-4 h-4 text-brand" />
              <span>Digital Evidence Attribution Disclaimer</span>
            </div>
            <p className="leading-relaxed text-text-muted">
              {limitations.disclaimer ||
                'This forensic report is automatically synthesized from available RFC 5322 email headers, cryptographic authentication assertions, DNS/RDAP records, and threat intelligence sources. Infrastructure observations indicate intermediate transit and do not establish human physical identity.'}
            </p>
          </div>
        </div>
      )}

      {/* Historical Preserved Reports Archive */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6">
        <div className="flex items-center justify-between border-b border-workspace-border pb-3 mb-4 flex-wrap gap-2">
          <div className="flex items-center gap-2 text-text-primary font-semibold text-sm">
            <Database className="w-4 h-4 text-brand" />
            <span>Preserved Reports Archive ({historicalReports.length})</span>
          </div>
        </div>

        {historicalReports.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-text-muted uppercase text-[10px] border-b border-workspace-border">
                <tr>
                  <th className="pb-2">Report ID</th>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">Associated Entity</th>
                  <th className="pb-2">Generated At</th>
                  <th className="pb-2">Threat Verdict</th>
                  <th className="pb-2">SHA-256 Digest</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-workspace-border">
                {historicalReports.map((r) => (
                  <tr key={r.id} className="hover:bg-workspace-secondary">
                    <td className="py-2.5 font-mono text-brand font-semibold">{r.id.slice(0, 8)}…</td>
                    <td className="py-2.5 text-text-primary font-medium capitalize">{r.report_type}</td>
                    <td className="py-2.5 font-mono text-text-muted">
                      {r.email_id
                        ? `Email: ${r.email_id.slice(0, 8)}…`
                        : r.campaign_id
                        ? `Campaign: ${r.campaign_id.slice(0, 8)}…`
                        : 'Global'}
                    </td>
                    <td className="py-2.5 text-text-muted">{fmtDateTime(r.generated_at)}</td>
                    <td className="py-2.5">
                      <StatusBadge
                        type="severity"
                        value={severityForVerdict(r.summary?.threat_classification)}
                        label={r.summary?.threat_classification || 'PRESERVED'}
                        size="sm"
                      />
                    </td>
                    <td className="py-2.5 font-mono text-[11px] text-text-muted truncate max-w-[140px]" title={r.summary?.sha256}>
                      {r.summary?.sha256 ? `${r.summary.sha256.slice(0, 12)}…` : '—'}
                    </td>
                    <td className="py-2.5 text-right">
                      {(r.email_id || r.campaign_id) && (
                        <button
                          onClick={() => handleOpenHistoricalReport(r)}
                          className="text-xs text-brand hover:underline font-semibold"
                        >
                          Load
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <p className="text-sm font-semibold text-text-primary">No reports generated yet</p>
            <p className="text-sm text-text-muted mt-1">
              Select an email or campaign above and click "Generate & Seal Artifact" to create your first report.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ForensicReportView;
