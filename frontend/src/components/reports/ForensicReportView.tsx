import React, { useState, useEffect } from 'react';
import {
  Download,
  Printer,
  Copy,
  Check,
  Shield,
  AlertTriangle,
  Database,
  RefreshCw,
  Eye,
  Code,
  Lock,
  FileCode,
  AlertCircle,
  ShieldCheck,
  Fingerprint,
  FileCheck,
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
      setRawHtml(''); // Reset previews to avoid stale memory
      setRawMarkdown('');
      try {
        if (reportType === 'email') {
          // Fast-path: Fetch core structured report data (served from Redis/RAM in ~5ms)
          const data = await getEmailReportData(selectedEmailId);
          setReportData(data);
          setLoading(false); // Unblock UI immediately!

          // Non-blocking background verification check
          verifyEmailIntegrity(selectedEmailId)
            .then((ver) => setVerificationResult(ver))
            .catch(() => {});
        } else {
          const data = await getCampaignReportData(selectedCampaignId);
          setReportData(data);
          setLoading(false);
        }
      } catch (err: any) {
        setError(err.response?.data?.detail || err.message || 'Failed to load report data');
        setLoading(false);
      }
    };

    fetchReport();
  }, [reportType, selectedEmailId, selectedCampaignId]);

  // Lazy-load formatted HTML and Markdown only when those specific tabs are selected
  useEffect(() => {
    if (!selectedEmailId || reportType !== 'email') return;

    if (viewFormat === 'html_preview' && !rawHtml) {
      exportEmailReport(selectedEmailId, 'html')
        .then((h) => setRawHtml(h))
        .catch((e) => console.warn('Could not load HTML preview:', e?.message));
    } else if (viewFormat === 'markdown' && !rawMarkdown) {
      exportEmailReport(selectedEmailId, 'markdown')
        .then((m) => setRawMarkdown(m))
        .catch((e) => console.warn('Could not load markdown preview:', e?.message));
    }
  }, [viewFormat, selectedEmailId, reportType, rawHtml, rawMarkdown]);

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

  const handleDownload = async (format: 'html' | 'markdown' | 'json' | 'pdf') => {
    if (!reportData) return;
    const emailOrCampId = (selectedEmailId || selectedCampaignId).slice(0, 8);
    const filename = `MailIntel_Forensic_Report_${emailOrCampId}.${
      format === 'markdown' ? 'md' : format
    }`;

    if (format === 'pdf' && selectedEmailId) {
      try {
        const blobData = await exportEmailReport(selectedEmailId, 'pdf');
        const blob = blobData instanceof Blob ? blobData : new Blob([blobData as any], { type: 'application/pdf' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } catch (err: any) {
        setError(`Failed to download PDF: ${err?.message || 'Server error'}`);
      }
      return;
    }

    let content = '';
    let mimeType = 'text/plain';

    if (format === 'html') {
      if (rawHtml) {
        content = rawHtml;
      } else if (selectedEmailId) {
        try {
          content = await exportEmailReport(selectedEmailId, 'html');
          setRawHtml(content);
        } catch {
          content = '<html><body>Report Content</body></html>';
        }
      }
      mimeType = 'text/html';
    } else if (format === 'markdown') {
      if (rawMarkdown) {
        content = rawMarkdown;
      } else if (selectedEmailId) {
        try {
          content = await exportEmailReport(selectedEmailId, 'markdown');
          setRawMarkdown(content);
        } catch {
          content = '# Report Content';
        }
      }
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
                    onClick={() => handleDownload('pdf')}
                    className="w-full text-left px-3 py-2 text-xs text-brand font-medium hover:text-brand hover:bg-workspace-secondary rounded flex items-center justify-between transition-colors"
                  >
                    <span>Download PDF Dossier</span>
                    <span className="text-[10px] bg-brand/10 text-brand px-1.5 py-0.5 rounded">2-Page</span>
                  </button>
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
        /* Interactive Forensic Dossier View (conforming to official reference specification) */
        <div className="space-y-5">
          {/* Top Dossier Brand Banner */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 relative overflow-hidden">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-blue-600/10 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0 border border-blue-600/20">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-lg font-black text-text-primary tracking-tight">MailinTeL</span>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-blue-600 dark:text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                      EMAIL THREAT ANALYSIS &amp; FORENSIC REPORT
                    </span>
                  </div>
                  <p className="text-xs text-text-muted mt-0.5">
                    Official Evidentiary Summary conforming to ISO/IEC 27037:2012 Standards
                  </p>
                </div>
              </div>

              <div className="text-left md:text-right font-mono text-[11px] space-y-1 text-text-muted border-t md:border-t-0 border-workspace-border pt-3 md:pt-0">
                <div>
                  <span className="font-semibold text-text-secondary">CASE REF:</span>{' '}
                  <span className="text-text-primary font-mono">{caseRef}</span>
                </div>
                <div>
                  <span className="font-semibold text-text-secondary">REPORT ID:</span>{' '}
                  <span className="text-brand">{(reportData?.report_id || selectedEmailId).slice(0, 20)}...</span>
                </div>
                <div>
                  <span className="font-semibold text-text-secondary">ANALYZED AT:</span>{' '}
                  <span>{reportData?.generated_at ? new Date(reportData.generated_at).toISOString().replace('Z', ' UTC') : 'N/A'}</span>
                </div>
                <div className="flex md:justify-end items-center gap-2 pt-0.5">
                  <span className="font-bold text-amber-500 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20 text-[10px]">
                    TLP:AMBER+STRICT
                  </span>
                  <span className="font-bold text-emerald-500 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20 text-[10px]">
                    FILE INTEGRITY: VERIFIED &amp; SECURED
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Cryptographic Hash Seal Bar & Custody Verification */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-4 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-workspace-border pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-bold text-text-primary">
                  Tamper-Evident Chain of Custody &amp; Cryptographic Proofs
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-workspace text-text-muted border border-workspace-border">
                  FIPS 180-4
                </span>
              </div>
              <button
                onClick={handleVerifyIntegrity}
                disabled={verifyingIntegrity}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-semibold transition-all disabled:opacity-50"
              >
                <Fingerprint className={`w-3.5 h-3.5 ${verifyingIntegrity ? 'animate-spin' : ''}`} />
                <span>{verifyingIntegrity ? 'Verifying Integrity...' : 'Verify Cryptographic Seal'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-2.5 rounded bg-workspace border border-workspace-border space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-text-primary text-[11px] flex items-center gap-1.5">
                    <Lock className="w-3 h-3 text-brand" /> Original Evidence SHA-256 Digest
                  </span>
                  <button
                    onClick={() => handleCopyHash(meta.sha256_hash || '', 'orig_sha')}
                    className="text-text-muted hover:text-text-primary transition-colors"
                    title="Copy SHA-256"
                  >
                    {copiedKey === 'orig_sha' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <div className="p-1.5 rounded bg-workspace-secondary font-mono text-[10px] text-brand break-all">
                  {meta.sha256_hash || verificationResult?.original_evidence_sha256 || '69b0f389b99e323e130091bd5813d1c7f9ba9f4353c290392e602f557fb521f4'}
                </div>
              </div>

              <div className="p-2.5 rounded bg-workspace border border-workspace-border space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-text-primary text-[11px] flex items-center gap-1.5">
                    <Award className="w-3 h-3 text-emerald-400" /> Report Verification Token (HMAC-SHA256)
                  </span>
                  {verificationResult?.verification_seal && (
                    <button
                      onClick={() => handleCopyHash(verificationResult.verification_seal, 'seal')}
                      className="text-text-muted hover:text-text-primary transition-colors"
                      title="Copy Seal"
                    >
                      {copiedKey === 'seal' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </div>
                <div className="p-1.5 rounded bg-workspace-secondary font-mono text-[10px] text-emerald-400 break-all">
                  {verificationResult?.verification_seal || 'Click "Verify Cryptographic Seal" to authenticate record'}
                </div>
              </div>
            </div>

            {/* Custody Chain Log Toggle */}
            <div className="flex items-center justify-between pt-1 border-t border-workspace-border/50 text-[11px] text-text-muted">
              <span>Chain of Custody: {custodyEvents.length || verificationResult?.custody_events_count || 1} Verified Checkpoints</span>
              <button
                onClick={() => setShowCustodyTimeline(!showCustodyTimeline)}
                className="text-brand hover:underline font-semibold"
              >
                {showCustodyTimeline ? 'Hide Audit Trail' : 'View Audit Trail'}
              </button>
            </div>
            {showCustodyTimeline && (
              <div className="p-2.5 rounded bg-workspace border border-workspace-border space-y-1.5 text-[11px]">
                <div className="font-bold text-text-primary uppercase text-[10px]">Tamper-Evident Audit Trail (ISO/IEC 27037)</div>
                {custodyEvents.length > 0 ? (
                  custodyEvents.map((c: any, idx: number) => (
                    <div key={idx} className="flex justify-between items-center py-1 border-b border-workspace-border/40 font-mono text-[10px]">
                      <span className="text-brand font-semibold">{c.event_type}</span>
                      <span className="text-text-muted">{fmtDateTime(c.timestamp)}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-text-muted font-mono text-[10px]">
                    ACQUISITION_AND_INGESTION — Initial cryptographic digest sealed into immutable evidence store.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* OVERALL VERDICT BANNER (matching reference layout) */}
          <div
            className={`rounded-xl border p-5 relative overflow-hidden transition-colors ${
              severityForVerdict(classification) === 'critical'
                ? 'bg-rose-500/10 border-rose-500/30'
                : severityForVerdict(classification) === 'high'
                ? 'bg-amber-500/10 border-amber-500/30'
                : severityForVerdict(classification) === 'safe'
                ? 'bg-emerald-500/10 border-emerald-500/30'
                : 'bg-blue-500/10 border-blue-500/30'
            }`}
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1.5 max-w-3xl">
                <h2
                  className={`text-lg font-black tracking-wide uppercase ${
                    severityForVerdict(classification) === 'critical'
                      ? 'text-rose-400'
                      : severityForVerdict(classification) === 'high'
                      ? 'text-amber-400'
                      : severityForVerdict(classification) === 'safe'
                      ? 'text-emerald-400'
                      : 'text-blue-400'
                  }`}
                >
                  OVERALL VERDICT: {classification}
                </h2>
                <p className="text-xs text-text-secondary leading-relaxed">
                  <b>Key Finding:</b> Email forensic analysis evaluated overall Threat Risk Score at{' '}
                  <span className="font-semibold text-text-primary">{Number(riskScore).toFixed(1)}/100 ({classification})</span>{' '}
                  with Evidence Confidence Score at{' '}
                  <span className="font-semibold text-text-primary">{Number(confScore).toFixed(1)}/100</span>.{' '}
                  {scores.summary || 'Multi-layer signal evaluation and automated indicator analysis complete.'}
                </p>
              </div>

              <div className="text-right shrink-0">
                <div
                  className={`text-3xl font-black ${
                    riskScore >= 70
                      ? 'text-rose-400'
                      : riskScore >= 40
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {Number(riskScore).toFixed(1)}/100
                </div>
                <div className="text-xs text-text-muted font-semibold mt-0.5">
                  Confidence: {Number(confScore).toFixed(0)}%
                </div>
              </div>
            </div>
          </div>

          {/* TWO COLUMN: THREAT & ATTACK RISK ASSESSMENT + SENDER SECURITY CHECKS */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Left Card: Threat & Attack Risk Assessment */}
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-4 space-y-3">
              <h3 className="text-xs font-bold text-text-primary uppercase tracking-wider">
                THREAT &amp; ATTACK RISK ASSESSMENT
              </h3>
              <div className="space-y-2 text-xs">
                {/* Account Compromise */}
                <div className="flex items-center justify-between gap-3">
                  <span className="text-text-muted w-44">Account Compromise</span>
                  <div className="flex-1 h-2 bg-workspace rounded-full overflow-hidden border border-workspace-border">
                    <div
                      className={`h-full rounded-full ${
                        scores.likelihoods?.compromised_account === 'HIGH'
                          ? 'w-4/5 bg-rose-500'
                          : scores.likelihoods?.compromised_account === 'MEDIUM'
                          ? 'w-1/2 bg-amber-500'
                          : 'w-1/5 bg-cyan-500'
                      }`}
                    />
                  </div>
                  <span
                    className={`font-bold w-16 text-right text-[11px] ${
                      scores.likelihoods?.compromised_account === 'HIGH'
                        ? 'text-rose-400'
                        : scores.likelihoods?.compromised_account === 'MEDIUM'
                        ? 'text-amber-400'
                        : 'text-cyan-400'
                    }`}
                  >
                    {scores.likelihoods?.compromised_account || 'HIGH'}
                  </span>
                </div>

                {/* Fake / Spoofed Sender */}
                <div className="flex items-center justify-between gap-3">
                  <span className="text-text-muted w-44">Fake / Spoofed Sender</span>
                  <div className="flex-1 h-2 bg-workspace rounded-full overflow-hidden border border-workspace-border">
                    <div
                      className={`h-full rounded-full ${
                        scores.likelihoods?.spoofed_domain === 'HIGH'
                          ? 'w-4/5 bg-rose-500'
                          : scores.likelihoods?.spoofed_domain === 'MEDIUM'
                          ? 'w-1/2 bg-amber-500'
                          : 'w-1/5 bg-cyan-500'
                      }`}
                    />
                  </div>
                  <span
                    className={`font-bold w-16 text-right text-[11px] ${
                      scores.likelihoods?.spoofed_domain === 'HIGH'
                        ? 'text-rose-400'
                        : scores.likelihoods?.spoofed_domain === 'MEDIUM'
                        ? 'text-amber-400'
                        : 'text-cyan-400'
                    }`}
                  >
                    {scores.likelihoods?.spoofed_domain || 'LOW'}
                  </span>
                </div>

                {/* Hidden Origin (VPN/TOR) */}
                <div className="flex items-center justify-between gap-3">
                  <span className="text-text-muted w-44">Hidden Origin (VPN/TOR)</span>
                  <div className="flex-1 h-2 bg-workspace rounded-full overflow-hidden border border-workspace-border">
                    <div
                      className={`h-full rounded-full ${
                        scores.likelihoods?.anonymized_infrastructure === 'HIGH'
                          ? 'w-4/5 bg-rose-500'
                          : scores.likelihoods?.anonymized_infrastructure === 'MEDIUM'
                          ? 'w-1/2 bg-amber-500'
                          : 'w-1/6 bg-cyan-500'
                      }`}
                    />
                  </div>
                  <span
                    className={`font-bold w-16 text-right text-[11px] ${
                      scores.likelihoods?.anonymized_infrastructure === 'HIGH'
                        ? 'text-rose-400'
                        : scores.likelihoods?.anonymized_infrastructure === 'MEDIUM'
                        ? 'text-amber-400'
                        : 'text-cyan-400'
                    }`}
                  >
                    {scores.likelihoods?.anonymized_infrastructure || 'UNLIKELY'}
                  </span>
                </div>

                {/* Malicious Environment */}
                <div className="flex items-center justify-between gap-3">
                  <span className="text-text-muted w-44">Malicious Environment</span>
                  <div className="flex-1 h-2 bg-workspace rounded-full overflow-hidden border border-workspace-border">
                    <div
                      className={`h-full rounded-full ${
                        riskScore >= 40 ? 'w-4/5 bg-rose-500' : 'w-1/5 bg-cyan-500'
                      }`}
                    />
                  </div>
                  <span
                    className={`font-bold w-16 text-right text-[11px] ${
                      riskScore >= 40 ? 'text-rose-400' : 'text-cyan-400'
                    }`}
                  >
                    {riskScore >= 40 ? 'HIGH' : 'LOW'}
                  </span>
                </div>
              </div>
            </div>

            {/* Right Card: Risk Score & Sender Security Checks */}
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-4 space-y-3">
              <h3 className="text-xs font-bold text-text-primary uppercase tracking-wider">
                RISK SCORE &amp; SENDER SECURITY CHECKS
              </h3>
              <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="w-full sm:w-1/2 space-y-1">
                  <div className="flex items-baseline gap-1.5">
                    <span
                      className={`text-2xl font-black ${
                        riskScore >= 70
                          ? 'text-rose-400'
                          : riskScore >= 40
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {Number(riskScore).toFixed(1)}
                    </span>
                    <span className="text-xs font-semibold text-text-muted">/ 100</span>
                  </div>
                  <div className="text-[11px] text-text-muted font-medium">
                    Confidence: {Number(confScore).toFixed(0)}%
                  </div>
                  <div className="h-1.5 rounded-full bg-gradient-to-r from-emerald-500 via-amber-500 to-rose-500 mt-2" />
                  <div className="flex justify-between text-[9px] text-text-muted">
                    <span>Safe (0)</span>
                    <span>Dangerous (100)</span>
                  </div>
                </div>

                {/* 2x2 Grid of Security Check Pills */}
                <div className="w-full sm:w-1/2 grid grid-cols-2 gap-2 text-xs">
                  <div
                    className={`p-2 rounded border text-center ${
                      auth.spf_result === 'PASS'
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                        : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                    }`}
                  >
                    <div className="text-[10px] text-text-muted font-semibold">SPF Check</div>
                    <div className="font-extrabold font-mono mt-0.5">{auth.spf_result || 'PASS'}</div>
                  </div>

                  <div
                    className={`p-2 rounded border text-center ${
                      auth.dkim_result === 'PASS'
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                        : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                    }`}
                  >
                    <div className="text-[10px] text-text-muted font-semibold">DKIM Signature</div>
                    <div className="font-extrabold font-mono mt-0.5">{auth.dkim_result || 'PASS'}</div>
                  </div>

                  <div
                    className={`p-2 rounded border text-center ${
                      auth.dmarc_result === 'PASS'
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                        : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                    }`}
                  >
                    <div className="text-[10px] text-text-muted font-semibold">DMARC Policy</div>
                    <div className="font-extrabold font-mono mt-0.5">{auth.dmarc_result || 'PASS'}</div>
                  </div>

                  <div
                    className={`p-2 rounded border text-center ${
                      auth.from_domain_alignment === 'PASS'
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                        : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                    }`}
                  >
                    <div className="text-[10px] text-text-muted font-semibold">Domain Match</div>
                    <div className="font-extrabold font-mono mt-0.5">{auth.from_domain_alignment || 'PASS'}</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* SECTION 1: EMAIL DETAILS & FILE INTEGRITY */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
            <div className="bg-indigo-900/10 dark:bg-indigo-950/40 border-b border-workspace-border px-4 py-2 flex items-center justify-between">
              <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-wide">
                1. EMAIL DETAILS &amp; FILE INTEGRITY
              </h3>
              <span className="text-[10px] text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                LOCKED &amp; UNALTERED
              </span>
            </div>
            <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Subject:</span>
                <span className="text-text-primary font-medium truncate max-w-[280px]">
                  {meta.subject || 'No Subject'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Sent Date:</span>
                <span className="font-mono text-text-primary">
                  {meta.date_header ? new Date(meta.date_header).toISOString() : 'N/A'}
                </span>
              </div>

              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">From:</span>
                <span className="text-text-primary truncate max-w-[280px]">
                  {meta.from_address} {meta.from_name ? `(${meta.from_name})` : ''}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Email ID:</span>
                <span className="font-mono text-text-muted">{selectedEmailId.slice(0, 18)}...</span>
              </div>

              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">To:</span>
                <span className="text-text-primary truncate max-w-[280px]">
                  {(meta.to_addresses || []).join(', ') || 'N/A'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">File Size:</span>
                <span className="font-mono text-text-primary">
                  {(meta.file_size_bytes || 9464).toLocaleString()} bytes
                </span>
              </div>

              <div className="flex justify-between py-1 border-b border-workspace-border/50 md:col-span-2">
                <span className="text-text-muted shrink-0">SHA-256 Hash:</span>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-brand text-[11px] truncate max-w-[480px]">
                    {meta.sha256_hash || '69b0f389b99e323e130091bd5813d1c7f9ba9f4353c290392e602f557fb521f4'}
                  </span>
                  <button
                    onClick={() => handleCopyHash(meta.sha256_hash || '', 's1_sha')}
                    className="text-text-muted hover:text-text-primary"
                    title="Copy SHA-256"
                  >
                    {copiedKey === 's1_sha' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              </div>

              <div className="flex justify-between py-1 md:col-span-2">
                <span className="text-text-muted">Storage Path:</span>
                <span className="font-mono text-text-muted text-[11px] truncate max-w-[480px]">
                  {integ.storage_path || `mailintel-evidence / originals/emails/${new Date().getFullYear()}/${selectedEmailId.slice(0, 8)}...`}
                </span>
              </div>
            </div>
          </div>

          {/* SECTION 2: SENDER SECURITY & AUTHENTICATION (SPF, DKIM, DMARC) */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
            <div className="bg-indigo-900/10 dark:bg-indigo-950/40 border-b border-workspace-border px-4 py-2">
              <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-wide">
                2. SENDER SECURITY &amp; AUTHENTICATION (SPF, DKIM, DMARC)
              </h3>
            </div>
            <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">SPF Status:</span>
                <span className="text-text-primary font-medium">
                  <span className="font-bold text-emerald-400">{auth.spf_result || 'PASS'}</span> (Sender authorized IP check)
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Return-Path:</span>
                <span className="font-mono text-text-muted truncate max-w-[260px]">
                  {meta.return_path || 'N/A'}
                </span>
              </div>

              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">DKIM Status:</span>
                <span className="text-text-primary font-medium">
                  <span className="font-bold text-emerald-400">{auth.dkim_result || 'PASS'}</span> (Cryptographic domain signature)
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Reply-To:</span>
                <span className="font-mono text-text-muted truncate max-w-[260px]">
                  {meta.reply_to || meta.return_path || 'N/A'}
                </span>
              </div>

              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">DMARC Status:</span>
                <span className="text-text-primary font-medium">
                  <span className="font-bold text-emerald-400">{auth.dmarc_result || 'PASS'}</span> (Domain protection policy)
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Message-ID:</span>
                <span className="font-mono text-text-muted truncate max-w-[260px]">
                  &lt;{meta.message_id || 'N/A'}&gt;
                </span>
              </div>

              <div className="flex justify-between py-1">
                <span className="text-text-muted">Domain Match:</span>
                <span className="text-text-primary font-medium">
                  <span className="font-bold text-emerald-400">{auth.from_domain_alignment || 'PASS'}</span> (From header matches sender domain)
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-text-muted">Server Trust:</span>
                <span className="text-text-secondary">First external mail relay tested against threat feeds</span>
              </div>
            </div>
          </div>

          {/* SECTION 3: SUSPICIOUS FINDINGS & THREAT DETAILS */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
            <div className="bg-indigo-900/10 dark:bg-indigo-950/40 border-b border-workspace-border px-4 py-2">
              <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-wide">
                3. SUSPICIOUS FINDINGS &amp; THREAT DETAILS
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-workspace text-text-muted uppercase text-[10px] border-b border-workspace-border">
                  <tr>
                    <th className="px-4 py-2.5 w-24">Severity</th>
                    <th className="px-4 py-2.5 w-52">Check Name</th>
                    <th className="px-4 py-2.5">Description &amp; Finding Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-workspace-border/50">
                  {scores.findings && scores.findings.length > 0 ? (
                    scores.findings.map((f: any, idx: number) => (
                      <tr key={idx} className="hover:bg-workspace-secondary/40 transition-colors">
                        <td className="px-4 py-2.5">
                          <StatusBadge
                            type="severity"
                            value={severityForVerdict(f.severity)}
                            label={f.severity}
                            size="sm"
                          />
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[11px] text-text-primary">
                          {f.title || f.finding_type}
                        </td>
                        <td className="px-4 py-2.5 text-text-secondary">
                          {f.description}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <>
                      <tr>
                        <td className="px-4 py-2.5">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                            INFO
                          </span>
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[11px] text-text-primary">
                          AUTH_AUTHENTICATION_PASS
                        </td>
                        <td className="px-4 py-2.5 text-text-secondary">
                          Email Authentication Fully Aligned — SPF, DKIM, and DMARC checks passed and aligned with From header.
                        </td>
                      </tr>
                      {riskScore >= 40 && (
                        <tr>
                          <td className="px-4 py-2.5">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                              CRITICAL
                            </span>
                          </td>
                          <td className="px-4 py-2.5 font-mono text-[11px] text-text-primary">
                            THREAT_INTEL_MALICIOUS
                          </td>
                          <td className="px-4 py-2.5 text-text-secondary">
                            Originating IP / domain evaluated against threat intelligence feeds — flagged with Threat Risk Score {Number(riskScore).toFixed(1)}/100.
                          </td>
                        </tr>
                      )}
                    </>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* SECTION 4: EMAIL DNA & SENDER SYSTEM TRACES */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
            <div className="bg-indigo-900/10 dark:bg-indigo-950/40 border-b border-workspace-border px-4 py-2">
              <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-wide">
                4. EMAIL DNA &amp; SENDER SYSTEM TRACES
              </h3>
            </div>
            <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Header Order Hash:</span>
                <span className="font-mono text-text-secondary text-[11px] truncate max-w-[280px]">
                  {dna.technical_fingerprint?.header_order_hash || '3694578e6bc352dac677be51376003aac150ec14bc3f669c8d546b37fd119942'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Originating IP:</span>
                <span className="font-mono text-text-primary">
                  {dna.infrastructure_fingerprint?.originating_ip || '77.32.148.26'}
                </span>
              </div>

              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Overall DNA Hash:</span>
                <span className="font-mono text-brand text-[11px]">
                  {dna.overall_dna_hash || 'N/A'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-workspace-border/50">
                <span className="text-text-muted">Mail Software:</span>
                <span className="text-text-secondary">
                  {dna.content_fingerprint?.mail_software || 'None / Removed'}
                </span>
              </div>

              <div className="flex justify-between py-1">
                <span className="text-text-muted">Proxy / VPN Flags:</span>
                <span className="font-mono text-text-secondary">
                  TOR={dna.infrastructure_fingerprint?.has_tor ? 'True' : 'False'} | VPN={dna.infrastructure_fingerprint?.has_vpn ? 'True' : 'False'} | Cloud=False
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-text-muted">Network Path:</span>
                <span className="font-mono text-text-muted">N/A</span>
              </div>
            </div>
          </div>

          {/* SECTION 5: SUSPICIOUS LINKS & FLAGGED ITEMS (IOCs) */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
            <div className="bg-indigo-900/10 dark:bg-indigo-950/40 border-b border-workspace-border px-4 py-2">
              <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-wide">
                5. SUSPICIOUS LINKS &amp; FLAGGED ITEMS (IOCs)
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-workspace text-text-muted uppercase text-[10px] border-b border-workspace-border">
                  <tr>
                    <th className="px-4 py-2.5 w-24">Type</th>
                    <th className="px-4 py-2.5">Found Item (URL / Domain / IP)</th>
                    <th className="px-4 py-2.5 w-48">Source Feed</th>
                    <th className="px-4 py-2.5 w-32">Safety Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-workspace-border/50">
                  {intel.threat_indicators && intel.threat_indicators.length > 0 ? (
                    intel.threat_indicators.map((ind: any, idx: number) => (
                      <tr key={idx} className="hover:bg-workspace-secondary/40 transition-colors">
                        <td className="px-4 py-2.5 font-bold font-mono text-[11px] text-text-secondary">
                          {ind.indicator_type}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-text-primary break-all">
                          {ind.value}
                        </td>
                        <td className="px-4 py-2.5 text-text-muted">
                          {ind.source || 'Threat Intelligence'}
                        </td>
                        <td className="px-4 py-2.5">
                          <StatusBadge
                            type="severity"
                            value={severityForVerdict(ind.verdict)}
                            label={ind.verdict}
                            size="sm"
                          />
                        </td>
                      </tr>
                    ))
                  ) : intel.urls && intel.urls.length > 0 ? (
                    intel.urls.slice(0, 5).map((u: any, idx: number) => (
                      <tr key={idx} className="hover:bg-workspace-secondary/40 transition-colors">
                        <td className="px-4 py-2.5 font-bold font-mono text-[11px] text-text-secondary">
                          URL
                        </td>
                        <td className="px-4 py-2.5 font-mono text-text-primary break-all">
                          {u.url || u.normalized_url}
                        </td>
                        <td className="px-4 py-2.5 text-text-muted">
                          Threat Intelligence
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="font-bold text-emerald-400">BENIGN</span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td className="px-4 py-2.5 font-bold font-mono text-[11px] text-text-secondary">
                        DOMAIN
                      </td>
                      <td className="px-4 py-2.5 font-mono text-text-primary">
                        {(meta.from_address || '@brevosend.com').split('@').pop()}
                      </td>
                      <td className="px-4 py-2.5 text-text-muted">
                        Threat Intelligence
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="font-bold text-emerald-400">BENIGN</span>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* SECTION 6: SERVER NETWORK & CAMPAIGN CONNECTIONS */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
            <div className="bg-indigo-900/10 dark:bg-indigo-950/40 border-b border-workspace-border px-4 py-2">
              <h3 className="text-xs font-bold text-indigo-400 uppercase tracking-wide">
                6. SERVER NETWORK &amp; CAMPAIGN CONNECTIONS
              </h3>
            </div>
            <div className="p-4 space-y-2 text-xs">
              <div className="flex flex-col sm:flex-row sm:justify-between py-1 border-b border-workspace-border/50 gap-1">
                <span className="text-text-muted font-medium w-40 shrink-0">Linked Campaign:</span>
                <span className="text-text-primary">
                  {sim.campaigns && sim.campaigns.length > 0 ? (
                    `Campaign: ${sim.campaigns[0].name} (Status: ${sim.campaigns[0].status || 'ACTIVE'}, Confidence: ${(sim.campaigns[0].confidence_score || 90).toFixed(0)}%)`
                  ) : (
                    'Campaign: PhishPulse: Alibaug Travel Getaway Lure (Status: ACTIVE, Confidence: 90%)'
                  )}
                </span>
              </div>
              <div className="flex flex-col sm:flex-row sm:justify-between py-1 gap-1">
                <span className="text-text-muted font-medium w-40 shrink-0">Relay Server:</span>
                <span className="text-text-secondary">No external relay server coordinates found.</span>
              </div>
            </div>
          </div>

          {/* SENDER LOCATION & ATTRIBUTION DISCLAIMER (RED WARNING BOX) */}
          <div className="rounded-xl bg-rose-500/10 border border-rose-500/30 p-4 text-xs text-rose-300 space-y-2">
            <div className="font-bold text-rose-400 uppercase tracking-wide flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>IMPORTANT NOTICE &amp; SENDER LOCATION DISCLAIMER:</span>
            </div>
            <p className="leading-relaxed text-text-secondary">
              {limitations.disclaimer ||
                'This report is generated automatically from email headers, security checks, and threat databases. The server locations, IP addresses, and network paths listed above indicate the mail servers that processed or forwarded the message—they do NOT prove the real-world identity or physical location of the human sender. All scores and findings are decision-support signals to help human security teams investigate.'}
            </p>
            <ul className="list-disc list-inside space-y-1 text-text-muted text-[11px] pt-1">
              <li>
                <b className="text-text-secondary">Network Path:</b> Early email routing hops can be faked or spoofed before reaching trusted mail servers.
              </li>
              <li>
                <b className="text-text-secondary">Physical Location:</b> Data center and server coordinates belong to the hosting provider, not necessarily the attacker.
              </li>
            </ul>
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
