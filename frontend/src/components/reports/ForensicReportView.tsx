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
  const [showStorageDetails, setShowStorageDetails] = useState<boolean>(false);

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
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

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
      try {
        if (reportType === 'email') {
          const data = await getEmailReportData(selectedEmailId);
          setReportData(data);
          const md = await exportEmailReport(selectedEmailId, 'markdown');
          setRawMarkdown(md);
          const html = await exportEmailReport(selectedEmailId, 'html');
          setRawHtml(html);
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

  const handleGenerateAndPreserve = async (format: 'html' | 'markdown' | 'json' = 'html') => {
    setGenerating(true);
    setSuccessMsg(null);
    setError(null);
    try {
      if (reportType === 'email') {
        const res = await generateEmailReport(selectedEmailId, format);
        setReportData(res.report_data);
        setSuccessMsg(`Report ${res.report_id.slice(0, 8)} generated and sealed for custody.`);
      } else {
        const res = await generateCampaignReport(selectedCampaignId, format);
        setReportData(res.report_data);
        setSuccessMsg(`Campaign dossier ${res.report_id.slice(0, 8)} generated and sealed for custody.`);
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
    const filename = `MailIntel_Report_${(selectedEmailId || selectedCampaignId).slice(0, 8)}.${
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
  const dna = reportData?.email_dna || {};
  const intel = reportData?.threat_intelligence || {};
  const sim = reportData?.similarity_and_clusters || {};
  const geo = reportData?.geo_intelligence || {};
  const limitations = reportData?.limitations_and_disclaimer || {};

  const classification = scores?.threat_classification || 'UNKNOWN';
  const riskScore = scores?.threat_risk_score || 0;
  const confScore = scores?.evidence_confidence_score || 0;

  const viewTabs: { id: ViewFormat; label: string; icon: React.ReactNode }[] = [
    { id: 'dossier', label: 'Interactive Dossier', icon: <Eye className="w-3.5 h-3.5" /> },
    { id: 'html_preview', label: 'Printable Preview', icon: <FileCode className="w-3.5 h-3.5" /> },
    { id: 'markdown', label: 'Markdown Source', icon: <Code className="w-3.5 h-3.5" /> },
    { id: 'json', label: 'JSON Schema', icon: <Database className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header & Triage Controls */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-text-primary tracking-tight">Forensic Reports</h1>
              <p className="text-sm text-text-muted mt-0.5">
                Generate and review tamper-evident forensic dossiers with full custody proofs.
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
              className="flex items-center gap-1.5 bg-brand hover:bg-brand-hover text-white px-3.5 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${generating ? 'animate-spin' : ''}`} />
              <span>{generating ? 'Generating…' : 'Generate & Preserve'}</span>
            </button>
          </div>
        </div>

        {successMsg && (
          <div className="mt-4 px-4 py-2.5 rounded-lg bg-severity-safe-soft border border-severity-safe/20 text-sm text-severity-safe flex items-center gap-2.5">
            <Check className="w-4 h-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}
        {error && (
          <div className="mt-4 px-4 py-2.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-sm text-severity-high flex items-center gap-2.5">
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
                    ? 'bg-brand-soft text-brand border border-brand/20'
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
              className="flex items-center gap-1.5 bg-workspace-card hover:bg-workspace-secondary border border-workspace-border text-text-secondary px-3 py-1.5 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-severity-safe" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={handlePrint}
              disabled={!reportData}
              className="flex items-center gap-1.5 bg-workspace-card hover:bg-workspace-secondary border border-workspace-border text-text-secondary px-3 py-1.5 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>

            <div className="relative group">
              <button
                disabled={!reportData}
                className="flex items-center gap-1.5 bg-brand-soft hover:bg-brand-soft border border-brand/20 text-brand px-3 py-1.5 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export File</span>
              </button>
              {reportData && (
                <div className="absolute right-0 mt-1 w-44 bg-workspace-card border border-workspace-border rounded-lg shadow-lg p-1 hidden group-hover:block z-30">
                  <button
                    onClick={() => handleDownload('html')}
                    className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-workspace-secondary rounded"
                  >
                    Download HTML (.html)
                  </button>
                  <button
                    onClick={() => handleDownload('markdown')}
                    className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-workspace-secondary rounded"
                  >
                    Download Markdown (.md)
                  </button>
                  <button
                    onClick={() => handleDownload('json')}
                    className="w-full text-left px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary hover:bg-workspace-secondary rounded"
                  >
                    Download JSON (.json)
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
              <div className="h-3 w-1/3 bg-workspace-secondary rounded mb-3" />
              <div className="h-3 w-2/3 bg-workspace-secondary rounded mb-2" />
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
              ? 'Analyze an email first, then come back here to generate its forensic report.'
              : 'Choose an entity and generate a report to see it here.'}
          </p>
        </div>
      ) : viewFormat === 'html_preview' ? (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-4">
          <div className="flex items-center justify-between mb-3 px-2">
            <span className="text-xs font-mono text-text-muted">Rendered Printable Document Preview</span>
            <button
              onClick={handlePrint}
              className="text-xs bg-brand hover:bg-brand-hover text-white px-3 py-1 rounded font-medium"
            >
              Print / Save as PDF
            </button>
          </div>
          <iframe
            id="report-html-frame"
            srcDoc={rawHtml}
            title="Forensic Report HTML Preview"
            className="w-full h-[800px] border border-workspace-border rounded-lg bg-white"
          />
        </div>
      ) : viewFormat === 'markdown' ? (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-text-muted">GitHub Flavored Markdown</span>
            <button onClick={handleCopyContent} className="text-xs text-brand hover:text-brand-hover font-medium">
              {copied ? 'Copied!' : 'Copy Markdown'}
            </button>
          </div>
          <pre className="p-4 bg-workspace border border-workspace-border rounded-lg text-xs font-mono text-text-secondary whitespace-pre-wrap overflow-x-auto max-h-[700px]">
            {rawMarkdown}
          </pre>
        </div>
      ) : viewFormat === 'json' ? (
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-text-muted">JSON Schema Payload</span>
            <button onClick={handleCopyContent} className="text-xs text-brand hover:text-brand-hover font-medium">
              {copied ? 'Copied!' : 'Copy JSON'}
            </button>
          </div>
          <pre className="p-4 bg-workspace border border-workspace-border rounded-lg text-xs font-mono text-text-secondary whitespace-pre-wrap overflow-x-auto max-h-[700px]">
            {JSON.stringify(reportData, null, 2)}
          </pre>
        </div>
      ) : (
        /* Interactive Dossier View */
        <div className="space-y-6">
          {/* Executive Verdict Banner — Design.md §25 report card pattern */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6 relative overflow-hidden">
            <div
              className={`absolute top-0 left-0 w-1.5 h-full ${
                severityForVerdict(classification) === 'critical'
                  ? 'bg-severity-critical'
                  : severityForVerdict(classification) === 'high'
                  ? 'bg-severity-high'
                  : severityForVerdict(classification) === 'safe'
                  ? 'bg-severity-safe'
                  : 'bg-severity-medium'
              }`}
            />
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
              <div>
                <div className="flex items-center gap-3 flex-wrap">
                  <StatusBadge type="severity" value={severityForVerdict(classification)} label={classification} />
                  <span className="text-xs font-mono text-text-muted">
                    REF-{(reportData.report_id || reportData.email_id || '').toString().slice(0, 8).toUpperCase()}
                  </span>
                  <span className="text-xs text-text-muted">{fmtDateTime(reportData.generated_at)}</span>
                </div>
                <h2 className="text-lg font-bold text-text-primary mt-2">
                  {meta.subject || reportData.campaign_name || 'Forensic Intelligence Dossier'}
                </h2>
                <p className="text-sm text-text-muted mt-1 max-w-3xl leading-relaxed">
                  {scores.summary || 'No automated forensic summary available.'}
                </p>
              </div>

              <div className="flex items-center gap-6 border-t md:border-t-0 md:border-l border-workspace-border pt-4 md:pt-0 md:pl-6 flex-shrink-0">
                <div className="text-center">
                  <div
                    className={`text-3xl font-extrabold ${
                      riskScore >= 70
                        ? 'text-severity-critical'
                        : riskScore >= 40
                        ? 'text-severity-high'
                        : 'text-severity-safe'
                    }`}
                  >
                    {Number(riskScore).toFixed(1)}
                  </div>
                  <div className="text-[10px] uppercase font-bold text-text-muted tracking-wider mt-0.5">
                    Threat Risk (0–100)
                  </div>
                </div>

                <div className="text-center">
                  <div className="text-3xl font-extrabold text-brand">{Number(confScore).toFixed(1)}%</div>
                  <div className="text-[10px] uppercase font-bold text-text-muted tracking-wider mt-0.5">
                    Evidence Confidence
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* 1 & 2: Evidence & Authentication */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3 mb-4">
                <Lock className="w-4 h-4 text-brand" />
                <span>Digital Evidence & Integrity</span>
              </div>
              <div className="space-y-2.5 text-sm">
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">Email ID</span>
                  <span className="font-mono text-text-primary">{reportData.email_id || 'N/A'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">From (Sender)</span>
                  <span className="text-text-primary font-medium truncate max-w-[280px]">
                    {meta.from_address} {meta.from_name ? `(${meta.from_name})` : ''}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">To (Recipients)</span>
                  <span className="text-text-primary truncate max-w-[280px]">
                    {(meta.to_addresses || []).join(', ') || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">SHA-256 Digest</span>
                  <span className="font-mono text-brand truncate max-w-[220px]" title={meta.sha256_hash}>
                    {meta.sha256_hash || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-text-muted">File Size</span>
                  <span className="text-text-primary font-mono">
                    {meta.file_size_bytes?.toLocaleString() || 0} bytes
                  </span>
                </div>

                {(integ.bucket || integ.immutable !== undefined) && (
                  <div className="pt-2">
                    <button
                      onClick={() => setShowStorageDetails((v) => !v)}
                      className="flex items-center gap-1 text-xs text-text-muted hover:text-text-primary"
                    >
                      {showStorageDetails ? (
                        <ChevronUp className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" />
                      )}
                      Storage details
                    </button>
                    {showStorageDetails && (
                      <div className="mt-2 p-3 bg-workspace rounded-lg text-xs text-text-secondary space-y-1">
                        <div className="flex justify-between">
                          <span className="text-text-muted">Preservation bucket</span>
                          <span className="font-mono">{integ.bucket || 'N/A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-text-muted">Immutable</span>
                          <span>{integ.immutable ? 'Yes' : 'No'}</span>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3 mb-4">
                <Shield className="w-4 h-4 text-severity-safe" />
                <span>Cryptographic Authentication</span>
              </div>
              <div className="space-y-2.5 text-sm">
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">SPF Authentication</span>
                  <span className={`font-mono font-bold ${auth.spf_result === 'PASS' ? 'text-severity-safe' : 'text-severity-critical'}`}>
                    {auth.spf_result || 'NONE'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">DKIM Signature</span>
                  <span className={`font-mono font-bold ${auth.dkim_result === 'PASS' ? 'text-severity-safe' : 'text-text-muted'}`}>
                    {auth.dkim_result || 'NONE'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">DMARC Alignment Policy</span>
                  <span className={`font-mono font-bold ${auth.dmarc_result === 'PASS' ? 'text-severity-safe' : 'text-severity-critical'}`}>
                    {auth.dmarc_result || 'NONE'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">From-Domain Alignment</span>
                  <span className="font-mono text-text-primary">{auth.from_domain_alignment || 'NONE'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
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
          </div>

          {/* Explainable Findings */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
            <div className="flex items-center justify-between border-b border-workspace-border pb-3 mb-4 flex-wrap gap-2">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm">
                <AlertTriangle className="w-4 h-4 text-severity-high" />
                <span>Explainable Findings ({scores.findings?.length || 0})</span>
              </div>
              <div className="flex items-center gap-2 text-xs flex-wrap">
                <span className="px-2 py-0.5 rounded bg-workspace-secondary text-text-secondary">
                  Spoofed: {scores.likelihoods?.spoofed_domain || 'UNLIKELY'}
                </span>
                <span className="px-2 py-0.5 rounded bg-workspace-secondary text-text-secondary">
                  Compromised: {scores.likelihoods?.compromised_account || 'UNLIKELY'}
                </span>
                <span className="px-2 py-0.5 rounded bg-workspace-secondary text-text-secondary">
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
                      Conf: {(f.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-sm text-text-muted py-3 text-center">
                No active suspicious findings flagged for this email.
              </div>
            )}
          </div>

          {/* DNA & Threat Indicators */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3 mb-4">
                <Layers className="w-4 h-4 text-severity-medium" />
                <span>Email DNA Structural Fingerprint</span>
              </div>
              <div className="space-y-2.5 text-sm">
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">Overall DNA Hash</span>
                  <span className="font-mono text-severity-medium truncate max-w-[220px]">
                    {dna.overall_dna_hash || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">Header Ordering Hash</span>
                  <span className="font-mono text-text-secondary truncate max-w-[220px]">
                    {dna.technical_fingerprint?.header_order_hash || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-workspace-border/60">
                  <span className="text-text-muted">Originating IP</span>
                  <span className="font-mono text-text-secondary">
                    {dna.infrastructure_fingerprint?.originating_ip || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-text-muted">Anonymized Infrastructure</span>
                  <span className="text-text-secondary">
                    TOR: {dna.infrastructure_fingerprint?.has_tor ? 'Yes' : 'No'} · VPN:{' '}
                    {dna.infrastructure_fingerprint?.has_vpn ? 'Yes' : 'No'}
                  </span>
                </div>
              </div>
            </div>

            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3 mb-4">
                <Globe className="w-4 h-4 text-brand" />
                <span>Threat Intelligence & URLs ({intel.urls?.length || 0})</span>
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
          </div>

          {/* Campaign & Similarity Correlations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3 mb-4">
                <Globe className="w-4 h-4 text-severity-safe" />
                <span>Campaign Associations ({sim.campaigns?.length || 0})</span>
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

            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
              <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3 mb-4">
                <Layers className="w-4 h-4 text-severity-medium" />
                <span>Semantically Similar Lures ({sim.similar_emails?.length || 0})</span>
              </div>
              <div className="space-y-2">
                {sim.similar_emails && sim.similar_emails.length > 0 ? (
                  sim.similar_emails.map((s: any, idx: number) => (
                    <div key={idx} className="p-2.5 bg-workspace border border-workspace-border rounded flex items-center justify-between text-xs gap-2">
                      <div className="truncate max-w-[260px]">
                        <div className="font-medium text-text-primary truncate">{s.target_subject || 'Correlated Email'}</div>
                        <div className="text-[10px] text-text-muted font-mono truncate">{s.target_sender || 'Unknown'}</div>
                      </div>
                      <span className="font-mono text-severity-safe font-bold">
                        {(s.weighted_similarity_score * 100).toFixed(0)}%
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-text-muted py-3 text-center">No similar lures detected in corpus.</div>
                )}
              </div>
            </div>
          </div>

          {/* Geolocation */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5">
            <div className="flex items-center gap-2 text-text-primary font-semibold text-sm border-b border-workspace-border pb-3 mb-4">
              <Globe className="w-4 h-4 text-brand" />
              <span>Infrastructure Geolocation & Hop Transit Nodes</span>
            </div>

            {geo.locations && geo.locations.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-workspace-border text-text-muted uppercase text-[10px]">
                      <th className="pb-2">IP Address</th>
                      <th className="pb-2">Role</th>
                      <th className="pb-2">Country</th>
                      <th className="pb-2">City / Region</th>
                      <th className="pb-2">ASN / Provider</th>
                      <th className="pb-2">Coordinates</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-workspace-border">
                    {geo.locations.map((loc: any, idx: number) => (
                      <tr key={idx} className="hover:bg-workspace-secondary">
                        <td className="py-2.5 font-mono text-brand">{loc.ip_address}</td>
                        <td className="py-2.5 text-text-muted">{loc.role}</td>
                        <td className="py-2.5 text-text-primary font-medium">
                          {loc.country} ({loc.country_code})
                        </td>
                        <td className="py-2.5 text-text-muted">
                          {loc.city || 'N/A'}, {loc.region || 'N/A'}
                        </td>
                        <td className="py-2.5 text-text-muted truncate max-w-[200px]">
                          {loc.asn || ''} {loc.isp || 'N/A'}
                        </td>
                        <td className="py-2.5 font-mono text-text-muted text-[11px]">
                          {loc.latitude ? `${loc.latitude.toFixed(2)}, ${loc.longitude.toFixed(2)}` : 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-sm text-text-muted py-3 text-center">
                No public intermediate infrastructure geolocations recorded.
              </div>
            )}
          </div>

          {/* Attribution Disclaimer & Uncertainty */}
          <div className="rounded-xl bg-severity-high-soft border border-severity-high/20 p-5 text-sm text-text-secondary space-y-3">
            <div className="flex items-center gap-2 text-severity-high font-bold text-sm">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>Forensic Attribution Disclaimer & Uncertainty Statement</span>
            </div>
            <p className="leading-relaxed text-text-secondary">{limitations.disclaimer}</p>
            {limitations.uncertainty_notes && limitations.uncertainty_notes.length > 0 && (
              <ul className="list-disc list-inside space-y-1 text-text-muted text-xs">
                {limitations.uncertainty_notes.map((note: string, idx: number) => (
                  <li key={idx}>{note}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {/* Preserved Reports Archive */}
      <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-6">
        <div className="flex items-center justify-between border-b border-workspace-border pb-3 mb-4 flex-wrap gap-2">
          <div className="flex items-center gap-2 text-text-primary font-semibold text-sm">
            <Database className="w-4 h-4 text-brand" />
            <span>Preserved Reports Archive ({historicalReports.length})</span>
          </div>
        </div>

        {historicalReports.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-text-muted uppercase text-[11px] border-b border-workspace-border">
                <tr>
                  <th className="pb-2">Report ID</th>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">Associated Email / Campaign</th>
                  <th className="pb-2">Generated At</th>
                  <th className="pb-2">Verdict</th>
                  <th className="pb-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-workspace-border">
                {historicalReports.map((r) => (
                  <tr key={r.id} className="hover:bg-workspace-secondary">
                    <td className="py-2.5 font-mono text-brand">{r.id.slice(0, 8)}…</td>
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
                    <td className="py-2.5 text-right">
                      {(r.email_id || r.campaign_id) && (
                        <button
                          onClick={() => handleOpenHistoricalReport(r)}
                          className="text-xs text-brand hover:text-brand-hover font-medium"
                        >
                          View
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
              Select an email or campaign above and click "Generate & Preserve" to create your first report.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
