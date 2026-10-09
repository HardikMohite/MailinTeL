import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Cpu,
  Terminal,
  Paperclip,
  Activity,
  Play,
  CheckCircle2,
  AlertTriangle,
  UploadCloud,
  FileCode,
  Network,
  Database,
  Loader2,
  RefreshCw,
  Search,
} from 'lucide-react';
import {
  AttachmentSandboxReport,
  EmailSandboxReportsResponse,
  getEmailSandboxReports,
  detonateAttachmentInSandbox,
  detonateDirectFileInSandbox,
} from '../../services/api';

interface AttachmentSandboxPanelProps {
  emailId: string;
  attachmentCount?: number;
}

export const AttachmentSandboxPanel: React.FC<AttachmentSandboxPanelProps> = ({
  emailId,
  attachmentCount = 0,
}) => {
  const [sandboxData, setSandboxData] = useState<EmailSandboxReportsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [detonatingHash, setDetonatingHash] = useState<string | null>(null);
  const [selectedReportIndex, setSelectedReportIndex] = useState<number>(0);
  const [activeSubTab, setActiveSubTab] = useState<'static' | 'processes' | 'network' | 'mitre'>('static');
  
  // Direct file detonation state
  const [directLoading, setDirectLoading] = useState(false);
  const [directReport, setDirectReport] = useState<AttachmentSandboxReport | null>(null);
  const [directError, setDirectError] = useState<string | null>(null);

  const fetchReports = async () => {
    if (!emailId) return;
    setLoading(true);
    try {
      const res = await getEmailSandboxReports(emailId);
      setSandboxData(res);
      if (res.reports.length > 0) {
        setSelectedReportIndex(0);
      }
    } catch (err) {
      console.error('Failed to load sandbox reports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [emailId]);

  const handleDetonate = async (sha256: string) => {
    setDetonatingHash(sha256);
    try {
      const updated = await detonateAttachmentInSandbox(emailId, sha256);
      if (sandboxData) {
        const nextReports = sandboxData.reports.map((r) =>
          r.sha256.toLowerCase() === sha256.toLowerCase() ? updated : r
        );
        const highestScore = Math.max(...nextReports.map((r) => r.dynamic_detonation.detonation_score), 0);
        const overall = highestScore >= 65 ? 'MALICIOUS' : highestScore >= 35 ? 'SUSPICIOUS' : 'CLEAN';
        setSandboxData({
          ...sandboxData,
          reports: nextReports,
          highest_detonation_score: highestScore,
          overall_verdict: overall,
        });
      }
    } catch (err) {
      console.error('Detonation failed:', err);
    } finally {
      setDetonatingHash(null);
    }
  };

  const handleDirectFileUpload = async (file: File) => {
    setDirectLoading(true);
    setDirectError(null);
    try {
      const res = await detonateDirectFileInSandbox(file);
      setDirectReport(res);
    } catch (err: any) {
      setDirectError(err.message || 'Direct sandbox detonation failed.');
    } finally {
      setDirectLoading(false);
    }
  };

  const currentReport = directReport || (sandboxData?.reports && sandboxData.reports.length > 0 ? sandboxData.reports[selectedReportIndex] : null);

  const getVerdictBadge = (verdict: string) => {
    switch (verdict.toUpperCase()) {
      case 'MALICIOUS':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-black bg-rose-500/15 text-rose-600 border border-rose-500/30">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
            MALICIOUS VERDICT
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-black bg-amber-500/15 text-amber-600 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
            SUSPICIOUS HEURISTICS
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-black bg-emerald-500/15 text-emerald-600 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            BENIGN / CLEAN
          </span>
        );
    }
  };

  return (
    <div className="space-y-4 rounded-2xl bg-workspace-card border border-workspace-border p-5 shadow-xs">
      {/* Sandbox Header Strip */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-workspace-border">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-violet-50 text-violet-600 border border-violet-200">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-text-primary">
                Attachment Investigation &amp; Sandbox Detonation Lab
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-violet-100 text-violet-800 border border-violet-200">
                MicroVM Isolated · {attachmentCount > 0 ? `${attachmentCount} Attachment(s)` : 'Direct Sandbox'}
              </span>
            </div>
            <p className="text-xs text-text-muted mt-0.5">
              Automated static heuristic parsing and isolated Windows 11 Enterprise hypervisor execution
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {sandboxData && sandboxData.reports.length > 0 && (
            <div className="text-right mr-2 hidden sm:block">
              <div className="text-[10px] text-text-muted uppercase font-bold tracking-wider">Overall Verdict</div>
              <div className="text-xs font-black text-text-primary">{getVerdictBadge(sandboxData.overall_verdict)}</div>
            </div>
          )}
          <button
            onClick={fetchReports}
            className="p-2 rounded-xl bg-workspace border border-workspace-border text-text-muted hover:text-text-primary hover:bg-workspace-secondary transition-colors"
            title="Refresh Sandbox Telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {loading && !sandboxData ? (
        <div className="p-8 text-center text-xs text-text-muted flex items-center justify-center gap-2.5">
          <Loader2 className="w-4 h-4 animate-spin text-brand" />
          Connecting to hypervisor microVM and assembling attachment telemetry…
        </div>
      ) : null}

      {/* When email HAS attachments */}
      {sandboxData && sandboxData.reports.length > 0 && (
        <div className="space-y-4">
          {/* Attachment Selector Pills if multiple */}
          {sandboxData.reports.length > 1 && (
            <div className="flex items-center gap-2 overflow-x-auto pb-1">
              {sandboxData.reports.map((rep, idx) => (
                <button
                  key={rep.sha256}
                  onClick={() => { setSelectedReportIndex(idx); setDirectReport(null); }}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap border transition-all flex items-center gap-2 ${
                    selectedReportIndex === idx && !directReport
                      ? 'bg-brand/10 border-brand text-brand shadow-xs'
                      : 'bg-workspace border-workspace-border text-text-muted hover:text-text-primary'
                  }`}
                >
                  <Paperclip className="w-3.5 h-3.5" />
                  <span>{rep.attachment_name}</span>
                  <span className={`w-2 h-2 rounded-full ${rep.dynamic_detonation.verdict === 'MALICIOUS' ? 'bg-rose-500' : rep.dynamic_detonation.verdict === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                </button>
              ))}
            </div>
          )}

          {currentReport && (
            <div className="space-y-4">
              {/* Attachment Identity Banner */}
              <div className="p-4 rounded-xl bg-workspace border border-workspace-border flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-start gap-3.5">
                  <div className="p-2.5 rounded-xl bg-workspace-card border border-workspace-border text-text-primary shrink-0">
                    <FileCode className="w-5 h-5 text-brand" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2.5">
                      <h4 className="text-sm font-extrabold text-text-primary">{currentReport.attachment_name}</h4>
                      {getVerdictBadge(currentReport.dynamic_detonation.verdict)}
                    </div>
                    <div className="text-[11px] font-mono text-text-muted mt-1 flex flex-wrap gap-3">
                      <span>Size: <strong>{(currentReport.size_bytes / 1024).toFixed(1)} KB</strong></span>
                      <span>MIME: <strong>{currentReport.content_type}</strong></span>
                      <span>SHA-256: <strong className="text-text-secondary select-all">{currentReport.sha256.substring(0, 16)}…</strong></span>
                      <span>MD5: <strong className="text-text-secondary select-all">{currentReport.md5.substring(0, 12)}…</strong></span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right">
                    <div className="text-[10px] text-text-muted font-bold uppercase">Detonation Score</div>
                    <div className="text-lg font-black text-text-primary">
                      {currentReport.dynamic_detonation.detonation_score} <span className="text-xs text-text-muted">/ 100</span>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDetonate(currentReport.sha256)}
                    disabled={detonatingHash === currentReport.sha256}
                    className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-violet-600 hover:bg-violet-700 text-white text-xs font-bold transition-all shadow-xs disabled:opacity-50"
                  >
                    {detonatingHash === currentReport.sha256 ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        Detonating in VM…
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 fill-current" />
                        Re-Detonate in VM
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Subtabs: Static Analysis vs Processes vs Network vs MITRE */}
              <div className="flex items-center gap-2 border-b border-workspace-border pb-1">
                <button
                  onClick={() => setActiveSubTab('static')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${
                    activeSubTab === 'static' ? 'bg-workspace text-text-primary border border-workspace-border' : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  Static Heuristics &amp; Entropy
                </button>
                <button
                  onClick={() => setActiveSubTab('processes')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
                    activeSubTab === 'processes' ? 'bg-workspace text-text-primary border border-workspace-border' : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  Process Tree ({currentReport.dynamic_detonation.processes_spawned.length})
                </button>
                <button
                  onClick={() => setActiveSubTab('network')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
                    activeSubTab === 'network' ? 'bg-workspace text-text-primary border border-workspace-border' : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  <Network className="w-3.5 h-3.5" />
                  C2 Network Telemetry ({currentReport.dynamic_detonation.network_beacons.length})
                </button>
                <button
                  onClick={() => setActiveSubTab('mitre')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
                    activeSubTab === 'mitre' ? 'bg-workspace text-text-primary border border-workspace-border' : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  <Activity className="w-3.5 h-3.5" />
                  MITRE ATT&amp;CK ({currentReport.dynamic_detonation.mitre_attack_matrix.length})
                </button>
              </div>

              {/* Subtab 1: Static Heuristics */}
              {activeSubTab === 'static' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border space-y-1">
                      <div className="text-[10px] text-text-muted font-bold uppercase">Shannon Entropy</div>
                      <div className="text-base font-black text-text-primary">
                        {currentReport.static_analysis.entropy.toFixed(2)} <span className="text-xs text-text-muted">/ 8.00</span>
                      </div>
                      <div className="text-[10.5px] font-semibold text-text-secondary">
                        {currentReport.static_analysis.entropy_status}
                      </div>
                      <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden mt-1">
                        <div
                          className={`h-full rounded-full ${
                            currentReport.static_analysis.entropy > 7.2 ? 'bg-rose-500' : 'bg-emerald-500'
                          }`}
                          style={{ width: `${(currentReport.static_analysis.entropy / 8) * 100}%` }}
                        />
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border space-y-1">
                      <div className="text-[10px] text-text-muted font-bold uppercase">Magic File Signature</div>
                      <div className="text-xs font-mono font-bold text-text-primary mt-1 truncate">
                        {currentReport.static_analysis.magic_signature}
                      </div>
                      <div className="text-[10.5px] font-semibold">
                        {currentReport.static_analysis.is_extension_mismatch ? (
                          <span className="text-rose-600 font-bold">⚠️ Extension Mismatch Detected</span>
                        ) : (
                          <span className="text-emerald-600 font-semibold">✓ Signature Matches Extension</span>
                        )}
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border space-y-1">
                      <div className="text-[10px] text-text-muted font-bold uppercase">Macros &amp; OLE Code</div>
                      <div className="text-sm font-bold text-text-primary mt-1">
                        {currentReport.static_analysis.has_macros ? (
                          <span className="text-rose-600 font-bold">⚠️ Embedded VBA / OLE Code Found</span>
                        ) : (
                          <span className="text-emerald-600 font-semibold">✓ No Active Code Streams</span>
                        )}
                      </div>
                      <div className="text-[10px] text-text-muted">Analyzed document streams</div>
                    </div>

                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border space-y-1">
                      <div className="text-[10px] text-text-muted font-bold uppercase">MicroVM Execution Time</div>
                      <div className="text-sm font-mono font-bold text-text-primary mt-1">
                        {currentReport.dynamic_detonation.detonation_time_ms} ms
                      </div>
                      <div className="text-[10px] text-text-muted font-mono truncate">
                        {currentReport.dynamic_detonation.sandbox_env.substring(0, 30)}…
                      </div>
                    </div>
                  </div>

                  {/* YARA Rules Matches */}
                  {currentReport.static_analysis.yara_rule_matches.length > 0 && (
                    <div className="p-3.5 rounded-xl bg-workspace border border-workspace-border space-y-2">
                      <div className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                        <Search className="w-3.5 h-3.5 text-brand" />
                        <span>YARA Rule Detections ({currentReport.static_analysis.yara_rule_matches.length})</span>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {currentReport.static_analysis.yara_rule_matches.map((yr, idx) => (
                          <div
                            key={idx}
                            className="px-2.5 py-1 rounded-lg bg-workspace-card border border-workspace-border text-xs font-mono flex items-center gap-2"
                          >
                            <span className="font-bold text-rose-600">{yr.rule}</span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-100 text-rose-800 font-semibold uppercase">
                              {yr.severity}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Suspicious Extracted Strings */}
                  {currentReport.static_analysis.suspicious_string_hits.length > 0 && (
                    <div className="p-3.5 rounded-xl bg-workspace border border-workspace-border space-y-2">
                      <div className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-amber-600" />
                        <span>Suspicious Native String / API Artifacts</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                        {currentReport.static_analysis.suspicious_string_hits.map((s, idx) => (
                          <span key={idx} className="px-2 py-0.5 rounded bg-amber-50 text-amber-900 border border-amber-200">
                            {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Subtab 2: Process Tree */}
              {activeSubTab === 'processes' && (
                <div className="space-y-3">
                  <div className="p-3.5 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs space-y-2 overflow-x-auto">
                    <div className="text-slate-400 text-[10.5px] uppercase font-bold tracking-wider mb-2 flex items-center gap-2">
                      <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                      Hypervisor Process Spawn Timeline (MicroVM PID Hierarchy)
                    </div>
                    {currentReport.dynamic_detonation.processes_spawned.map((pr) => (
                      <div key={pr.pid} className="flex items-start gap-3 py-1 border-b border-slate-800/80 last:border-0">
                        <span className="text-emerald-400 font-bold shrink-0">PID {pr.pid}</span>
                        <div className="min-w-0">
                          <div className="font-semibold text-slate-200 flex items-center gap-2">
                            <span>{pr.process_name}</span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-normal">
                              {pr.status}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 break-all select-all mt-0.5">{pr.command_line}</div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Dropped Files & Registry keys */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border space-y-2">
                      <div className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                        <Database className="w-3.5 h-3.5 text-brand" />
                        <span>Dropped Files ({currentReport.dynamic_detonation.dropped_files.length})</span>
                      </div>
                      {currentReport.dynamic_detonation.dropped_files.length > 0 ? (
                        <div className="space-y-1.5">
                          {currentReport.dynamic_detonation.dropped_files.map((df, i) => (
                            <div key={i} className="p-2 rounded-lg bg-workspace-card border border-workspace-border text-xs font-mono">
                              <div className="font-bold text-rose-600 truncate">{df.path}</div>
                              <div className="text-[10.5px] text-text-muted mt-0.5 flex justify-between">
                                <span>{(df.size_bytes / 1024).toFixed(1)} KB · {df.file_type}</span>
                                <span className="font-bold text-rose-600">{df.verdict}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-xs text-text-muted">No child dropped payload files observed.</div>
                      )}
                    </div>

                    <div className="p-3 rounded-xl bg-workspace border border-workspace-border space-y-2">
                      <div className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-amber-600" />
                        <span>Registry Persistence ({currentReport.dynamic_detonation.registry_modifications.length})</span>
                      </div>
                      {currentReport.dynamic_detonation.registry_modifications.length > 0 ? (
                        <div className="space-y-1.5">
                          {currentReport.dynamic_detonation.registry_modifications.map((rm, i) => (
                            <div key={i} className="p-2 rounded-lg bg-workspace-card border border-workspace-border text-xs font-mono">
                              <div className="text-[10px] text-amber-600 font-bold uppercase">{rm.action}</div>
                              <div className="text-text-primary font-semibold break-all text-[11px]">{rm.key}</div>
                              <div className="text-text-muted text-[10.5px] truncate mt-0.5">{rm.value}</div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-xs text-text-muted">No persistence registry keys written.</div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Subtab 3: Network C2 Beacons */}
              {activeSubTab === 'network' && (
                <div className="space-y-3">
                  {currentReport.dynamic_detonation.network_beacons.length > 0 ? (
                    <div className="overflow-x-auto border border-workspace-border rounded-xl">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-workspace text-text-muted uppercase text-[10px] border-b border-workspace-border font-bold">
                          <tr>
                            <th className="p-2.5">Destination Host / IP</th>
                            <th className="p-2.5">Port / Proto</th>
                            <th className="p-2.5">Sinkhole Telemetry</th>
                            <th className="p-2.5">Forensic Observations</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-workspace-border font-mono text-[11px]">
                          {currentReport.dynamic_detonation.network_beacons.map((nb, i) => (
                            <tr key={i} className="hover:bg-workspace/50">
                              <td className="p-2.5 font-bold text-text-primary select-all">
                                {nb.destination_host} ({nb.destination_ip})
                              </td>
                              <td className="p-2.5 text-text-secondary">{nb.port} / {nb.protocol}</td>
                              <td className="p-2.5">
                                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
                                  {nb.status}
                                </span>
                              </td>
                              <td className="p-2.5 text-text-muted">{nb.notes}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="p-6 text-center text-xs text-text-muted rounded-xl bg-workspace border border-workspace-border">
                      No external DNS lookups or outbound C2 connection attempts were captured during execution.
                    </div>
                  )}
                </div>
              )}

              {/* Subtab 4: MITRE ATT&CK Matrix */}
              {activeSubTab === 'mitre' && (
                <div className="space-y-3">
                  {currentReport.dynamic_detonation.mitre_attack_matrix.length > 0 ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                      {currentReport.dynamic_detonation.mitre_attack_matrix.map((mt, i) => (
                        <div key={i} className="p-3 rounded-xl bg-workspace border border-workspace-border space-y-1">
                          <div className="text-[10px] text-brand font-bold uppercase tracking-wider">{mt.tactic}</div>
                          <div className="text-xs font-mono font-bold text-rose-600">{mt.technique_id}</div>
                          <div className="text-xs text-text-primary font-semibold">{mt.name}</div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-6 text-center text-xs text-text-muted rounded-xl bg-workspace border border-workspace-border">
                      No MITRE ATT&amp;CK threat techniques were triggered by this attachment payload.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* When email has NO attachments, or analyst wants to test any standalone file */}
      {(!sandboxData || sandboxData.reports.length === 0) && (
        <div className="p-6 rounded-2xl bg-gradient-to-b from-workspace to-workspace-card border border-workspace-border text-center space-y-4">
          <div className="max-w-md mx-auto space-y-2">
            <div className="w-12 h-12 rounded-2xl bg-violet-50 text-violet-600 border border-violet-200 flex items-center justify-center mx-auto mb-2">
              <Cpu className="w-6 h-6" />
            </div>
            <h4 className="text-sm font-bold text-text-primary">
              Zero Attachments Enclosed in Email Payload
            </h4>
            <p className="text-xs text-text-muted leading-relaxed">
              This message did not contain enclosed MIME file attachments. You can test any suspicious binary, script, or document directly in the isolated MicroVM sandbox environment.
            </p>
          </div>

          <div className="max-w-sm mx-auto">
            <label className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-700 text-white text-xs font-bold transition-all cursor-pointer shadow-xs hover:shadow-sm">
              {directLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <UploadCloud className="w-3.5 h-3.5" />}
              {directLoading ? 'Detonating File in Sandbox…' : 'Upload File to Detonate in Sandbox'}
              <input
                type="file"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleDirectFileUpload(f);
                }}
                className="hidden"
                disabled={directLoading}
              />
            </label>
            <div className="text-[10.5px] text-text-muted mt-2">
              Supports .exe, .scr, .pdf, .docx, .vbs, .js, .iso (Max 50MB)
            </div>
          </div>

          {directError && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs max-w-md mx-auto">
              {directError}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
