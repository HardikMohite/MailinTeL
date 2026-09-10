import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Building2,
  Users,
  UserPlus,
  ShieldCheck,
  Loader2,
  AlertTriangle,
  Copy,
  Check,
  X,
  MoreVertical,
  Mail,
  FileText,
  Download,
  Search,
  RefreshCw,
  Eye,
  Inbox,
  Flame,
  LayoutDashboard,
  Activity,
} from 'lucide-react';
import { DashboardView } from '../components/dashboard/DashboardView';
import { OrganizationView } from '../components/settings/OrganizationView';
import {
  listPlatformOrganizations,
  listPlatformUsers,
  invitePlatformUser,
  updatePlatformUserRole,
  deactivatePlatformUser,
  listEmails,
  getEvidenceDownloadUrl,
  EmailDetailResponse,
  OrganizationItem,
  PlatformMember,
} from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useApiErrorHandler } from '../hooks/useApiErrorHandler';
import { StatusBadge } from '../components/common/StatusBadge';
import { ALL_ASSIGNABLE_ROLES, RoleCode } from '../constants/rbac';


const ROLE_LABELS: Record<string, string> = {
  INSTITUTION_ADMIN: 'Institution Admin',
  SYSTEM_ADMIN: 'System Admin',
  SECURITY_ANALYST: 'Security Analyst',
  CYBER_CELL_INVESTIGATOR: 'Cyber Cell Investigator',
  USER: 'User',
};
const roleLabel = (code: string) => ROLE_LABELS[code] || code;
const fmtDateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : 'Never');

export interface PlatformAdminViewProps {
  onSelectEmail?: (emailId: string) => void;
  onOpenReport?: (emailId: string) => void;
  onAnalyze?: () => void;
  onExploreGraph?: () => void;
}

export const PlatformAdminView: React.FC<PlatformAdminViewProps> = ({
  onSelectEmail,
  onOpenReport,
  onAnalyze,
  onExploreGraph,
}) => {
  const { user, isCrossOrg } = useAuth();
  const parseApiError = useApiErrorHandler();
  const canAccess = isCrossOrg() && user?.role === 'SYSTEM_ADMIN';

  // Navigation sub-tabs
  const [activeSection, setActiveSection] = useState<'overview' | 'phishing' | 'organizations' | 'users'>('overview');

  // --- Phishing Email Ingestion & Triage Queue ----------------------
  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [emailsLoading, setEmailsLoading] = useState(true);
  const [emailsError, setEmailsError] = useState<string | null>(null);
  const [emailSearch, setEmailSearch] = useState('');
  const [emailOrgFilter, setEmailOrgFilter] = useState('');
  const [emailQualFilter, setEmailQualFilter] = useState('');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  // --- Organizations (cached for cross-section filters) -------------
  const [organizations, setOrganizations] = useState<OrganizationItem[]>([]);

  // --- Cross-org users -------------------------------------------------
  const [members, setMembers] = useState<PlatformMember[]>([]);
  const [membersLoading, setMembersLoading] = useState(true);
  const [membersError, setMembersError] = useState<string | null>(null);
  const [orgFilter, setOrgFilter] = useState('');

  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteName, setInviteName] = useState('');
  const [inviteOrgId, setInviteOrgId] = useState('');
  const [inviteRole, setInviteRole] = useState<RoleCode>('SECURITY_ANALYST');
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [issuedCredential, setIssuedCredential] = useState<{ email: string; password: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const [busyMemberId, setBusyMemberId] = useState<string | null>(null);
  const [openMenuId, setOpenMenuId] = useState<string | null>(null);

  // Data Loaders
  const loadEmails = useCallback(async () => {
    setEmailsLoading(true);
    setEmailsError(null);
    try {
      const data = await listEmails(
        0,
        100,
        undefined,
        emailQualFilter || undefined,
        emailOrgFilter || undefined,
        true
      );
      setEmails(data.items || []);
    } catch (err) {
      setEmailsError(parseApiError(err).message);
    } finally {
      setEmailsLoading(false);
    }
  }, [emailQualFilter, emailOrgFilter, parseApiError]);

  const loadOrganizations = useCallback(async () => {
    try {
      const data = await listPlatformOrganizations();
      setOrganizations(data);
    } catch {
      // Non-fatal fallback for dropdown filters
    }
  }, []);

  const loadMembers = useCallback(
    async (orgId: string) => {
      setMembersLoading(true);
      setMembersError(null);
      try {
        const data = await listPlatformUsers(orgId || undefined);
        setMembers(data);
      } catch (err) {
        setMembersError(parseApiError(err).message);
      } finally {
        setMembersLoading(false);
      }
    },
    [parseApiError]
  );

  useEffect(() => {
    if (!canAccess) return;
    loadEmails();
    loadOrganizations();
  }, [canAccess, loadEmails, loadOrganizations]);

  useEffect(() => {
    if (!canAccess) return;
    loadMembers(orgFilter);
  }, [canAccess, orgFilter, loadMembers]);

  // Phishing Emails Filtered View — strictly excludes safe / benign emails
  const SAFE_STATUSES = useMemo(() => new Set(['NORMAL', 'SAFE', 'BENIGN']), []);

  const phishingEmails = useMemo(() => {
    return emails.filter((e) => !SAFE_STATUSES.has((e.qualification_status || '').toUpperCase()));
  }, [emails, SAFE_STATUSES]);

  const filteredEmails = useMemo(() => {
    const q = emailSearch.toLowerCase().trim();
    if (!q) return phishingEmails;
    return phishingEmails.filter(
      (e) =>
        e.subject?.toLowerCase().includes(q) ||
        e.sender_address?.toLowerCase().includes(q) ||
        e.sender_display_name?.toLowerCase().includes(q) ||
        e.sha256_hash?.toLowerCase().includes(q) ||
        e.original_filename?.toLowerCase().includes(q)
    );
  }, [phishingEmails, emailSearch]);

  // Email KPI metrics (Phishing & Threats only)
  const emailStats = useMemo(() => {
    const total = phishingEmails.length;
    const criticalOrHigh = phishingEmails.filter(
      (e) =>
        e.qualification_status === 'CRITICAL' ||
        e.qualification_status === 'HIGH' ||
        e.qualification_status === 'MALICIOUS' ||
        e.qualification_status === 'HIGH_RISK'
    ).length;
    const suspicious = phishingEmails.filter(
      (e) => e.qualification_status === 'SUSPICIOUS' || e.qualification_status === 'MEDIUM'
    ).length;
    const investigating = phishingEmails.filter(
      (e) =>
        e.qualification_status === 'QUALIFIED_FOR_INVESTIGATION' ||
        e.analysis_status === 'PENDING' ||
        e.analysis_status === 'PROCESSING'
    ).length;
    return { total, criticalOrHigh, suspicious, investigating };
  }, [phishingEmails]);

  const handleDownloadEml = async (email: EmailDetailResponse) => {
    if (!email.evidence_id) return;
    setDownloadingId(email.id);
    try {
      const res = await getEvidenceDownloadUrl(email.evidence_id);
      if (res.download_url) {
        window.open(res.download_url, '_blank');
      }
    } catch (err) {
      alert(`Could not generate download URL: ${parseApiError(err).message}`);
    } finally {
      setDownloadingId(null);
    }
  };

  if (!canAccess) {
    return (
      <div className="bg-workspace-card border border-workspace-border rounded-xl p-10 text-center">
        <AlertTriangle className="w-6 h-6 text-severity-critical mx-auto mb-2" />
        <p className="text-[13px] text-text-secondary">
          Platform administration is only available to System Administrators.
        </p>
      </div>
    );
  }



  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInviteError(null);
    if (!inviteOrgId) {
      setInviteError('Choose an organization to invite this user into.');
      return;
    }
    setInviting(true);
    try {
      const result = await invitePlatformUser({
        email: inviteEmail.trim(),
        full_name: inviteName.trim() || undefined,
        organization_id: inviteOrgId,
        role_code: inviteRole,
      });
      setIssuedCredential({ email: result.user.email, password: result.temporary_password });
      setInviteEmail('');
      setInviteName('');
      setInviteRole('SECURITY_ANALYST');
      setShowInvite(false);
      await loadMembers(orgFilter);
    } catch (err) {
      setInviteError(parseApiError(err).message);
    } finally {
      setInviting(false);
    }
  };

  const handleRoleChange = async (member: PlatformMember, role: RoleCode) => {
    setOpenMenuId(null);
    setBusyMemberId(member.id);
    setMembersError(null);
    try {
      await updatePlatformUserRole(member.id, role);
      await loadMembers(orgFilter);
    } catch (err) {
      setMembersError(parseApiError(err).message);
    } finally {
      setBusyMemberId(null);
    }
  };

  const handleDeactivate = async (member: PlatformMember) => {
    setOpenMenuId(null);
    if (!window.confirm(`Deactivate ${member.email}? They will immediately lose access.`)) return;
    setBusyMemberId(member.id);
    setMembersError(null);
    try {
      await deactivatePlatformUser(member.id);
      await loadMembers(orgFilter);
    } catch (err) {
      setMembersError(parseApiError(err).message);
    } finally {
      setBusyMemberId(null);
    }
  };

  const copyPassword = () => {
    if (!issuedCredential) return;
    navigator.clipboard?.writeText(issuedCredential.password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Command Bar */}
      <div className="bg-workspace-card border border-workspace-border rounded-xl p-5 flex flex-wrap items-center justify-between gap-4 shadow-sm">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand-soft border border-brand/20 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-6 h-6 text-brand" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-text-primary tracking-tight">Platform Administration</h2>
              <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-brand text-white">
                Admin Console
              </span>
            </div>
            <p className="text-xs text-text-muted mt-0.5">
              Cross-organization governance, triage oversight & system forensic operations.
            </p>
          </div>
        </div>

        {/* Navigation Switcher Pills */}
        <div className="flex items-center gap-1 bg-workspace p-1 rounded-xl border border-workspace-border text-xs font-medium">
          <button
            onClick={() => setActiveSection('overview')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
              activeSection === 'overview'
                ? 'bg-workspace-card text-brand font-semibold shadow-xs'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <LayoutDashboard className="w-3.5 h-3.5" />
            <span>System Overview</span>
          </button>
          <button
            onClick={() => setActiveSection('phishing')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
              activeSection === 'phishing'
                ? 'bg-workspace-card text-brand font-semibold shadow-xs'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Phishing Triage ({emailStats.total})</span>
          </button>
          <button
            onClick={() => setActiveSection('organizations')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
              activeSection === 'organizations'
                ? 'bg-workspace-card text-brand font-semibold shadow-xs'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Building2 className="w-3.5 h-3.5" />
            <span>Organizations ({organizations.length})</span>
          </button>
          <button
            onClick={() => setActiveSection('users')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
              activeSection === 'users'
                ? 'bg-workspace-card text-brand font-semibold shadow-xs'
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Users className="w-3.5 h-3.5" />
            <span>Users & Access</span>
          </button>
        </div>
      </div>

      {/* SECTION 0: SYSTEM OVERVIEW & TELEMETRY */}
      {activeSection === 'overview' && (
        <DashboardView
          onAnalyze={onAnalyze || (() => {})}
          onExploreGraph={onExploreGraph || (() => {})}
          onSelectEmail={onSelectEmail || (() => {})}
        />
      )}

      {/* SECTION 1: ALL PHISHING EMAILS & TRIAGE QUEUE */}
      {activeSection === 'phishing' && (
        <section className="space-y-4">
          {/* KPI Metrics Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            <div
              style={{ '--kpi-accent': '#2563B8' } as React.CSSProperties}
              className="kpi-card p-4 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                  Total Phishing Threats
                </span>
                <div className="w-8 h-8 rounded-lg bg-brand-soft text-brand flex items-center justify-center shrink-0">
                  <Inbox className="w-4 h-4" />
                </div>
              </div>
              <div>
                <div className="text-2xl font-extrabold text-text-primary tabular-nums tracking-tight">
                  {emailStats.total}
                </div>
                <div className="text-[10.5px] text-text-muted mt-1">Cross-tenant threat queue</div>
              </div>
            </div>

            <div
              style={{ '--kpi-accent': '#C73A32' } as React.CSSProperties}
              className="kpi-card p-4 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-rose-600">
                  High / Critical Phishing
                </span>
                <div className="w-8 h-8 rounded-lg bg-rose-50 text-rose-600 flex items-center justify-center shrink-0">
                  <Flame className="w-4 h-4" />
                </div>
              </div>
              <div>
                <div className="text-2xl font-extrabold text-rose-700 tabular-nums tracking-tight">
                  {emailStats.criticalOrHigh}
                </div>
                <div className="text-[10.5px] text-rose-600/80 mt-1">Confirmed or critical risk</div>
              </div>
            </div>

            <div
              style={{ '--kpi-accent': '#D88916' } as React.CSSProperties}
              className="kpi-card p-4 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-amber-600">
                  Suspicious Ingestions
                </span>
                <div className="w-8 h-8 rounded-lg bg-amber-50 text-amber-600 flex items-center justify-center shrink-0">
                  <AlertTriangle className="w-4 h-4" />
                </div>
              </div>
              <div>
                <div className="text-2xl font-extrabold text-amber-700 tabular-nums tracking-tight">
                  {emailStats.suspicious}
                </div>
                <div className="text-[10.5px] text-amber-600/80 mt-1">Requires analyst triage</div>
              </div>
            </div>

            <div
              style={{ '--kpi-accent': '#0284C7' } as React.CSSProperties}
              className="kpi-card p-4 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-sky-600">
                  Active Investigations
                </span>
                <div className="w-8 h-8 rounded-lg bg-sky-50 text-sky-600 flex items-center justify-center shrink-0">
                  <Activity className="w-4 h-4" />
                </div>
              </div>
              <div>
                <div className="text-2xl font-extrabold text-sky-700 tabular-nums tracking-tight">
                  {emailStats.investigating}
                </div>
                <div className="text-[10.5px] text-sky-600/80 mt-1">Active forensic cases</div>
              </div>
            </div>
          </div>

          {/* Email Filter Bar */}
          <div className="bg-workspace-card border border-workspace-border rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[280px]">
              {/* Search Bar */}
              <div className="relative flex-1 min-w-[220px]">
                <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={emailSearch}
                  onChange={(e) => setEmailSearch(e.target.value)}
                  placeholder="Search subject, sender address, SHA-256 hash..."
                  className="w-full pl-9 pr-3.5 py-2 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-brand/20 focus:border-brand transition-all"
                />
              </div>

              {/* Organization Filter */}
              <select
                value={emailOrgFilter}
                onChange={(e) => setEmailOrgFilter(e.target.value)}
                className="px-3 py-2 text-xs bg-workspace border border-workspace-border rounded-lg text-text-secondary focus:outline-none focus:ring-2 focus:ring-brand/20"
              >
                <option value="">All Organizations</option>
                {organizations.map((org) => (
                  <option key={org.id} value={org.id}>
                    {org.name}
                  </option>
                ))}
              </select>

              {/* Threat Status Filter */}
              <select
                value={emailQualFilter}
                onChange={(e) => setEmailQualFilter(e.target.value)}
                className="px-3 py-2 text-xs bg-workspace border border-workspace-border rounded-lg text-text-secondary focus:outline-none focus:ring-2 focus:ring-brand/20"
              >
                <option value="">All Threat Verdicts</option>
                <option value="CRITICAL">Critical Phishing</option>
                <option value="HIGH">High Threat</option>
                <option value="SUSPICIOUS">Suspicious</option>
              </select>
            </div>

            <button
              onClick={() => loadEmails()}
              disabled={emailsLoading}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-workspace-border text-xs font-medium text-text-secondary hover:bg-workspace transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${emailsLoading ? 'animate-spin' : ''}`} />
              <span>Refresh Queue</span>
            </button>
          </div>

          {/* Emails Table */}
          {emailsError && (
            <div className="bg-rose-50 border border-rose-200 rounded-xl p-4 text-xs text-rose-800 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{emailsError}</span>
            </div>
          )}

          <div className="bg-workspace-card border border-workspace-border rounded-xl overflow-hidden shadow-xs">
            {emailsLoading ? (
              <div className="p-12 flex flex-col items-center justify-center text-text-muted text-xs gap-2">
                <Loader2 className="w-5 h-5 text-brand animate-spin" />
                <span>Loading global phishing queue…</span>
              </div>
            ) : filteredEmails.length === 0 ? (
              <div className="p-12 text-center text-text-muted text-xs">
                No phishing emails match the active filter criteria.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-workspace-header border-b border-workspace-border text-[11px] font-semibold uppercase tracking-wider text-text-muted select-none">
                    <tr>
                      <th className="px-4 py-3">Subject & Evidence</th>
                      <th className="px-4 py-3">Sender</th>
                      <th className="px-4 py-3">Threat Verdict</th>
                      <th className="px-4 py-3">Pipeline Stage</th>
                      <th className="px-4 py-3">Ingested</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-workspace-border">
                    {filteredEmails.map((email) => {
                      const isHighThreat =
                        email.qualification_status === 'CRITICAL' ||
                        email.qualification_status === 'HIGH' ||
                        email.qualification_status === 'MALICIOUS';
                      const isSuspicious =
                        email.qualification_status === 'SUSPICIOUS' || email.qualification_status === 'MEDIUM';

                      return (
                        <tr
                          key={email.id}
                          className="hover:bg-workspace-secondary/40 transition-colors group"
                        >
                          {/* Subject & Hash */}
                          <td className="px-4 py-3 max-w-[280px]">
                            <button
                              onClick={() => onSelectEmail && onSelectEmail(email.id)}
                              className="font-semibold text-text-primary hover:text-brand truncate block text-left w-full group-hover:underline"
                              title={email.subject || 'No Subject'}
                            >
                              {email.subject || 'No Subject'}
                            </button>
                            <div className="text-[11px] text-text-muted font-mono mt-0.5 truncate">
                              {email.sha256_hash ? `SHA256: ${email.sha256_hash.slice(0, 16)}…` : 'Raw EML ingested'}
                            </div>
                          </td>

                          {/* Sender */}
                          <td className="px-4 py-3">
                            <div className="font-medium text-text-primary truncate max-w-[200px]">
                              {email.sender_display_name || email.sender_address || 'Unknown Sender'}
                            </div>
                            {email.sender_display_name && email.sender_address && (
                              <div className="text-[11px] text-text-muted truncate max-w-[200px]">
                                {email.sender_address}
                              </div>
                            )}
                          </td>

                          {/* Threat Verdict */}
                          <td className="px-4 py-3">
                            <span
                              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${
                                isHighThreat
                                  ? 'bg-rose-100 text-rose-800 border border-rose-200'
                                  : isSuspicious
                                  ? 'bg-amber-100 text-amber-800 border border-amber-200'
                                  : 'bg-sky-100 text-sky-800 border border-sky-200'
                              }`}
                            >
                              <span
                                className={`w-1.5 h-1.5 rounded-full ${
                                  isHighThreat ? 'bg-rose-600' : isSuspicious ? 'bg-amber-600' : 'bg-sky-600'
                                }`}
                              />
                              {email.qualification_status || 'UNQUALIFIED'}
                            </span>
                          </td>

                          {/* Analysis Stage */}
                          <td className="px-4 py-3">
                            <span className="text-[11px] font-medium text-slate-600">
                              {email.analysis_status || 'COMPLETED'}
                            </span>
                          </td>

                          {/* Date */}
                          <td className="px-4 py-3 text-text-muted text-[11px] whitespace-nowrap">
                            {fmtDateTime(email.created_at)}
                          </td>

                          {/* Actions */}
                          <td className="px-4 py-3 text-right whitespace-nowrap">
                            <div className="inline-flex items-center gap-1.5">
                              {onSelectEmail && (
                                <button
                                  onClick={() => onSelectEmail(email.id)}
                                  title="Inspect in Analysis Workspace"
                                  className="p-1.5 rounded-lg border border-workspace-border hover:bg-brand-soft hover:text-brand text-slate-600 transition-colors"
                                >
                                  <Eye className="w-3.5 h-3.5" />
                                </button>
                              )}

                              {onOpenReport && (
                                <button
                                  onClick={() => onOpenReport(email.id)}
                                  title="Open Forensic Report"
                                  className="p-1.5 rounded-lg border border-workspace-border hover:bg-brand-soft hover:text-brand text-slate-600 transition-colors"
                                >
                                  <FileText className="w-3.5 h-3.5" />
                                </button>
                              )}

                              {email.evidence_id && (
                                <button
                                  onClick={() => handleDownloadEml(email)}
                                  disabled={downloadingId === email.id}
                                  title="Download Raw EML"
                                  className="p-1.5 rounded-lg border border-workspace-border hover:bg-brand-soft hover:text-brand text-slate-600 transition-colors disabled:opacity-50"
                                >
                                  {downloadingId === email.id ? (
                                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                  ) : (
                                    <Download className="w-3.5 h-3.5" />
                                  )}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      )}

      {/* SECTION 2: ORGANIZATIONS */}
      {activeSection === 'organizations' && (
        <OrganizationView />
      )}

      {/* SECTION 3: USERS ACROSS ORGANIZATIONS */}
      {activeSection === 'users' && (
        <section className="space-y-3">

          {issuedCredential && (
            <div className="bg-severity-safe-soft border border-severity-safe/30 rounded-xl p-4 flex items-start justify-between gap-4">
              <div className="text-[13px] text-text-primary">
                <div className="font-semibold flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-severity-safe" />
                  Account created for {issuedCredential.email}
                </div>
                <p className="text-text-secondary mt-1">
                  There&apos;s no email delivery yet in this build — share this one-time password with them directly. It
                  won&apos;t be shown again.
                </p>
                <div className="mt-2 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-workspace-card border border-workspace-border font-mono text-[13px]">
                  <span>{issuedCredential.password}</span>
                  <button onClick={copyPassword} className="text-text-muted hover:text-text-primary">
                    {copied ? <Check className="w-4 h-4 text-severity-safe" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <button onClick={() => setIssuedCredential(null)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {showInvite && (
            <div className="bg-workspace-card border border-workspace-border rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-[13.5px] font-semibold text-text-primary">Invite platform user</h4>
                <button onClick={() => setShowInvite(false)} className="text-text-muted hover:text-text-primary">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <form onSubmit={handleInvite} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-[12px] font-medium text-text-secondary mb-1">Email</label>
                  <input
                    type="email"
                    required
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-workspace-border text-[13px] focus:outline-none focus:ring-2 focus:ring-brand/30"
                    placeholder="analyst@org.com"
                  />
                </div>
                <div>
                  <label className="block text-[12px] font-medium text-text-secondary mb-1">Full name</label>
                  <input
                    type="text"
                    value={inviteName}
                    onChange={(e) => setInviteName(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-workspace-border text-[13px] focus:outline-none focus:ring-2 focus:ring-brand/30"
                    placeholder="Alex Chen"
                  />
                </div>
                <div>
                  <label className="block text-[12px] font-medium text-text-secondary mb-1">Organization</label>
                  <select
                    required
                    value={inviteOrgId}
                    onChange={(e) => setInviteOrgId(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-workspace-border text-[13px] bg-workspace focus:outline-none focus:ring-2 focus:ring-brand/30"
                  >
                    <option value="">Select organization...</option>
                    {organizations.map((org) => (
                      <option key={org.id} value={org.id}>
                        {org.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-[12px] font-medium text-text-secondary mb-1">Role</label>
                  <select
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value as RoleCode)}
                    className="w-full px-3 py-2 rounded-lg border border-workspace-border text-[13px] bg-workspace focus:outline-none focus:ring-2 focus:ring-brand/30"
                  >
                    {ALL_ASSIGNABLE_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {roleLabel(r)}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="sm:col-span-2 flex items-center gap-3">
                  <button
                    type="submit"
                    disabled={inviting || !inviteEmail.trim() || !inviteOrgId}
                    className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-lg bg-brand text-white text-[13px] font-medium hover:bg-brand-hover transition-colors disabled:opacity-50"
                  >
                    {inviting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    Create user
                  </button>
                  {inviteError && (
                    <span className="text-[12.5px] text-severity-critical flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      {inviteError}
                    </span>
                  )}
                </div>
              </form>
            </div>
          )}

          {membersError && (
            <div className="bg-severity-critical-soft border border-severity-critical/30 rounded-xl p-4 flex items-center gap-2 text-[13px] text-severity-critical">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {membersError}
            </div>
          )}

          <div className="bg-workspace-card border border-workspace-border rounded-xl overflow-hidden shadow-xs">
            <div className="px-4 py-3 border-b border-workspace-border flex items-center justify-between flex-wrap gap-3">
              <span className="text-xs font-semibold text-text-muted uppercase tracking-wider">
                All Users ({members.length})
              </span>
              <div className="flex items-center gap-2.5">
                <select
                  value={orgFilter}
                  onChange={(e) => setOrgFilter(e.target.value)}
                  className="px-2.5 py-1.5 bg-workspace border border-workspace-border rounded-lg text-xs text-text-secondary focus:outline-none focus:ring-2 focus:ring-brand/20"
                >
                  <option value="">All organizations</option>
                  {organizations.map((org) => (
                    <option key={org.id} value={org.id}>
                      {org.name}
                    </option>
                  ))}
                </select>
                <button
                  onClick={() => {
                    setShowInvite(true);
                    setInviteError(null);
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand text-white text-xs font-medium hover:bg-brand-hover transition-colors"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  Invite user
                </button>
              </div>
            </div>
            {membersLoading ? (
              <div className="p-10 flex items-center justify-center text-text-muted text-[13px] gap-2">
                <Loader2 className="w-4 h-4 animate-spin" /> Loading users...
              </div>
            ) : members.length === 0 ? (
              <div className="p-10 text-center text-text-muted text-[13px]">No users found for this organization.</div>
            ) : (
              <table className="w-full text-[13px]">
                <thead className="bg-workspace-header border-b border-workspace-border">
                  <tr className="text-left text-text-muted text-[11.5px] uppercase tracking-wide">
                    <th className="px-4 py-2.5 font-semibold">User</th>
                    <th className="px-4 py-2.5 font-semibold">Organization</th>
                    <th className="px-4 py-2.5 font-semibold">Role</th>
                    <th className="px-4 py-2.5 font-semibold">Status</th>
                    <th className="px-4 py-2.5 font-semibold">Last login</th>
                    <th className="px-4 py-2.5 text-right font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {members.map((m) => (
                    <tr key={m.id} className="border-b border-workspace-border last:border-0 hover:bg-workspace-secondary/50">
                      <td className="px-4 py-3">
                        <div className="font-medium text-text-primary">{m.full_name || m.email}</div>
                        {m.full_name && <div className="text-[12px] text-text-muted">{m.email}</div>}
                      </td>
                      <td className="px-4 py-3 text-text-secondary">{m.organization_name || '—'}</td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11.5px] font-medium bg-brand-soft text-brand">
                          {roleLabel(m.role)}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge type="severity" value={m.account_status === 'ACTIVE' ? 'safe' : 'critical'} label={m.account_status} size="sm" />
                      </td>
                      <td className="px-4 py-3 text-text-muted">{fmtDateTime(m.last_login_at)}</td>
                      <td className="px-4 py-3 text-right relative">
                        <button
                          onClick={() => setOpenMenuId(openMenuId === m.id ? null : m.id)}
                          disabled={busyMemberId === m.id || m.id === user?.id}
                          className="p-1.5 rounded-lg hover:bg-workspace text-text-secondary disabled:opacity-40"
                          title={m.id === user?.id ? "You cannot modify your own account" : "Manage user"}
                        >
                          {busyMemberId === m.id ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            <MoreVertical className="w-4 h-4" />
                          )}
                        </button>
                        {openMenuId === m.id && (
                          <div className="absolute right-4 top-10 w-48 bg-workspace-card border border-workspace-border rounded-lg shadow-lg z-10 py-1 text-left">
                            <div className="px-3 py-1 text-[11px] font-semibold text-text-muted uppercase">Change role</div>
                            {ALL_ASSIGNABLE_ROLES.map((r) => (
                              <button
                                key={r}
                                onClick={() => handleRoleChange(m, r)}
                                disabled={m.role === r}
                                className="w-full text-left px-3 py-1.5 text-[12.5px] hover:bg-workspace disabled:opacity-40"
                              >
                                {roleLabel(r)} {m.role === r && '✓'}
                              </button>
                            ))}
                            <div className="border-t border-workspace-border my-1" />
                            <button
                              onClick={() => handleDeactivate(m)}
                              disabled={m.account_status === 'DEACTIVATED'}
                              className="w-full text-left px-3 py-1.5 text-[12.5px] text-severity-critical hover:bg-severity-critical-soft disabled:opacity-40"
                            >
                              Deactivate account
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      )}
    </div>
  );
};

export default PlatformAdminView;
