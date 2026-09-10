import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Users,
  UserPlus,
  Shield,
  ShieldCheck,
  Search,
  RefreshCw,
  Loader2,
  AlertTriangle,
  Copy,
  Check,
  X,
  Building2,
  Lock,
  UserCheck,
  Mail,
  Calendar,
  History,
  Activity,
  Info,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import {
  listPlatformUsers,
  listPlatformOrganizations,
  invitePlatformUser,
  updatePlatformUserRole,
  deactivatePlatformUser,
  listOrgMembers,
  inviteOrgMember,
  updateOrgMemberRole,
  deactivateOrgMember,
  listPlatformAuditLog,
  OrgMember,
  OrganizationItem,
  AuditLogEntry,
  AssignableRole,
} from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { useApiErrorHandler } from '../../hooks/useApiErrorHandler';
import { StatusBadge } from '../common/StatusBadge';
import { ALL_ASSIGNABLE_ROLES, RoleCode } from '../../constants/rbac';

const ROLE_LABELS: Record<string, string> = {
  INSTITUTION_ADMIN: 'Institution Admin',
  SYSTEM_ADMIN: 'System Admin',
  SECURITY_ANALYST: 'Security Analyst',
  CYBER_CELL_INVESTIGATOR: 'Cyber Cell Investigator',
  USER: 'User',
};

const roleLabel = (code: string) => ROLE_LABELS[code] || code;

const roleBadgeClass = (code: string) => {
  switch (code) {
    case 'SYSTEM_ADMIN':
      return 'bg-purple-100 text-purple-800 border-purple-200';
    case 'INSTITUTION_ADMIN':
      return 'bg-amber-100 text-amber-800 border-amber-200';
    case 'CYBER_CELL_INVESTIGATOR':
      return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    case 'SECURITY_ANALYST':
      return 'bg-sky-100 text-sky-800 border-sky-200';
    default:
      return 'bg-slate-100 text-slate-700 border-slate-200';
  }
};

const actionBadgeClass = (action: string) => {
  const act = action.toUpperCase();
  if (act.includes('LOGIN') || act.includes('AUTH')) {
    return 'bg-emerald-50 text-emerald-700 border-emerald-200';
  }
  if (act.includes('DELETE') || act.includes('DEACTIVATE')) {
    return 'bg-rose-50 text-rose-700 border-rose-200';
  }
  if (act.includes('ROLE') || act.includes('UPDATE')) {
    return 'bg-amber-50 text-amber-700 border-amber-200';
  }
  if (act.includes('INVITE') || act.includes('CREATE')) {
    return 'bg-blue-50 text-blue-700 border-blue-200';
  }
  return 'bg-slate-50 text-slate-700 border-slate-200';
};

const fmtDateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : 'Never');

interface GenericUserItem extends OrgMember {
  organization_id?: string;
  organization_name?: string;
}

export const UserPanelView: React.FC = () => {
  const { user, isCrossOrg } = useAuth();
  const parseApiError = useApiErrorHandler();
  const isSysAdmin = isCrossOrg() && user?.role === 'SYSTEM_ADMIN';

  const [users, setUsers] = useState<GenericUserItem[]>([]);
  const [organizations, setOrganizations] = useState<OrganizationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & search
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedOrg, setSelectedOrg] = useState('');
  const [selectedRole, setSelectedRole] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');

  // Invite modal
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteName, setInviteName] = useState('');
  const [inviteOrgId, setInviteOrgId] = useState('');
  const [inviteRole, setInviteRole] = useState<RoleCode>('SECURITY_ANALYST');
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [issuedCredential, setIssuedCredential] = useState<{ email: string; password: string } | null>(null);
  const [copied, setCopied] = useState(false);

  // Action menu & busy states
  const [busyUserId, setBusyUserId] = useState<string | null>(null);

  // Double-clicked user audit logs state
  const [selectedAuditUser, setSelectedAuditUser] = useState<GenericUserItem | null>(null);
  const [userAuditLogs, setUserAuditLogs] = useState<AuditLogEntry[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [auditSearchQuery, setAuditSearchQuery] = useState('');
  const [auditActionFilter, setAuditActionFilter] = useState('');
  const [expandedLogIds, setExpandedLogIds] = useState<Set<string>>(new Set());

  // Load organizations
  const loadOrgs = useCallback(async () => {
    if (!isSysAdmin) return;
    try {
      const data = await listPlatformOrganizations();
      setOrganizations(data);
    } catch {
      // Non-fatal if organization list fails
    }
  }, [isSysAdmin]);

  // Load users
  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (isSysAdmin) {
        const data = await listPlatformUsers(selectedOrg || undefined);
        setUsers(data);
      } else {
        const data = await listOrgMembers();
        setUsers(data);
      }
    } catch (err) {
      setError(parseApiError(err).message);
    } finally {
      setLoading(false);
    }
  }, [isSysAdmin, selectedOrg, parseApiError]);

  useEffect(() => {
    loadOrgs();
  }, [loadOrgs]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  // Open audit modal for a user (on double click or action button)
  const handleOpenAuditModal = useCallback(async (targetUser: GenericUserItem) => {
    setSelectedAuditUser(targetUser);
    setAuditSearchQuery('');
    setAuditActionFilter('');
    setExpandedLogIds(new Set());
    setAuditLoading(true);
    setAuditError(null);
    try {
      const data = await listPlatformAuditLog({
        actor_user_id: targetUser.id,
        limit: 250,
      });
      setUserAuditLogs(data);
    } catch (err) {
      setAuditError(parseApiError(err).message || 'Failed to retrieve audit log entries for this user.');
    } finally {
      setAuditLoading(false);
    }
  }, [parseApiError]);

  // Reload current user's audit logs
  const handleRefreshUserAudit = useCallback(async () => {
    if (!selectedAuditUser) return;
    setAuditLoading(true);
    setAuditError(null);
    try {
      const data = await listPlatformAuditLog({
        actor_user_id: selectedAuditUser.id,
        limit: 250,
      });
      setUserAuditLogs(data);
    } catch (err) {
      setAuditError(parseApiError(err).message);
    } finally {
      setAuditLoading(false);
    }
  }, [selectedAuditUser, parseApiError]);

  const toggleLogExpand = (logId: string) => {
    setExpandedLogIds((prev) => {
      const next = new Set(prev);
      if (next.has(logId)) next.delete(logId);
      else next.add(logId);
      return next;
    });
  };

  // Filtered roster
  const filteredUsers = useMemo(() => {
    return users.filter((u) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchName = (u.full_name || '').toLowerCase().includes(q);
        const matchEmail = (u.email || '').toLowerCase().includes(q);
        const matchRole = roleLabel(u.role).toLowerCase().includes(q);
        const matchOrg = (u.organization_name || '').toLowerCase().includes(q);
        if (!matchName && !matchEmail && !matchRole && !matchOrg) return false;
      }
      if (selectedRole && u.role !== selectedRole) return false;
      if (selectedStatus && u.account_status !== selectedStatus) return false;
      return true;
    });
  }, [users, searchQuery, selectedRole, selectedStatus]);

  // Filtered audit logs for the selected user
  const filteredAuditLogs = useMemo(() => {
    return userAuditLogs.filter((log) => {
      if (auditActionFilter && log.action !== auditActionFilter) return false;
      if (auditSearchQuery.trim()) {
        const q = auditSearchQuery.toLowerCase();
        const matchAction = log.action.toLowerCase().includes(q);
        const matchResource = (log.resource_type || '').toLowerCase().includes(q);
        const matchId = (log.resource_id || '').toLowerCase().includes(q);
        if (!matchAction && !matchResource && !matchId) return false;
      }
      return true;
    });
  }, [userAuditLogs, auditActionFilter, auditSearchQuery]);

  const availableAuditActions = useMemo(() => {
    return Array.from(new Set(userAuditLogs.map((l) => l.action))).filter(Boolean);
  }, [userAuditLogs]);

  // Metrics summary
  const metrics = useMemo(() => {
    const total = users.length;
    const active = users.filter((u) => u.account_status === 'ACTIVE').length;
    const admins = users.filter((u) => u.role === 'SYSTEM_ADMIN' || u.role === 'INSTITUTION_ADMIN').length;
    const analysts = users.filter(
      (u) => u.role === 'SECURITY_ANALYST' || u.role === 'CYBER_CELL_INVESTIGATOR'
    ).length;
    return { total, active, admins, analysts };
  }, [users]);

  // Handle invitation
  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInviteError(null);
    if (isSysAdmin && !inviteOrgId) {
      setInviteError('Please choose an organization for this user.');
      return;
    }
    setInviting(true);
    try {
      if (isSysAdmin) {
        const result = await invitePlatformUser({
          email: inviteEmail.trim(),
          full_name: inviteName.trim() || undefined,
          organization_id: inviteOrgId,
          role_code: inviteRole,
        });
        setIssuedCredential({ email: result.user.email, password: result.temporary_password });
      } else {
        const result = await inviteOrgMember({
          email: inviteEmail.trim(),
          full_name: inviteName.trim() || undefined,
          role_code: inviteRole as AssignableRole,
        });
        setIssuedCredential({ email: result.user.email, password: result.temporary_password });
      }
      setInviteEmail('');
      setInviteName('');
      setInviteRole('SECURITY_ANALYST');
      setShowInviteModal(false);
      await loadUsers();
    } catch (err) {
      setInviteError(parseApiError(err).message);
    } finally {
      setInviting(false);
    }
  };

  // Handle role modification
  const handleRoleChange = async (targetUser: GenericUserItem, newRole: RoleCode) => {
    setBusyUserId(targetUser.id);
    setError(null);
    try {
      if (isSysAdmin) {
        await updatePlatformUserRole(targetUser.id, newRole);
      } else {
        await updateOrgMemberRole(targetUser.id, newRole as AssignableRole);
      }
      await loadUsers();
    } catch (err) {
      setError(parseApiError(err).message);
    } finally {
      setBusyUserId(null);
    }
  };

  // Handle deactivation
  const handleDeactivate = async (targetUser: GenericUserItem) => {
    if (!window.confirm(`Are you sure you want to deactivate ${targetUser.email}? They will lose platform access.`)) {
      return;
    }
    setBusyUserId(targetUser.id);
    setError(null);
    try {
      if (isSysAdmin) {
        await deactivatePlatformUser(targetUser.id);
      } else {
        await deactivateOrgMember(targetUser.id);
      }
      await loadUsers();
    } catch (err) {
      setError(parseApiError(err).message);
    } finally {
      setBusyUserId(null);
    }
  };

  const copyPassword = () => {
    if (!issuedCredential) return;
    navigator.clipboard.writeText(issuedCredential.password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-brand-soft flex items-center justify-center text-brand">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-text-primary">User Panel</h1>
              <p className="text-xs text-text-muted mt-0.5">
                Manage accounts, role assignments, and governance permissions across the platform.
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadUsers()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-workspace-border bg-workspace-card text-xs font-medium text-text-secondary hover:bg-workspace hover:text-text-primary transition-colors disabled:opacity-50"
            title="Refresh User List"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => {
              setShowInviteModal(true);
              setInviteError(null);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors shadow-xs"
          >
            <UserPlus className="w-4 h-4" />
            <span>Invite New User</span>
          </button>
        </div>
      </div>

      {/* KPI Cards Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div
          style={{ '--kpi-accent': '#2563B8' } as React.CSSProperties}
          className="kpi-card p-4 flex flex-col justify-between"
        >
          <div className="flex items-center justify-between gap-2 mb-3">
            <span className="text-[11px] font-semibold text-text-muted uppercase tracking-wider truncate">
              Total Users
            </span>
            <div className="w-8 h-8 rounded-lg bg-brand-soft text-brand flex items-center justify-center shrink-0">
              <Users className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-2xl font-extrabold text-text-primary tabular-nums tracking-tight">
              {loading ? <span className="inline-block w-12 h-6 rounded shimmer-bg" /> : metrics.total}
            </div>
            <div className="text-[10.5px] text-text-muted mt-1 truncate">
              Provisioned accounts
            </div>
          </div>
        </div>

        <div
          style={{ '--kpi-accent': '#2D8B68' } as React.CSSProperties}
          className="kpi-card p-4 flex flex-col justify-between"
        >
          <div className="flex items-center justify-between gap-2 mb-3">
            <span className="text-[11px] font-semibold text-text-muted uppercase tracking-wider truncate">
              Active Accounts
            </span>
            <div className="w-8 h-8 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0">
              <UserCheck className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-2xl font-extrabold text-text-primary tabular-nums tracking-tight">
              {loading ? <span className="inline-block w-12 h-6 rounded shimmer-bg" /> : metrics.active}
            </div>
            <div className="text-[10.5px] text-emerald-700 font-medium mt-1 truncate">
              {metrics.total > 0 ? `${Math.round((metrics.active / metrics.total) * 100)}% active rate` : 'All healthy'}
            </div>
          </div>
        </div>

        <div
          style={{ '--kpi-accent': '#7C62C8' } as React.CSSProperties}
          className="kpi-card p-4 flex flex-col justify-between"
        >
          <div className="flex items-center justify-between gap-2 mb-3">
            <span className="text-[11px] font-semibold text-text-muted uppercase tracking-wider truncate">
              Administrators
            </span>
            <div className="w-8 h-8 rounded-lg bg-purple-50 text-purple-600 flex items-center justify-center shrink-0">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-2xl font-extrabold text-text-primary tabular-nums tracking-tight">
              {loading ? <span className="inline-block w-12 h-6 rounded shimmer-bg" /> : metrics.admins}
            </div>
            <div className="text-[10.5px] text-text-muted mt-1 truncate">
              System & Org Admins
            </div>
          </div>
        </div>

        <div
          style={{ '--kpi-accent': '#0284C7' } as React.CSSProperties}
          className="kpi-card p-4 flex flex-col justify-between"
        >
          <div className="flex items-center justify-between gap-2 mb-3">
            <span className="text-[11px] font-semibold text-text-muted uppercase tracking-wider truncate">
              Security Analysts
            </span>
            <div className="w-8 h-8 rounded-lg bg-sky-50 text-sky-600 flex items-center justify-center shrink-0">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-2xl font-extrabold text-text-primary tabular-nums tracking-tight">
              {loading ? <span className="inline-block w-12 h-6 rounded shimmer-bg" /> : metrics.analysts}
            </div>
            <div className="text-[10.5px] text-text-muted mt-1 truncate">
              Forensic & Triage Roles
            </div>
          </div>
        </div>
      </div>

      {/* Temporary Password Alert Banner */}
      {issuedCredential && (
        <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 flex items-start justify-between gap-4">
          <div className="text-xs text-text-primary">
            <div className="font-semibold text-emerald-800 flex items-center gap-1.5 text-sm">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              Account Created for {issuedCredential.email}
            </div>
            <p className="text-emerald-700 mt-1">
              There is no outbound email delivery configured yet. Share this temporary one-time password with the user directly.
            </p>
            <div className="mt-2.5 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white border border-emerald-300 font-mono text-xs text-emerald-900 shadow-xs">
              <span>{issuedCredential.password}</span>
              <button
                onClick={copyPassword}
                className="text-emerald-600 hover:text-emerald-800 p-0.5 rounded transition-colors"
                title="Copy temporary password"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <button onClick={() => setIssuedCredential(null)} className="text-emerald-600 hover:text-emerald-900">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {error && (
        <div className="bg-rose-50 border border-rose-200 rounded-xl p-4 flex items-center gap-2 text-xs text-rose-800">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Table Card */}
      <div className="bg-workspace-card border border-workspace-border rounded-xl shadow-xs overflow-hidden">
        {/* Table Filters Toolbar */}
        <div className="p-4 border-b border-workspace-border flex flex-wrap items-center justify-between gap-3 bg-workspace/40">
          <div className="flex flex-wrap items-center gap-3 flex-1">
            {/* Search Box */}
            <div className="relative min-w-[240px] flex-1 sm:flex-initial">
              <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by name, email, or role…"
                className="w-full pl-9 pr-3.5 py-1.5 text-xs bg-workspace-card border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-brand/25 transition-all"
              />
            </div>

            {/* Org Filter (for System Admins) */}
            {isSysAdmin && (
              <select
                value={selectedOrg}
                onChange={(e) => setSelectedOrg(e.target.value)}
                className="px-2.5 py-1.5 text-xs bg-workspace-card border border-workspace-border rounded-lg text-text-secondary focus:outline-none focus:ring-2 focus:ring-brand/25"
              >
                <option value="">All Organizations ({organizations.length})</option>
                {organizations.map((org) => (
                  <option key={org.id} value={org.id}>
                    {org.name}
                  </option>
                ))}
              </select>
            )}

            {/* Role Filter */}
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-workspace-card border border-workspace-border rounded-lg text-text-secondary focus:outline-none focus:ring-2 focus:ring-brand/25"
            >
              <option value="">All Roles</option>
              {ALL_ASSIGNABLE_ROLES.map((r) => (
                <option key={r} value={r}>
                  {roleLabel(r)}
                </option>
              ))}
            </select>

            {/* Status Filter */}
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-workspace-card border border-workspace-border rounded-lg text-text-secondary focus:outline-none focus:ring-2 focus:ring-brand/25"
            >
              <option value="">All Statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="INACTIVE">Inactive</option>
              <option value="DEACTIVATED">Deactivated</option>
            </select>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-[11px] text-brand font-medium bg-brand-soft/60 px-2.5 py-1 rounded-md border border-brand/20">
              <Info className="w-3.5 h-3.5 shrink-0" />
              <span>Double-click any row to view user audit logs</span>
            </div>
            <div className="text-xs text-text-muted">
              Showing <strong className="text-text-primary">{filteredUsers.length}</strong> of{' '}
              <strong className="text-text-primary">{users.length}</strong>
            </div>
          </div>
        </div>

        {/* User Roster Table */}
        {loading ? (
          <div className="p-12 flex flex-col items-center justify-center text-text-muted text-xs gap-2">
            <Loader2 className="w-5 h-5 text-brand animate-spin" />
            <span>Loading user directory…</span>
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="p-12 text-center text-text-muted text-xs">
            No users match the current search or filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-workspace-header border-b border-workspace-border text-text-muted uppercase text-[11px] tracking-wider font-semibold">
                <tr>
                  <th className="px-5 py-3">User</th>
                  {isSysAdmin && <th className="px-4 py-3">Organization</th>}
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Last Active</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-workspace-border">
                {filteredUsers.map((u) => {
                  const isSelf = u.id === user?.id;
                  const isBusy = busyUserId === u.id;
                  const initials = (u.full_name || u.email || 'U')
                    .split(' ')
                    .map((n) => n[0])
                    .slice(0, 2)
                    .join('')
                    .toUpperCase();

                  return (
                    <tr
                      key={u.id}
                      onDoubleClick={() => handleOpenAuditModal(u)}
                      className="hover:bg-brand-soft/30 cursor-pointer transition-colors group select-none"
                      title="Double-click to view audit logs for this user"
                    >
                      {/* User Info */}
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-brand-soft text-brand font-bold text-xs flex items-center justify-center shrink-0 border border-brand/20 group-hover:scale-105 transition-transform">
                            {initials}
                          </div>
                          <div className="min-w-0">
                            <div className="font-semibold text-text-primary truncate flex items-center gap-1.5">
                              <span>{u.full_name || u.email}</span>
                              {isSelf && (
                                <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-brand text-white">
                                  You
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-text-muted truncate flex items-center gap-1 mt-0.5">
                              <Mail className="w-3 h-3" />
                              <span>{u.email}</span>
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Organization */}
                      {isSysAdmin && (
                        <td className="px-4 py-3.5 text-text-secondary whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <Building2 className="w-3.5 h-3.5 text-text-muted" />
                            <span>{u.organization_name || 'System / Cross-org'}</span>
                          </div>
                        </td>
                      )}

                      {/* Role Badge */}
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold border ${roleBadgeClass(
                            u.role
                          )}`}
                        >
                          {roleLabel(u.role)}
                        </span>
                      </td>

                      {/* Account Status */}
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <StatusBadge
                          type="severity"
                          value={u.account_status === 'ACTIVE' ? 'safe' : 'critical'}
                          label={u.account_status}
                          size="sm"
                        />
                      </td>

                      {/* Last Login */}
                      <td className="px-4 py-3.5 text-text-muted whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Calendar className="w-3 h-3 text-text-muted" />
                          <span>{fmtDateTime(u.last_login_at)}</span>
                        </div>
                      </td>

                      {/* Actions Menu */}
                      <td className="px-4 py-3.5 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="inline-flex items-center gap-1.5">
                          {/* Dedicated View Audit Logs Button */}
                          <button
                            onClick={() => handleOpenAuditModal(u)}
                            className="p-1.5 rounded-lg border border-workspace-border text-text-secondary hover:text-brand hover:bg-brand-soft/50 hover:border-brand/30 transition-colors"
                            title="View audit logs (or double-click row)"
                          >
                            <History className="w-3.5 h-3.5" />
                          </button>

                          <select
                            disabled={isBusy || isSelf}
                            value={u.role}
                            onChange={(e) => handleRoleChange(u, e.target.value as RoleCode)}
                            className="px-2 py-1 text-[11.5px] bg-workspace border border-workspace-border rounded-md text-text-secondary focus:outline-none focus:ring-1 focus:ring-brand/30 disabled:opacity-40"
                            title={isSelf ? 'You cannot alter your own role' : 'Change user role'}
                          >
                            {ALL_ASSIGNABLE_ROLES.map((r) => (
                              <option key={r} value={r}>
                                {roleLabel(r)}
                              </option>
                            ))}
                          </select>

                          <button
                            onClick={() => handleDeactivate(u)}
                            disabled={isBusy || isSelf || u.account_status === 'DEACTIVATED'}
                            className="p-1.5 rounded-lg border border-workspace-border text-rose-600 hover:bg-rose-50 hover:border-rose-200 transition-colors disabled:opacity-40"
                            title={isSelf ? 'Cannot deactivate self' : 'Deactivate user account'}
                          >
                            {isBusy ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Lock className="w-3.5 h-3.5" />
                            )}
                          </button>
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

      {/* User Audit Logs Modal (Triggered on Double-Click) */}
      {selectedAuditUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="bg-workspace-card border border-workspace-border rounded-2xl w-full max-w-4xl max-h-[90vh] shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-workspace-border flex items-center justify-between bg-workspace/50 shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center font-bold text-sm border border-brand/20">
                  {(selectedAuditUser.full_name || selectedAuditUser.email || 'U')
                    .split(' ')
                    .map((n) => n[0])
                    .slice(0, 2)
                    .join('')
                    .toUpperCase()}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-bold text-text-primary">
                      {selectedAuditUser.full_name || selectedAuditUser.email}
                    </h2>
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-[10.5px] font-semibold border ${roleBadgeClass(
                        selectedAuditUser.role
                      )}`}
                    >
                      {roleLabel(selectedAuditUser.role)}
                    </span>
                  </div>
                  <div className="text-xs text-text-muted flex items-center gap-2 mt-0.5">
                    <span>{selectedAuditUser.email}</span>
                    <span>•</span>
                    <span>{selectedAuditUser.organization_name || 'System / Cross-organization'}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleRefreshUserAudit}
                  disabled={auditLoading}
                  className="p-2 rounded-lg border border-workspace-border bg-workspace-card text-text-secondary hover:text-text-primary hover:bg-workspace transition-colors disabled:opacity-50"
                  title="Refresh audit logs"
                >
                  <RefreshCw className={`w-4 h-4 ${auditLoading ? 'animate-spin' : ''}`} />
                </button>
                <button
                  onClick={() => setSelectedAuditUser(null)}
                  className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-workspace transition-colors"
                  title="Close modal"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Quick Metrics Bar */}
            <div className="px-6 py-3 border-b border-workspace-border bg-workspace-header/30 flex items-center justify-between flex-wrap gap-3 text-xs shrink-0">
              <div className="flex items-center gap-6">
                <div>
                  <span className="text-text-muted">Total Recorded Events:</span>{' '}
                  <strong className="text-text-primary font-semibold">{userAuditLogs.length}</strong>
                </div>
                <div>
                  <span className="text-text-muted">Action Types:</span>{' '}
                  <strong className="text-text-primary font-semibold">{availableAuditActions.length}</strong>
                </div>
                <div>
                  <span className="text-text-muted">Latest Activity:</span>{' '}
                  <strong className="text-text-primary font-semibold">
                    {userAuditLogs.length > 0 ? fmtDateTime(userAuditLogs[0].occurred_at) : 'None'}
                  </strong>
                </div>
              </div>

              <div className="flex items-center gap-2 flex-1 sm:flex-initial justify-end">
                {/* Search in logs */}
                <div className="relative min-w-[180px]">
                  <Search className="w-3.5 h-3.5 text-text-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={auditSearchQuery}
                    onChange={(e) => setAuditSearchQuery(e.target.value)}
                    placeholder="Search action or resource…"
                    className="w-full pl-8 pr-3 py-1 text-xs bg-workspace-card border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-brand/30"
                  />
                </div>

                {/* Filter by action */}
                {availableAuditActions.length > 0 && (
                  <select
                    value={auditActionFilter}
                    onChange={(e) => setAuditActionFilter(e.target.value)}
                    className="px-2.5 py-1 text-xs bg-workspace-card border border-workspace-border rounded-lg text-text-secondary focus:outline-none focus:ring-1 focus:ring-brand/30"
                  >
                    <option value="">All Action Types</option>
                    {availableAuditActions.map((act) => (
                      <option key={act} value={act}>
                        {act}
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </div>

            {/* Modal Body / Logs Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {auditError && (
                <div className="bg-rose-50 border border-rose-200 rounded-xl p-4 flex items-center gap-2 text-xs text-rose-800">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
                  <span>{auditError}</span>
                </div>
              )}

              {auditLoading ? (
                <div className="p-16 flex flex-col items-center justify-center text-text-muted text-xs gap-3">
                  <Loader2 className="w-6 h-6 text-brand animate-spin" />
                  <span>Fetching security audit trail for {selectedAuditUser.full_name || selectedAuditUser.email}…</span>
                </div>
              ) : filteredAuditLogs.length === 0 ? (
                <div className="p-16 text-center text-xs text-text-muted space-y-2">
                  <Activity className="w-8 h-8 text-text-muted mx-auto opacity-50" />
                  <div className="font-semibold text-text-primary text-sm">No Audit Logs Found</div>
                  <p className="max-w-md mx-auto text-text-muted">
                    No matching audit log entries were found for this user. Administrative actions, role adjustments, and
                    account activities will be logged chronologically here.
                  </p>
                </div>
              ) : (
                <div className="border border-workspace-border rounded-xl overflow-hidden shadow-2xs">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-workspace-header border-b border-workspace-border text-text-muted uppercase text-[10.5px] tracking-wider font-semibold">
                      <tr>
                        <th className="px-4 py-2.5">Timestamp</th>
                        <th className="px-4 py-2.5">Action</th>
                        <th className="px-4 py-2.5">Target Resource</th>
                        <th className="px-4 py-2.5">Scope</th>
                        <th className="px-4 py-2.5 text-right">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-workspace-border">
                      {filteredAuditLogs.map((log) => {
                        const isExpanded = expandedLogIds.has(log.id);
                        const hasMetadata = log.metadata_json && Object.keys(log.metadata_json).length > 0;

                        return (
                          <React.Fragment key={log.id}>
                            <tr
                              onClick={() => hasMetadata && toggleLogExpand(log.id)}
                              className={`hover:bg-workspace/60 transition-colors ${
                                hasMetadata ? 'cursor-pointer' : ''
                              }`}
                            >
                              <td className="px-4 py-3 text-text-muted font-mono text-[11px] whitespace-nowrap">
                                <div className="flex items-center gap-1.5">
                                  <Calendar className="w-3 h-3 text-text-muted" />
                                  <span>{fmtDateTime(log.occurred_at)}</span>
                                </div>
                              </td>

                              <td className="px-4 py-3 whitespace-nowrap">
                                <span
                                  className={`inline-flex items-center px-2 py-0.5 rounded-md font-mono text-[11px] font-semibold border ${actionBadgeClass(
                                    log.action
                                  )}`}
                                >
                                  {log.action}
                                </span>
                              </td>

                              <td className="px-4 py-3 text-text-secondary whitespace-nowrap font-mono text-[11px]">
                                {log.resource_type ? (
                                  <div className="flex items-center gap-1.5">
                                    <span className="font-semibold text-text-primary">{log.resource_type}</span>
                                    {log.resource_id && (
                                      <span className="text-text-muted">
                                        ({log.resource_id.slice(0, 8)}…)
                                      </span>
                                    )}
                                  </div>
                                ) : (
                                  '—'
                                )}
                              </td>

                              <td className="px-4 py-3 text-text-muted whitespace-nowrap text-[11px]">
                                {log.organization_id ? (
                                  <span className="flex items-center gap-1">
                                    <Building2 className="w-3 h-3 text-text-muted" />
                                    <span>
                                      {organizations.find((o) => o.id === log.organization_id)?.name ||
                                        log.organization_id.slice(0, 8) + '…'}
                                    </span>
                                  </span>
                                ) : (
                                  'Platform / Global'
                                )}
                              </td>

                              <td className="px-4 py-3 text-right whitespace-nowrap">
                                {hasMetadata ? (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      toggleLogExpand(log.id);
                                    }}
                                    className="inline-flex items-center gap-1 text-[11px] font-medium text-brand hover:underline"
                                  >
                                    <span>{isExpanded ? 'Hide' : 'View Payload'}</span>
                                    {isExpanded ? (
                                      <ChevronDown className="w-3 h-3" />
                                    ) : (
                                      <ChevronRight className="w-3 h-3" />
                                    )}
                                  </button>
                                ) : (
                                  <span className="text-text-muted text-[11px]">None</span>
                                )}
                              </td>
                            </tr>

                            {/* Collapsible Metadata Payload Row */}
                            {isExpanded && hasMetadata && (
                              <tr className="bg-workspace/80">
                                <td colSpan={5} className="px-4 py-3">
                                  <div className="rounded-lg bg-navy-sidebar text-slate-200 p-3 font-mono text-[11px] overflow-x-auto border border-navy-border shadow-inner">
                                    <pre>{JSON.stringify(log.metadata_json, null, 2)}</pre>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3 border-t border-workspace-border bg-workspace-header/50 flex items-center justify-between text-xs text-text-muted shrink-0">
              <span>
                Double-click any user in the User Panel anytime to open their specific audit trail.
              </span>
              <button
                onClick={() => setSelectedAuditUser(null)}
                className="px-4 py-1.5 rounded-lg border border-workspace-border bg-workspace-card text-xs font-semibold text-text-primary hover:bg-workspace transition-colors"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Invite User Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-workspace-card border border-workspace-border rounded-2xl w-full max-w-lg shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="px-6 py-4 border-b border-workspace-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-brand-soft text-brand flex items-center justify-center">
                  <UserPlus className="w-4 h-4" />
                </div>
                <h3 className="text-sm font-bold text-text-primary">Invite Platform User</h3>
              </div>
              <button
                onClick={() => setShowInviteModal(false)}
                className="text-text-muted hover:text-text-primary p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleInvite} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1">
                  Email Address <span className="text-rose-500">*</span>
                </label>
                <input
                  type="email"
                  required
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="analyst@institution.gov"
                  className="w-full px-3 py-2 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-brand/30"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1">
                  Full Name (Optional)
                </label>
                <input
                  type="text"
                  value={inviteName}
                  onChange={(e) => setInviteName(e.target.value)}
                  placeholder="Dr. Rajesh Sharma"
                  className="w-full px-3 py-2 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 focus:ring-brand/30"
                />
              </div>

              {isSysAdmin && (
                <div>
                  <label className="block text-xs font-semibold text-text-secondary mb-1">
                    Assigned Organization <span className="text-rose-500">*</span>
                  </label>
                  <select
                    required
                    value={inviteOrgId}
                    onChange={(e) => setInviteOrgId(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary focus:outline-none focus:ring-2 focus:ring-brand/30"
                  >
                    <option value="">Select an organization…</option>
                    {organizations.map((org) => (
                      <option key={org.id} value={org.id}>
                        {org.name} ({org.organization_type})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1">
                  Assigned Security Role <span className="text-rose-500">*</span>
                </label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as RoleCode)}
                  className="w-full px-3 py-2 text-xs bg-workspace border border-workspace-border rounded-lg text-text-primary focus:outline-none focus:ring-2 focus:ring-brand/30"
                >
                  {ALL_ASSIGNABLE_ROLES.map((r) => (
                    <option key={r} value={r}>
                      {roleLabel(r)}
                    </option>
                  ))}
                </select>
                <p className="text-[11px] text-text-muted mt-1">
                  Roles define whether this account can access investigation graphs, cross-org evidence, or triage queues.
                </p>
              </div>

              {inviteError && (
                <div className="bg-rose-50 border border-rose-200 rounded-lg p-3 text-xs text-rose-700 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
                  <span>{inviteError}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-workspace-border">
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="px-4 py-2 text-xs font-medium text-text-secondary hover:bg-workspace rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={inviting || !inviteEmail.trim() || (isSysAdmin && !inviteOrgId)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors disabled:opacity-50"
                >
                  {inviting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  <span>Issue Invitation</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserPanelView;
