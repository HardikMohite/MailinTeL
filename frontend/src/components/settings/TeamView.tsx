import React, { useEffect, useState } from 'react';
import { Users, UserPlus, Shield, Loader2, AlertTriangle, Copy, Check, X, MoreVertical } from 'lucide-react';
import {
  listOrgMembers,
  inviteOrgMember,
  updateOrgMemberRole,
  deactivateOrgMember,
  OrgMember,
  AssignableRole,
  ASSIGNABLE_ROLES,
} from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { useApiErrorHandler } from '../../hooks/useApiErrorHandler';
import { StatusBadge } from '../common/StatusBadge';

const ROLE_LABELS: Record<string, string> = {
  INSTITUTION_ADMIN: 'Institution Admin',
  SYSTEM_ADMIN: 'System Admin',
  SECURITY_ANALYST: 'Security Analyst',
  CYBER_CELL_INVESTIGATOR: 'Cyber Cell Investigator',
  USER: 'User',
};

const roleLabel = (code: string) => ROLE_LABELS[code] || code;

const fmtDateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : 'Never');

export const TeamView: React.FC = () => {
  const { user } = useAuth();
  const parseApiError = useApiErrorHandler();
  const isAdmin = user?.role === 'INSTITUTION_ADMIN' || user?.role === 'SYSTEM_ADMIN';

  const [members, setMembers] = useState<OrgMember[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteName, setInviteName] = useState('');
  const [inviteRole, setInviteRole] = useState<AssignableRole>('SECURITY_ANALYST');
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [issuedCredential, setIssuedCredential] = useState<{ email: string; password: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const [busyMemberId, setBusyMemberId] = useState<string | null>(null);
  const [openMenuId, setOpenMenuId] = useState<string | null>(null);

  const loadMembers = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listOrgMembers();
      setMembers(data);
    } catch (err) {
      setError(parseApiError(err).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMembers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInviteError(null);
    setInviting(true);
    try {
      const result = await inviteOrgMember({
        email: inviteEmail.trim(),
        full_name: inviteName.trim() || undefined,
        role_code: inviteRole,
      });
      setIssuedCredential({ email: result.user.email, password: result.temporary_password });
      setInviteEmail('');
      setInviteName('');
      setInviteRole('SECURITY_ANALYST');
      setShowInvite(false);
      await loadMembers();
    } catch (err) {
      setInviteError(parseApiError(err).message);
    } finally {
      setInviting(false);
    }
  };

  const handleRoleChange = async (member: OrgMember, role: AssignableRole) => {
    setOpenMenuId(null);
    setBusyMemberId(member.id);
    setError(null);
    try {
      await updateOrgMemberRole(member.id, role);
      await loadMembers();
    } catch (err) {
      setError(parseApiError(err).message);
    } finally {
      setBusyMemberId(null);
    }
  };

  const handleDeactivate = async (member: OrgMember) => {
    setOpenMenuId(null);
    if (!window.confirm(`Deactivate ${member.email}? They will immediately lose access.`)) return;
    setBusyMemberId(member.id);
    setError(null);
    try {
      await deactivateOrgMember(member.id);
      await loadMembers();
    } catch (err) {
      setError(parseApiError(err).message);
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
      {/* Header */}
      <div className="bg-workspace-card border border-workspace-border rounded-xl p-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-brand-soft flex items-center justify-center">
            <Users className="w-5 h-5 text-brand" />
          </div>
          <div>
            <h2 className="text-[15px] font-semibold text-text-primary">Team & Access</h2>
            <p className="text-[12.5px] text-text-muted mt-0.5">
              {isAdmin
                ? 'Provision teammates and manage their role within your organization.'
                : 'Members of your organization. Contact an admin to invite or change access.'}
            </p>
          </div>
        </div>
        {isAdmin && (
          <button
            onClick={() => {
              setShowInvite(true);
              setInviteError(null);
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-brand text-white text-[13px] font-medium hover:bg-brand-hover transition-colors"
          >
            <UserPlus className="w-4 h-4" />
            Invite employee
          </button>
        )}
      </div>

      {/* One-time temporary password banner */}
      {issuedCredential && (
        <div className="bg-severity-safe-soft border border-severity-safe/30 rounded-xl p-4 flex items-start justify-between gap-4">
          <div className="text-[13px] text-text-primary">
            <div className="font-semibold flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-severity-safe" />
              Account created for {issuedCredential.email}
            </div>
            <p className="text-text-secondary mt-1">
              There's no email delivery yet in this build — share this one-time password with them directly.
              It won't be shown again.
            </p>
            <div className="mt-2 flex items-center gap-2">
              <code className="px-2.5 py-1.5 rounded-md bg-workspace-card border border-workspace-border font-mono text-[13px] text-text-primary">
                {issuedCredential.password}
              </code>
              <button
                onClick={copyPassword}
                className="inline-flex items-center gap-1 px-2 py-1.5 rounded-md border border-workspace-border text-[12px] text-text-secondary hover:bg-workspace-secondary transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-severity-safe" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
          <button onClick={() => setIssuedCredential(null)} className="text-text-muted hover:text-text-primary">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {error && (
        <div className="bg-severity-critical-soft border border-severity-critical/30 rounded-xl p-4 flex items-center gap-2 text-[13px] text-severity-critical">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Invite form */}
      {showInvite && isAdmin && (
        <div className="bg-workspace-card border border-workspace-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[13.5px] font-semibold text-text-primary">Invite employee / teammate</h3>
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
                placeholder="teammate@yourorg.com"
              />
            </div>
            <div>
              <label className="block text-[12px] font-medium text-text-secondary mb-1">Full name (optional)</label>
              <input
                type="text"
                value={inviteName}
                onChange={(e) => setInviteName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-workspace-border text-[13px] focus:outline-none focus:ring-2 focus:ring-brand/30"
                placeholder="Jane Doe"
              />
            </div>
            <div>
              <label className="block text-[12px] font-medium text-text-secondary mb-1">Role</label>
              <select
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value as AssignableRole)}
                className="w-full px-3 py-2 rounded-lg border border-workspace-border text-[13px] focus:outline-none focus:ring-2 focus:ring-brand/30"
              >
                {ASSIGNABLE_ROLES.map((code) => (
                  <option key={code} value={code}>
                    {roleLabel(code)}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="submit"
                disabled={inviting || !inviteEmail.trim()}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-lg bg-brand text-white text-[13px] font-medium hover:bg-brand-hover transition-colors disabled:opacity-50"
              >
                {inviting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Create account
              </button>
            </div>
            {inviteError && (
              <div className="sm:col-span-2 text-[12.5px] text-severity-critical flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                {inviteError}
              </div>
            )}
          </form>
        </div>
      )}

      {/* Roster */}
      <div className="bg-workspace-card border border-workspace-border rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-10 flex items-center justify-center text-text-muted text-[13px] gap-2">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading team...
          </div>
        ) : members.length === 0 ? (
          <div className="p-10 text-center text-text-muted text-[13px]">No members found.</div>
        ) : (
          <table className="w-full text-[13px]">
            <thead className="bg-workspace-header border-b border-workspace-border">
              <tr className="text-left text-text-muted text-[11.5px] uppercase tracking-wide">
                <th className="px-4 py-2.5 font-semibold">Member</th>
                <th className="px-4 py-2.5 font-semibold">Role</th>
                <th className="px-4 py-2.5 font-semibold">Status</th>
                <th className="px-4 py-2.5 font-semibold">Last login</th>
                {isAdmin && <th className="px-4 py-2.5 font-semibold text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {members.map((member) => (
                <tr key={member.id} className="border-b border-workspace-border last:border-0 hover:bg-workspace-secondary/50">
                  <td className="px-4 py-3">
                    <div className="font-medium text-text-primary">{member.full_name || '—'}</div>
                    <div className="text-text-muted text-[12px]">{member.email}</div>
                  </td>
                  <td className="px-4 py-3 text-text-secondary">{roleLabel(member.role)}</td>
                  <td className="px-4 py-3">
                    <StatusBadge
                      type="severity"
                      value={member.membership_status === 'ACTIVE' ? 'safe' : 'critical'}
                      label={member.membership_status}
                      size="sm"
                    />
                  </td>
                  <td className="px-4 py-3 text-text-muted">{fmtDateTime(member.last_login_at)}</td>
                  {isAdmin && (
                    <td className="px-4 py-3 text-right relative">
                      {member.id === user?.id ? (
                        <span className="text-text-muted text-[12px]">You</span>
                      ) : busyMemberId === member.id ? (
                        <Loader2 className="w-4 h-4 animate-spin inline-block text-text-muted" />
                      ) : member.membership_status !== 'ACTIVE' ? (
                        <span className="text-text-muted text-[12px]">Deactivated</span>
                      ) : (
                        <div className="inline-block">
                          <button
                            onClick={() => setOpenMenuId(openMenuId === member.id ? null : member.id)}
                            className="p-1.5 rounded-md hover:bg-workspace-secondary text-text-muted hover:text-text-primary"
                          >
                            <MoreVertical className="w-4 h-4" />
                          </button>
                          {openMenuId === member.id && (
                            <div className="absolute right-4 mt-1 w-56 bg-workspace-card border border-workspace-border rounded-lg shadow-lg z-10 text-left overflow-hidden">
                              <div className="px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-text-muted border-b border-workspace-border">
                                Change role
                              </div>
                              {ASSIGNABLE_ROLES.filter((r) => r !== member.role).map((code) => (
                                <button
                                  key={code}
                                  onClick={() => handleRoleChange(member, code)}
                                  className="w-full text-left px-3 py-2 text-[12.5px] text-text-secondary hover:bg-workspace-secondary"
                                >
                                  Make {roleLabel(code)}
                                </button>
                              ))}
                              <button
                                onClick={() => handleDeactivate(member)}
                                className="w-full text-left px-3 py-2 text-[12.5px] text-severity-critical hover:bg-severity-critical-soft border-t border-workspace-border"
                              >
                                Deactivate member
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default TeamView;
