import React, { useState, useEffect, useCallback } from 'react';
import {
  Building2,
  Shield,
  Users,
  CheckCircle2,
  Lock,
  Plus,
  Trash2,
  AlertTriangle,
  MoreVertical,
  X,
  Loader2,
  UserPlus,
  Crown,
  RefreshCw,
  Search,
  ArrowLeft,
  ShieldAlert,
  ChevronRight,
  Building,
} from 'lucide-react';

import { useAuth } from '../../context/AuthContext';
import { StatusBadge } from '../common/StatusBadge';
import {
  listPlatformOrganizations,
  getPlatformOrganization,
  createPlatformOrganization,
  deletePlatformOrganization,
  updatePlatformOrganizationStatus,
  assignOrganizationMember,
  assignCompanyAdmin,
  removeOrganizationMember,
  listEligibleUsers,
  OrganizationItem,
  OrganizationDetail,
  EligibleUser,
} from '../../services/api';

const fmtDate = (isoString?: string | null) => {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    return d.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return isoString;
  }
};

const fmtDateTime = (isoString?: string | null) => {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    return `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })} ${d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`;
  } catch {
    return isoString;
  }
};

export const OrganizationView: React.FC = () => {
  const { user } = useAuth();
  const isPlatformAdmin = user?.role === 'SYSTEM_ADMIN';

  // Platform Admin state
  const [organizations, setOrganizations] = useState<OrganizationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Active workspace / drill-down detail state
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [selectedOrg, setSelectedOrg] = useState<OrganizationDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  // Eligible users catalog for assignment dropdowns
  const [eligibleUsers, setEligibleUsers] = useState<EligibleUser[]>([]);


  // Modals state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgType, setNewOrgType] = useState('ENTERPRISE');
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [createOrgError, setCreateOrgError] = useState<string | null>(null);

  // Delete modal state
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [orgToDelete, setOrgToDelete] = useState<OrganizationItem | null>(null);
  const [deleteMode, setDeleteMode] = useState<'soft' | 'hard'>('soft');
  const [deletingOrg, setDeletingOrg] = useState(false);
  const [deleteOrgError, setDeleteOrgError] = useState<string | null>(null);

  // Add member modal state
  const [showAddMemberModal, setShowAddMemberModal] = useState(false);
  const [newMemberEmail, setNewMemberEmail] = useState('');
  const [newMemberName, setNewMemberName] = useState('');
  const [addingMember, setAddingMember] = useState(false);
  const [addMemberError, setAddMemberError] = useState<string | null>(null);

  // Assign Company Admin modal state
  const [showAssignAdminModal, setShowAssignAdminModal] = useState(false);
  const [adminCandidateId, setAdminCandidateId] = useState('');
  const [assigningAdmin, setAssigningAdmin] = useState(false);
  const [assignAdminError, setAssignAdminError] = useState<string | null>(null);

  // Actions menu state
  const [activeMenuOrgId, setActiveMenuOrgId] = useState<string | null>(null);

  // Feedback banner
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => {
      setFeedback(null);
    }, 5000);
  };

  // 1. Fetch organizations
  const loadOrganizations = useCallback(async () => {
    if (!isPlatformAdmin) return;
    setLoading(true);
    setError(null);
    try {
      const data = await listPlatformOrganizations();
      setOrganizations(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve organizations from the database.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [isPlatformAdmin]);

  // 2. Fetch selected organization detail
  const loadOrganizationDetail = useCallback(async (orgId: string) => {
    setDetailLoading(true);
    setDetailError(null);
    try {
      const detail = await getPlatformOrganization(orgId);
      setSelectedOrg(detail);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve organization details.';
      setDetailError(msg);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  // 3. Fetch eligible platform users
  const loadEligibleUsers = useCallback(async () => {
    if (!isPlatformAdmin) return;
    try {
      const data = await listEligibleUsers();
      setEligibleUsers(data);
    } catch {
      // Non-fatal fallback
    }
  }, [isPlatformAdmin]);


  useEffect(() => {
    if (isPlatformAdmin) {
      loadOrganizations();
      loadEligibleUsers();
    }
  }, [isPlatformAdmin, loadOrganizations, loadEligibleUsers]);

  useEffect(() => {
    if (selectedOrgId) {
      loadOrganizationDetail(selectedOrgId);
    } else {
      setSelectedOrg(null);
    }
  }, [selectedOrgId, loadOrganizationDetail]);

  // Close menus on window click
  useEffect(() => {
    const handleClickOutside = () => setActiveMenuOrgId(null);
    window.addEventListener('click', handleClickOutside);
    return () => window.removeEventListener('click', handleClickOutside);
  }, []);

  // Handlers
  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;
    setCreatingOrg(true);
    setCreateOrgError(null);
    try {
      const created = await createPlatformOrganization({
        name: newOrgName.trim(),
        organization_type: newOrgType.trim() || 'ENTERPRISE',
      });
      setShowCreateModal(false);
      setNewOrgName('');
      setNewOrgType('ENTERPRISE');
      showFeedback('success', `Organization "${created.name}" created successfully.`);
      await loadOrganizations();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create organization in database.';
      setCreateOrgError(msg);
    } finally {
      setCreatingOrg(false);
    }
  };

  const handleToggleStatus = async (org: OrganizationItem | OrganizationDetail) => {
    const nextStatus = org.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
    try {
      await updatePlatformOrganizationStatus(org.id, nextStatus);
      showFeedback('success', `Organization status changed to ${nextStatus}.`);
      await loadOrganizations();
      if (selectedOrgId === org.id) {
        await loadOrganizationDetail(org.id);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to update organization status.';
      showFeedback('error', msg);
    }
  };

  const confirmDeleteOrg = (org: OrganizationItem) => {
    setOrgToDelete(org);
    setDeleteMode('soft');
    setDeleteOrgError(null);
    setShowDeleteModal(true);
  };

  const handleDeleteOrg = async () => {
    if (!orgToDelete) return;
    setDeletingOrg(true);
    setDeleteOrgError(null);
    try {
      const isPermanent = deleteMode === 'hard';
      await deletePlatformOrganization(orgToDelete.id, isPermanent);
      setShowDeleteModal(false);
      const actionLabel = isPermanent ? 'permanently deleted' : 'deactivated';
      showFeedback('success', `Organization "${orgToDelete.name}" ${actionLabel} successfully.`);
      if (selectedOrgId === orgToDelete.id) {
        setSelectedOrgId(null);
      }
      setOrgToDelete(null);
      await loadOrganizations();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to remove organization.';
      setDeleteOrgError(msg);
    } finally {
      setDeletingOrg(false);
    }
  };

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOrgId || !newMemberEmail.trim()) return;
    setAddingMember(true);
    setAddMemberError(null);
    try {
      await assignOrganizationMember(selectedOrgId, {
        email: newMemberEmail.trim(),
        full_name: newMemberName.trim() || undefined,
        role_code: 'USER',
      });
      setShowAddMemberModal(false);
      setNewMemberEmail('');
      setNewMemberName('');
      showFeedback('success', `Member ${newMemberEmail.trim()} successfully assigned with role User.`);
      await loadOrganizationDetail(selectedOrgId);
      await loadOrganizations();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to assign member.';
      setAddMemberError(msg);
    } finally {
      setAddingMember(false);
    }
  };

  const handleAssignCompanyAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOrgId || !adminCandidateId) return;
    setAssigningAdmin(true);
    setAssignAdminError(null);
    try {
      await assignCompanyAdmin(selectedOrgId, {
        user_id: adminCandidateId,
      });
      setShowAssignAdminModal(false);
      setAdminCandidateId('');
      showFeedback('success', 'Company Admin role successfully assigned and persisted.');
      await loadOrganizationDetail(selectedOrgId);
      await loadOrganizations();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to assign Company Admin.';
      setAssignAdminError(msg);
    } finally {
      setAssigningAdmin(false);
    }
  };

  const handleMakeMemberAdminDirectly = async (userId: string) => {
    if (!selectedOrgId) return;
    try {
      await assignCompanyAdmin(selectedOrgId, { user_id: userId });
      showFeedback('success', 'Selected member promoted to Company Admin.');
      await loadOrganizationDetail(selectedOrgId);
      await loadOrganizations();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to assign Company Admin.';
      showFeedback('error', msg);
    }
  };

  const handleRemoveMember = async (userId: string, memberEmail: string) => {
    if (!selectedOrgId) return;
    if (!confirm(`Are you sure you want to remove ${memberEmail} from this organization?`)) return;
    try {
      await removeOrganizationMember(selectedOrgId, userId);
      showFeedback('success', `Member ${memberEmail} removed from organization.`);
      await loadOrganizationDetail(selectedOrgId);
      await loadOrganizations();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to remove member.';
      showFeedback('error', msg);
    }
  };

  // Filter out individual personal workspaces so only actual enterprise/managed organizations appear
  const isPersonalWorkspace = (o: OrganizationItem) =>
    o.organization_type?.toUpperCase() === 'PERSONAL' ||
    o.name?.trim().toLowerCase() === 'personal workspace';

  const nonPersonalOrgs = organizations.filter((o) => !isPersonalWorkspace(o));

  // Filter organizations by search
  const filteredOrganizations = nonPersonalOrgs.filter(
    (o) =>
      o.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      o.organization_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (o.company_admin?.email && o.company_admin.email.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (o.company_admin?.full_name && o.company_admin.full_name.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  // If user is not Platform Admin, display their dedicated organization workspace view
  if (!isPlatformAdmin) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <Building2 className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary tracking-tight">Organization</h1>
            <p className="text-sm text-text-muted mt-0.5">
              Workspace profile, organizational governance, and identity parameters.
            </p>
          </div>
        </div>

        <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-workspace-border">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-navy-elevated flex items-center justify-center text-text-primary border border-navy-border">
                <Building2 className="w-5 h-5 text-brand" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-text-primary">
                  {user?.organization_name || 'MailIntel Security Operations'}
                </h2>
                <p className="text-xs text-text-muted mt-0.5">Forensic Intelligence Organization</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <StatusBadge type="severity" value="safe" label="ACTIVE" size="sm" />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs pt-2">
            <div className="p-3.5 rounded-lg bg-workspace border border-workspace-border space-y-1">
              <span className="text-text-muted block text-[11px]">Organization Identifier</span>
              <span className="font-mono font-medium text-text-primary truncate block" title={user?.organization_id || ''}>
                {user?.organization_id || 'System Default'}
              </span>
            </div>
            <div className="p-3.5 rounded-lg bg-workspace border border-workspace-border space-y-1">
              <span className="text-text-muted block text-[11px]">Your Authority</span>
              <span className="font-medium text-text-primary block">
                {user?.role ? user.role.replace(/_/g, ' ') : 'Administrator'}
              </span>
            </div>
            <div className="p-3.5 rounded-lg bg-workspace border border-workspace-border space-y-1">
              <span className="text-text-muted block text-[11px]">Workspace Mode</span>
              <span className="font-medium text-text-primary block">Dedicated Tenant Partition</span>
            </div>
            <div className="p-3.5 rounded-lg bg-workspace border border-workspace-border space-y-1">
              <span className="text-text-muted block text-[11px]">Evidence Isolation</span>
              <span className="font-medium text-severity-safe flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> Enforced
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
            <div className="flex items-center gap-2.5">
              <Shield className="w-4 h-4 text-brand" />
              <h3 className="text-sm font-bold text-text-primary">Multi-Tenant Scoping</h3>
            </div>
            <p className="text-xs text-text-muted leading-relaxed">
              All evidence artifacts, forensic reports, and email analyses are cryptographically isolated within this organization.
            </p>
          </div>
          <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
            <div className="flex items-center gap-2.5">
              <Users className="w-4 h-4 text-brand" />
              <h3 className="text-sm font-bold text-text-primary">Access Management</h3>
            </div>
            <p className="text-xs text-text-muted leading-relaxed">
              Member provisioning and role assignments are managed via Team &amp; Access under strict role-based authorization.
            </p>
          </div>
          <div className="p-5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-3">
            <div className="flex items-center gap-2.5">
              <Lock className="w-4 h-4 text-brand" />
              <h3 className="text-sm font-bold text-text-primary">Compliance &amp; Custody</h3>
            </div>
            <p className="text-xs text-text-muted leading-relaxed">
              Chain of custody logs and forensic hashes (SHA-256) are immutably tied to the organization tenant context.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // =========================================================================
  // PLATFORM ADMIN INTERFACE
  // =========================================================================

  return (
    <div className="space-y-6">
      {/* Toast / Notification Banner */}
      {feedback && (
        <div
          className={`px-4 py-3 rounded-xl border text-xs font-medium flex items-center justify-between gap-3 shadow-sm transition-all ${
            feedback.type === 'success'
              ? 'bg-severity-safe-soft text-severity-safe border-severity-safe/30'
              : 'bg-severity-critical-soft text-severity-critical border-severity-critical/30'
          }`}
        >
          <div className="flex items-center gap-2">
            {feedback.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0" />
            )}
            <span>{feedback.message}</span>
          </div>
          <button onClick={() => setFeedback(null)} className="text-current opacity-70 hover:opacity-100">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* VIEW A: ORGANIZATION DETAILS & MEMBERS WORKSPACE */}
      {selectedOrgId ? (
        <div className="space-y-6">
          {/* Breadcrumb & Navigation */}
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <button
              onClick={() => setSelectedOrgId(null)}
              className="inline-flex items-center gap-2 text-xs font-medium text-text-muted hover:text-brand transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Organizations
            </button>

            <div className="flex items-center gap-2">
              <button
                onClick={() => selectedOrg && handleToggleStatus(selectedOrg)}
                className="px-3 py-1.5 rounded-lg border border-workspace-border text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-workspace transition-colors"
              >
                {selectedOrg?.status === 'ACTIVE' ? 'Deactivate Organization' : 'Reactivate Organization'}
              </button>
              {selectedOrg && (
                <button
                  onClick={() => confirmDeleteOrg(selectedOrg)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-severity-critical/30 text-severity-critical hover:bg-severity-critical-soft text-xs font-medium transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Remove
                </button>
              )}
            </div>
          </div>

          {detailLoading ? (
            <div className="p-12 rounded-xl bg-workspace-card border border-workspace-border flex items-center justify-center text-text-muted text-xs gap-2">
              <Loader2 className="w-4 h-4 animate-spin text-brand" />
              Loading organization details...
            </div>
          ) : detailError ? (
            <div className="p-6 rounded-xl bg-severity-critical-soft border border-severity-critical/30 text-severity-critical text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {detailError}
            </div>
          ) : selectedOrg ? (
            <>
              {/* Organization Header Card */}
              <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-workspace-border">
                  <div className="flex items-center gap-3.5">
                    <div className="w-12 h-12 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
                      <Building2 className="w-6 h-6" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <h2 className="text-xl font-bold text-text-primary tracking-tight">{selectedOrg.name}</h2>
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider bg-workspace border border-workspace-border text-text-secondary">
                          {selectedOrg.organization_type}
                        </span>
                        <StatusBadge
                          type="severity"
                          value={selectedOrg.status === 'ACTIVE' ? 'safe' : 'critical'}
                          label={selectedOrg.status}
                          size="sm"
                        />
                      </div>
                      <p className="text-xs text-text-muted mt-1 font-mono">ID: {selectedOrg.id}</p>
                    </div>
                  </div>

                  <div className="text-right text-xs text-text-muted">
                    <div>Created: {fmtDate(selectedOrg.created_at)}</div>
                    <div>Updated: {fmtDateTime(selectedOrg.updated_at)}</div>
                  </div>
                </div>

                {/* Company Admin Section */}
                <div className="p-4 rounded-lg bg-workspace border border-workspace-border flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center justify-center shrink-0">
                      <Crown className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-[11px] font-semibold text-text-muted uppercase tracking-wider">
                        Company Admin
                      </div>
                      {selectedOrg.company_admin ? (
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-sm font-semibold text-text-primary">
                            {selectedOrg.company_admin.full_name || 'Admin User'}
                          </span>
                          <span className="text-xs text-text-muted">({selectedOrg.company_admin.email})</span>
                        </div>
                      ) : (
                        <div className="text-xs text-text-muted italic mt-0.5">No Company Admin assigned</div>
                      )}
                    </div>
                  </div>

                  <button
                    onClick={() => {
                      setAdminCandidateId(selectedOrg.company_admin?.id || '');
                      setAssignAdminError(null);
                      setShowAssignAdminModal(true);
                    }}
                    className="inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-brand text-white text-xs font-medium hover:bg-brand-hover transition-colors shrink-0"
                  >
                    <Crown className="w-3.5 h-3.5" />
                    {selectedOrg.company_admin ? 'Change Admin' : 'Assign Admin'}
                  </button>
                </div>
              </div>

              {/* Members Section */}
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-bold text-text-primary">Organization Members</h3>
                    <p className="text-xs text-text-muted mt-0.5">
                      Roster of users currently assigned to this organization partition.
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      setNewMemberEmail('');
                      setNewMemberName('');
                      setAddMemberError(null);
                      setShowAddMemberModal(true);
                    }}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-brand text-white text-xs font-medium hover:bg-brand-hover transition-colors"
                  >
                    <UserPlus className="w-3.5 h-3.5" />
                    Add Member
                  </button>
                </div>

                {/* Members Table */}
                <div className="rounded-xl bg-workspace-card border border-workspace-border overflow-hidden shadow-sm">
                  {selectedOrg.members.length === 0 ? (
                    <div className="p-12 text-center space-y-3">
                      <div className="w-10 h-10 rounded-full bg-workspace border border-workspace-border mx-auto flex items-center justify-center text-text-muted">
                        <Users className="w-5 h-5" />
                      </div>
                      <h4 className="text-sm font-semibold text-text-primary">No members assigned</h4>
                      <p className="text-xs text-text-muted max-w-sm mx-auto">
                        Add members to this organization to begin managing access and permissions.
                      </p>
                      <button
                        onClick={() => {
                          setNewMemberEmail('');
                          setNewMemberName('');
                          setShowAddMemberModal(true);
                        }}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand text-white text-xs font-medium hover:bg-brand-hover transition-colors mt-2"
                      >
                        <UserPlus className="w-3.5 h-3.5" />
                        Add Member
                      </button>
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead className="bg-workspace-header border-b border-workspace-border">
                          <tr className="text-left text-text-muted text-[11px] uppercase tracking-wider">
                            <th className="px-5 py-3 font-semibold">User</th>
                            <th className="px-5 py-3 font-semibold">Email</th>
                            <th className="px-5 py-3 font-semibold">Role</th>
                            <th className="px-5 py-3 font-semibold">Membership Status</th>
                            <th className="px-5 py-3 font-semibold text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-workspace-border">
                          {selectedOrg.members.map((member) => {
                            const isCompanyAdmin = member.role === 'INSTITUTION_ADMIN';
                            return (
                              <tr key={member.id} className="hover:bg-workspace-secondary/50 transition-colors">
                                <td className="px-5 py-3.5">
                                  <div className="font-semibold text-text-primary">
                                    {member.full_name || 'Anonymous User'}
                                  </div>
                                </td>
                                <td className="px-5 py-3.5 text-text-muted font-mono">{member.email}</td>
                                <td className="px-5 py-3.5">
                                  {isCompanyAdmin ? (
                                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                      <Crown className="w-3 h-3" /> Company Admin
                                    </span>
                                  ) : (
                                    <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-workspace border border-workspace-border text-text-secondary">
                                      {member.role.replace(/_/g, ' ')}
                                    </span>
                                  )}
                                </td>
                                <td className="px-5 py-3.5">
                                  <StatusBadge
                                    type="severity"
                                    value={member.membership_status === 'ACTIVE' ? 'safe' : 'critical'}
                                    label={member.membership_status}
                                    size="sm"
                                  />
                                </td>
                                <td className="px-5 py-3.5 text-right">
                                  <div className="flex items-center justify-end gap-2">
                                    {!isCompanyAdmin && (
                                      <button
                                        onClick={() => handleMakeMemberAdminDirectly(member.id)}
                                        title="Make Company Admin"
                                        className="inline-flex items-center gap-1 px-2 py-1 rounded bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 text-[11px] font-medium transition-colors"
                                      >
                                        <Crown className="w-3 h-3" />
                                        Make Admin
                                      </button>
                                    )}
                                    <button
                                      onClick={() => handleRemoveMember(member.id, member.email)}
                                      title="Remove Member"
                                      className="p-1 rounded text-text-muted hover:text-severity-critical hover:bg-severity-critical-soft transition-colors"
                                    >
                                      <Trash2 className="w-3.5 h-3.5" />
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
              </div>
            </>
          ) : null}
        </div>
      ) : (
        /* VIEW B: MAIN ORGANIZATIONS LIST (DEFAULT) */
        <div className="space-y-5">
          {/* Header Card */}
          <div className="p-6 rounded-xl bg-workspace-card border border-workspace-border shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
                <Building2 className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-text-primary tracking-tight">Organizations</h1>
                <p className="text-sm text-text-muted mt-0.5">
                  Create and review every organization on the platform.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => loadOrganizations()}
                disabled={loading}
                title="Refresh Organizations"
                className="p-2.5 rounded-lg border border-workspace-border text-text-muted hover:text-text-primary hover:bg-workspace transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              </button>
              <button
                onClick={() => {
                  setNewOrgName('');
                  setNewOrgType('ENTERPRISE');
                  setCreateOrgError(null);
                  setShowCreateModal(true);
                }}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover shadow-sm transition-colors shrink-0"
              >
                <Plus className="w-4 h-4" />
                New organization
              </button>
            </div>
          </div>

          {/* Search & Filter Bar */}
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="relative flex-1 min-w-[240px] max-w-md">
              <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search organizations by name, type, or admin..."
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-workspace-card border border-workspace-border text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-brand"
              />
            </div>
            <div className="text-xs text-text-muted font-medium">
              Showing {filteredOrganizations.length} of {nonPersonalOrgs.length} organizations
            </div>
          </div>

          {error && (
            <div className="p-4 rounded-xl bg-severity-critical-soft border border-severity-critical/30 text-severity-critical text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          {/* Main Organizations Table */}
          <div className="rounded-xl bg-workspace-card border border-workspace-border overflow-hidden shadow-sm">
            {loading ? (
              <div className="p-12 flex items-center justify-center text-text-muted text-xs gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-brand" />
                Loading organizations from database...
              </div>
            ) : filteredOrganizations.length === 0 ? (
              <div className="p-12 text-center space-y-3">
                <Building className="w-8 h-8 text-text-muted mx-auto" />
                <h3 className="text-sm font-semibold text-text-primary">No organizations found</h3>
                <p className="text-xs text-text-muted max-w-sm mx-auto">
                  {searchQuery ? 'No organizations matched your search filter.' : 'No organizations are currently provisioned in the database.'}
                </p>
                {!searchQuery && (
                  <button
                    onClick={() => setShowCreateModal(true)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand text-white text-xs font-medium hover:bg-brand-hover transition-colors mt-2"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    Create First Organization
                  </button>
                )}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-workspace-header border-b border-workspace-border">
                    <tr className="text-left text-text-muted text-[11px] uppercase tracking-wider">
                      <th className="px-5 py-3 font-semibold">Organization</th>
                      <th className="px-5 py-3 font-semibold">Type</th>
                      <th className="px-5 py-3 font-semibold">Company Admin</th>
                      <th className="px-5 py-3 font-semibold">Members</th>
                      <th className="px-5 py-3 font-semibold">Status</th>
                      <th className="px-5 py-3 font-semibold">Created</th>
                      <th className="px-5 py-3 font-semibold text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-workspace-border">
                    {filteredOrganizations.map((org) => {
                      const isMenuOpen = activeMenuOrgId === org.id;
                      return (
                        <tr
                          key={org.id}
                          className="hover:bg-workspace-secondary/50 transition-colors cursor-pointer group"
                          onClick={() => setSelectedOrgId(org.id)}
                        >
                          <td className="px-5 py-3.5 font-medium text-text-primary">
                            <div className="flex items-center gap-2.5">
                              <Building2 className="w-4 h-4 text-brand shrink-0" />
                              <div>
                                <span className="font-semibold text-text-primary group-hover:text-brand transition-colors block">
                                  {org.name}
                                </span>
                                <span className="text-[10px] text-text-muted font-mono">{org.id.slice(0, 8)}...</span>
                              </div>
                            </div>
                          </td>
                          <td className="px-5 py-3.5 text-text-secondary">
                            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-workspace border border-workspace-border">
                              {org.organization_type}
                            </span>
                          </td>
                          <td className="px-5 py-3.5">
                            {org.company_admin ? (
                              <div className="flex items-center gap-1.5">
                                <Crown className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                                <div>
                                  <div className="font-medium text-text-primary">
                                    {org.company_admin.full_name || 'Admin User'}
                                  </div>
                                  <div className="text-[10.5px] text-text-muted font-mono">{org.company_admin.email}</div>
                                </div>
                              </div>
                            ) : (
                              <span className="text-text-muted italic">Unassigned</span>
                            )}
                          </td>
                          <td className="px-5 py-3.5 text-text-secondary">
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-workspace border border-workspace-border font-mono text-[11px]">
                              <Users className="w-3 h-3 text-text-muted" />
                              {org.member_count ?? 0}
                            </span>
                          </td>
                          <td className="px-5 py-3.5">
                            <StatusBadge
                              type="severity"
                              value={org.status === 'ACTIVE' ? 'safe' : 'critical'}
                              label={org.status}
                              size="sm"
                            />
                          </td>
                          <td className="px-5 py-3.5 text-text-muted font-mono">{fmtDate(org.created_at)}</td>
                          <td
                            className="px-5 py-3.5 text-right relative"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <div className="inline-block text-left">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setActiveMenuOrgId(isMenuOpen ? null : org.id);
                                }}
                                className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-workspace border border-transparent hover:border-workspace-border transition-colors"
                              >
                                <MoreVertical className="w-4 h-4" />
                              </button>

                              {isMenuOpen && (
                                <div className="absolute right-5 mt-1 w-48 rounded-xl bg-workspace-card border border-workspace-border shadow-xl z-20 py-1 text-left">
                                  <button
                                    onClick={() => {
                                      setActiveMenuOrgId(null);
                                      setSelectedOrgId(org.id);
                                    }}
                                    className="w-full px-3 py-2 text-left text-xs text-text-primary hover:bg-workspace flex items-center gap-2 transition-colors"
                                  >
                                    <ChevronRight className="w-3.5 h-3.5 text-brand" />
                                    Manage Organization
                                  </button>
                                  <button
                                    onClick={() => {
                                      setActiveMenuOrgId(null);
                                      handleToggleStatus(org);
                                    }}
                                    className="w-full px-3 py-2 text-left text-xs text-text-primary hover:bg-workspace flex items-center gap-2 transition-colors"
                                  >
                                    <RefreshCw className="w-3.5 h-3.5 text-text-muted" />
                                    {org.status === 'ACTIVE' ? 'Deactivate' : 'Reactivate'}
                                  </button>
                                  <div className="my-1 border-t border-workspace-border" />
                                  <button
                                    onClick={() => {
                                      setActiveMenuOrgId(null);
                                      confirmDeleteOrg(org);
                                    }}
                                    className="w-full px-3 py-2 text-left text-xs text-severity-critical hover:bg-severity-critical-soft flex items-center gap-2 transition-colors"
                                  >
                                    <Trash2 className="w-3.5 h-3.5" />
                                    Delete / Remove
                                  </button>
                                </div>
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
        </div>
      )}

      {/* =====================================================================
          MODAL 1: CREATE ORGANIZATION
      ===================================================================== */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-workspace-card border border-workspace-border rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-workspace-border">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-brand-soft text-brand flex items-center justify-center">
                  <Building2 className="w-4 h-4" />
                </div>
                <h3 className="text-base font-bold text-text-primary">Create Organization</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-text-muted hover:text-text-primary transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateOrg} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                  Organization Name *
                </label>
                <input
                  type="text"
                  required
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  placeholder="e.g. Apex Cyber Operations"
                  className="w-full px-3 py-2 rounded-lg bg-workspace border border-workspace-border text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-brand"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                  Organization Type
                </label>
                <select
                  value={newOrgType}
                  onChange={(e) => setNewOrgType(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-workspace border border-workspace-border text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-brand"
                >
                  <option value="ENTERPRISE">ENTERPRISE</option>
                  <option value="COMMERCIAL">COMMERCIAL</option>
                  <option value="GOVERNMENT">GOVERNMENT</option>
                  <option value="MSSP">MSSP</option>
                  <option value="ACADEMIC">ACADEMIC</option>
                </select>
              </div>

              {createOrgError && (
                <div className="p-3 rounded-lg bg-severity-critical-soft border border-severity-critical/30 text-severity-critical text-xs flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  {createOrgError}
                </div>
              )}

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg border border-workspace-border text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-workspace transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingOrg || !newOrgName.trim()}
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors disabled:opacity-50 shadow-sm"
                >
                  {creatingOrg && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  Create Organization
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* =====================================================================
          MODAL 2: SAFE DELETE CONFIRMATION
      ===================================================================== */}
      {showDeleteModal && orgToDelete && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-workspace-card border border-workspace-border rounded-2xl p-6 w-full max-w-lg shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center gap-3 text-severity-critical pb-2 border-b border-workspace-border">
              <div className="w-9 h-9 rounded-xl bg-severity-critical-soft flex items-center justify-center shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-text-primary">Delete organization?</h3>
                <p className="text-xs text-text-muted mt-0.5 font-normal">
                  You are about to remove <strong className="text-text-primary">{orgToDelete.name}</strong>.
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-workspace border border-workspace-border text-xs text-text-secondary space-y-2 leading-relaxed">
              <div className="font-semibold text-text-primary flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                Data Preservation Safeguard:
              </div>
              <p>
                Removing an organization will revoke member access and disband the partition. Historical
                investigations, evidence hashes, and forensic reports are maintained in the database for custody integrity.
              </p>
            </div>

            <div className="space-y-2.5">
              <label className="text-xs font-semibold text-text-primary block">Select Removal Strategy:</label>
              <div className="space-y-2">
                <label
                  className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                    deleteMode === 'soft'
                      ? 'bg-brand-soft/20 border-brand text-text-primary'
                      : 'bg-workspace border-workspace-border text-text-muted hover:border-text-muted'
                  }`}
                >
                  <input
                    type="radio"
                    name="deleteMode"
                    value="soft"
                    checked={deleteMode === 'soft'}
                    onChange={() => setDeleteMode('soft')}
                    className="mt-0.5 text-brand"
                  />
                  <div>
                    <div className="text-xs font-bold text-text-primary">Deactivate / Archive (Recommended)</div>
                    <div className="text-[11px] text-text-muted mt-0.5">
                      Sets status to INACTIVE. Members cannot log in, but all records and configurations remain intact and reactivatable.
                    </div>
                  </div>
                </label>

                <label
                  className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                    deleteMode === 'hard'
                      ? 'bg-severity-critical-soft border-severity-critical text-text-primary'
                      : 'bg-workspace border-workspace-border text-text-muted hover:border-text-muted'
                  }`}
                >
                  <input
                    type="radio"
                    name="deleteMode"
                    value="hard"
                    checked={deleteMode === 'hard'}
                    onChange={() => setDeleteMode('hard')}
                    className="mt-0.5 text-severity-critical"
                  />
                  <div>
                    <div className="text-xs font-bold text-severity-critical">Permanently Delete</div>
                    <div className="text-[11px] text-text-muted mt-0.5">
                      Completely removes the organization row and member associations from the database. Dependent records are unlinked.
                    </div>
                  </div>
                </label>
              </div>
            </div>

            {deleteOrgError && (
              <div className="p-3 rounded-lg bg-severity-critical-soft border border-severity-critical/30 text-severity-critical text-xs flex items-center gap-2">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                {deleteOrgError}
              </div>
            )}

            <div className="flex items-center justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setShowDeleteModal(false)}
                className="px-4 py-2 rounded-lg border border-workspace-border text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-workspace transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteOrg}
                disabled={deletingOrg}
                className={`inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-white text-xs font-semibold transition-colors shadow-sm disabled:opacity-50 ${
                  deleteMode === 'hard' ? 'bg-severity-critical hover:bg-severity-critical/90' : 'bg-brand hover:bg-brand-hover'
                }`}
              >
                {deletingOrg && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                {deleteMode === 'hard' ? 'Delete Organization' : 'Deactivate Organization'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          MODAL 3: ADD / ASSIGN MEMBER
      ===================================================================== */}
      {showAddMemberModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-workspace-card border border-workspace-border rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-workspace-border">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-brand-soft text-brand flex items-center justify-center">
                  <UserPlus className="w-4 h-4" />
                </div>
                <h3 className="text-base font-bold text-text-primary">Assign Member to Organization</h3>
              </div>
              <button
                onClick={() => setShowAddMemberModal(false)}
                className="text-text-muted hover:text-text-primary transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddMember} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                  Full Name
                </label>
                <input
                  type="text"
                  value={newMemberName}
                  onChange={(e) => setNewMemberName(e.target.value)}
                  placeholder="e.g. John Doe"
                  className="w-full px-3 py-2 rounded-lg bg-workspace border border-workspace-border text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-brand"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                  Email Address *
                </label>
                <input
                  type="email"
                  required
                  value={newMemberEmail}
                  onChange={(e) => setNewMemberEmail(e.target.value)}
                  placeholder="e.g. user@organization.com"
                  className="w-full px-3 py-2 rounded-lg bg-workspace border border-workspace-border text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-brand"
                />
                <p className="text-[11px] text-text-muted mt-1">
                  Assigns this email to the organization. If an account already exists, it is linked; otherwise, a new account is provisioned.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                  Assigned Organization Role
                </label>
                <div className="px-3 py-2 rounded-lg bg-workspace/60 border border-workspace-border text-xs text-text-primary flex items-center justify-between">
                  <span className="font-medium text-text-secondary">User (Standard Membership)</span>
                  <span className="text-[10px] text-brand font-medium bg-brand-soft px-1.5 py-0.5 rounded">Default</span>
                </div>
                <p className="text-[11px] text-text-muted mt-1">
                  New members are assigned the User role initially. Platform Admins can promote this member to Analyst or Company Admin later.
                </p>
              </div>

              {addMemberError && (
                <div className="p-3 rounded-lg bg-severity-critical-soft border border-severity-critical/30 text-severity-critical text-xs flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  {addMemberError}
                </div>
              )}

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddMemberModal(false)}
                  className="px-4 py-2 rounded-lg border border-workspace-border text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-workspace transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={addingMember || !newMemberEmail.trim()}
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors disabled:opacity-50 shadow-sm"
                >
                  {addingMember && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  Assign Member
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* =====================================================================
          MODAL 4: ASSIGN / CHANGE COMPANY ADMIN
      ===================================================================== */}
      {showAssignAdminModal && selectedOrg && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-workspace-card border border-workspace-border rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-workspace-border">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center justify-center">
                  <Crown className="w-4 h-4" />
                </div>
                <h3 className="text-base font-bold text-text-primary">Assign Company Admin</h3>
              </div>
              <button
                onClick={() => setShowAssignAdminModal(false)}
                className="text-text-muted hover:text-text-primary transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAssignCompanyAdmin} className="space-y-4">
              <div className="p-3 rounded-lg bg-workspace border border-workspace-border text-xs text-text-muted leading-relaxed">
                Assigning an existing user as <strong className="text-amber-400">Company Admin</strong> grants tenant-level administration over {selectedOrg.name}. The user will NOT receive Platform Admin privileges.
              </div>

              <div>
                <label className="block text-xs font-semibold text-text-secondary mb-1.5">
                  Select User *
                </label>
                <select
                  required
                  value={adminCandidateId}
                  onChange={(e) => setAdminCandidateId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-workspace border border-workspace-border text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-brand"
                >
                  <option value="">Choose eligible member...</option>
                  <optgroup label="Current Organization Members">
                    {selectedOrg.members.map((m) => (
                      <option key={`m-${m.id}`} value={m.id}>
                        {m.full_name ? `${m.full_name} (${m.email})` : m.email}
                      </option>
                    ))}
                  </optgroup>
                  <optgroup label="Other Platform Users">
                    {eligibleUsers
                      .filter((u) => !selectedOrg.members.some((m) => m.id === u.id))
                      .map((u) => (
                        <option key={`p-${u.id}`} value={u.id}>
                          {u.full_name ? `${u.full_name} (${u.email})` : u.email}
                        </option>
                      ))}
                  </optgroup>
                </select>
              </div>

              {assignAdminError && (
                <div className="p-3 rounded-lg bg-severity-critical-soft border border-severity-critical/30 text-severity-critical text-xs flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  {assignAdminError}
                </div>
              )}

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAssignAdminModal(false)}
                  className="px-4 py-2 rounded-lg border border-workspace-border text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-workspace transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={assigningAdmin || !adminCandidateId}
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors disabled:opacity-50 shadow-sm"
                >
                  {assigningAdmin && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  Confirm Company Admin
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrganizationView;
