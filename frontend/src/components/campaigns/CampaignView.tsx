import React, { useState, useEffect, useMemo } from 'react';
import {
  Flag,
  Plus,
  Sparkles,
  Users,
  RefreshCw,
  AlertTriangle,
  ArrowRight,
  Link2,
  Clock,
  CheckCircle2,
  Globe,
  ShieldCheck,
  Search,
  Check,
  Archive,
  MapPin,
  Navigation,
  Radio,
  Send,
} from 'lucide-react';
import {
  listCampaigns,
  getCampaign,
  createCampaign,
  updateCampaign,
  deleteCampaign,
  autoClusterCampaigns,
  getCampaignGeoInfrastructure,
  CampaignListItemResponse,
  CampaignDetailResponse,
  CampaignGeoInfrastructureResponse,
} from '../../services/api';
import { StatusBadge } from '../common/StatusBadge';
import { useAuth } from '../../context/AuthContext';

interface CampaignViewProps {
  onSelectEmail?: (emailId: string) => void;
}

const confidenceSeverity = (confidence: number): 'critical' | 'high' | 'medium' | 'low' => {
  if (confidence >= 85) return 'critical';
  if (confidence >= 65) return 'high';
  if (confidence >= 40) return 'medium';
  return 'low';
};

const fmtDate = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString() : 'Unknown');
const fmtDateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : 'Unknown');

export const CampaignView: React.FC<CampaignViewProps> = ({ onSelectEmail }) => {
  const { user, isCrossOrg, isAdmin } = useAuth();
  const isCyberCell = user?.role === 'CYBER_CELL_INVESTIGATOR' || isCrossOrg();
  const isAnalystOrAdmin = isAdmin() || user?.role === 'SECURITY_ANALYST' || isCyberCell;

  const [campaigns, setCampaigns] = useState<CampaignListItemResponse[]>([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>('');
  const [campaignDetails, setCampaignDetails] = useState<CampaignDetailResponse | null>(null);
  const [geoInfrastructure, setGeoInfrastructure] = useState<CampaignGeoInfrastructureResponse | null>(null);
  const [loadingGeo, setLoadingGeo] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [clustering, setClustering] = useState<boolean>(false);
  const [clusterNotice, setClusterNotice] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newCampaignName, setNewCampaignName] = useState<string>('');
  const [newThreatSummary, setNewThreatSummary] = useState<string>('');
  const [targetOrgFilter, setTargetOrgFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState<boolean>(false);

  useEffect(() => {
    loadCampaigns();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetOrgFilter]);

  const loadCampaigns = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listCampaigns(undefined, 0, 100, targetOrgFilter || undefined);
      setCampaigns(data || []);
      if (data && data.length > 0) {
        const initialId = selectedCampaignId && data.some((c) => c.id === selectedCampaignId) ? selectedCampaignId : data[0].id;
        setSelectedCampaignId(initialId);
        fetchCampaignDetails(initialId, data);
      } else {
        setSelectedCampaignId('');
        setCampaignDetails(null);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Error loading campaigns.');
    } finally {
      setLoading(false);
    }
  };

  const fetchCampaignDetails = async (campaignId: string, currentList?: CampaignListItemResponse[]) => {
    if (!campaignId) return;
    try {
      const data = await getCampaign(campaignId);
      setCampaignDetails(data);
    } catch (err: any) {
      console.warn(`Failed to fetch details for campaign ${campaignId}:`, err);
      const list = currentList && currentList.length > 0 ? currentList : campaigns;
      const found = list.find((c) => c.id === campaignId);
      if (found) {
        setCampaignDetails({
          id: found.id,
          campaign_name: found.campaign_name,
          campaign_status: found.campaign_status,
          campaign_confidence: found.campaign_confidence,
          threat_summary: found.threat_summary,
          first_detected_at: found.first_detected_at,
          last_activity_at: found.last_activity_at,
          total_members: found.member_count,
          total_evidence_links: 0,
          memberships: [],
          evidence: [],
          events: [],
        });
      }
    }

    // Load full transmission path and multi-receiver infrastructure
    try {
      setLoadingGeo(true);
      const geo = await getCampaignGeoInfrastructure(campaignId);
      setGeoInfrastructure(geo);
    } catch (err) {
      console.warn(`Could not load geo infrastructure for campaign ${campaignId}:`, err);
      setGeoInfrastructure(null);
    } finally {
      setLoadingGeo(false);
    }
  };

  const handleAutoCluster = async () => {
    if (!isAnalystOrAdmin) return;
    setClustering(true);
    setError(null);
    setClusterNotice(null);
    try {
      const result = await autoClusterCampaigns(60.0, targetOrgFilter || undefined);
      setClusterNotice(
        result.total_clusters_created > 0
          ? `Auto-clustering synthesized ${result.total_clusters_created} new threat campaign${result.total_clusters_created === 1 ? '' : 's'}.`
          : 'Auto-clustering completed: no new multi-signal clusters discovered above confidence threshold.'
      );
      await loadCampaigns();
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to auto-cluster campaigns.');
    } finally {
      setClustering(false);
    }
  };

  const handleCreateCampaign = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCampaignName.trim() || !isAnalystOrAdmin) return;
    try {
      const created = await createCampaign({
        campaign_name: newCampaignName.trim(),
        threat_summary: newThreatSummary.trim() || undefined,
        campaign_status: 'ACTIVE',
        organization_id: isCyberCell && targetOrgFilter ? targetOrgFilter : undefined,
      });
      setShowCreateModal(false);
      setNewCampaignName('');
      setNewThreatSummary('');
      setActionSuccess(`Campaign "${created.campaign_name}" registered successfully.`);
      setTimeout(() => setActionSuccess(null), 4000);
      await loadCampaigns();
      setSelectedCampaignId(created.id);
      fetchCampaignDetails(created.id);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to create campaign.');
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedCampaignId || !isAnalystOrAdmin) return;
    setUpdatingStatus(true);
    try {
      const updated = await updateCampaign(selectedCampaignId, { campaign_status: newStatus });
      setCampaignDetails(updated);
      setCampaigns((prev) =>
        prev.map((c) => (c.id === selectedCampaignId ? { ...c, campaign_status: newStatus } : c))
      );
      setActionSuccess(`Status updated to ${newStatus}`);
      setTimeout(() => setActionSuccess(null), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to update campaign status.');
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleArchiveCampaign = async () => {
    if (!selectedCampaignId || !isAnalystOrAdmin) return;
    if (!window.confirm('Are you sure you want to archive this threat campaign?')) return;
    try {
      await deleteCampaign(selectedCampaignId);
      setActionSuccess('Campaign archived successfully.');
      setTimeout(() => setActionSuccess(null), 3000);
      await loadCampaigns();
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to archive campaign.');
    }
  };

  const filteredCampaigns = useMemo(() => {
    return campaigns.filter((c) => {
      const matchesSearch =
        searchQuery.trim() === '' ||
        (c.campaign_name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (c.threat_summary || '').toLowerCase().includes(searchQuery.toLowerCase());
      const matchesStatus =
        statusFilter === 'ALL' || (c.campaign_status || '').toUpperCase() === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [campaigns, searchQuery, statusFilter]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Role-Specific Jurisdiction Header Banner */}
      {isCyberCell && (
        <div className="p-4 rounded-2xl bg-gradient-to-r from-blue-50/90 via-indigo-50/60 to-white border border-blue-200/90 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-100/80 border border-blue-200 text-blue-700 flex items-center justify-center shrink-0">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-black uppercase tracking-wider text-blue-950">
                  Cyber Cell Multi-Jurisdiction Investigation Hub
                </h3>
                <span className="px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 text-[10px] font-bold border border-blue-200">
                  NATIONAL / CROSS-ORG SCOPE
                </span>
              </div>
              <p className="text-xs text-blue-800/80 mt-0.5">
                Authorized for cross-tenant threat correlation, inter-institutional campaign tracking, and forensic evidence seizure.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Scope to Organization ID (optional)"
              value={targetOrgFilter}
              onChange={(e) => setTargetOrgFilter(e.target.value.trim())}
              className="px-3 py-1.5 rounded-lg bg-white border border-blue-200 text-xs text-slate-900 placeholder-blue-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-500/10 font-mono w-60"
            />
            {targetOrgFilter && (
              <button
                onClick={() => setTargetOrgFilter('')}
                className="px-2 py-1 rounded bg-blue-100 text-blue-800 text-xs hover:bg-blue-200 font-semibold"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}

      {/* Main Title & Action Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-workspace-card border border-workspace-border shadow-xs">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <Flag className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-2xl font-bold text-text-primary tracking-tight">Threat Campaigns &amp; Clusters</h1>
              {!isAnalystOrAdmin && (
                <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" /> Organization Threat Intelligence
                </span>
              )}
            </div>
            <p className="text-sm text-text-muted mt-0.5">
              Correlated clusters of phishing, spoofing, and BEC attacks linked by shared infrastructure, payloads, and temporal patterns.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          {isAnalystOrAdmin ? (
            <>
              <button
                onClick={handleAutoCluster}
                disabled={clustering}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-workspace text-text-primary border border-workspace-border text-xs font-semibold hover:bg-workspace-secondary transition-colors disabled:opacity-50 cursor-pointer shadow-xs"
                title="Automatically detect clusters across analyzed emails"
              >
                <Sparkles className={`w-3.5 h-3.5 text-brand ${clustering ? 'animate-spin' : ''}`} />
                {clustering ? 'Synthesizing…' : 'Run Auto-Cluster'}
              </button>
              <button
                onClick={() => setShowCreateModal(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-brand hover:bg-brand-hover text-white text-xs font-bold transition-colors cursor-pointer shadow-xs"
              >
                <Plus className="w-3.5 h-3.5" />
                New Campaign
              </button>
            </>
          ) : (
            <div className="text-xs text-text-muted font-medium bg-workspace px-3 py-1.5 rounded-lg border border-workspace-border">
              Viewing active threat intelligence for your organization
            </div>
          )}
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-text-muted hover:text-rose-300 font-bold px-2 py-0.5">
            Dismiss
          </button>
        </div>
      )}

      {(clusterNotice || actionSuccess) && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2.5">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          <span>{clusterNotice || actionSuccess}</span>
        </div>
      )}

      {/* Two-Column Campaign Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Filterable Campaign List */}
        <div className="rounded-2xl bg-workspace-card border border-workspace-border shadow-xs p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-text-primary">Campaigns ({filteredCampaigns.length})</h3>
            <button
              onClick={loadCampaigns}
              className="text-text-muted hover:text-brand transition-colors p-1 rounded-lg hover:bg-workspace"
              title="Refresh Campaigns"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
            <input
              type="text"
              placeholder="Search campaigns…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-workspace border border-workspace-border rounded-lg text-xs text-text-primary focus:outline-none focus:border-brand placeholder-text-muted"
            />
          </div>

          {/* Status Filter Tabs */}
          <div className="flex items-center gap-1 bg-workspace p-1 rounded-lg border border-workspace-border text-[11px] font-semibold">
            {(['ALL', 'ACTIVE', 'INVESTIGATING', 'MITIGATED'] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`flex-1 py-1 rounded-md transition-colors ${
                  statusFilter === st
                    ? 'bg-workspace-card text-brand shadow-xs font-bold'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {st === 'ALL' ? 'All' : st.slice(0, 5)}
              </button>
            ))}
          </div>

          {/* Scrollable Campaign Items */}
          <div className="space-y-2 max-h-[580px] overflow-y-auto pr-1">
            {filteredCampaigns.map((c) => {
              const isSelected = selectedCampaignId === c.id;
              return (
                <button
                  key={c.id}
                  onClick={() => {
                    setSelectedCampaignId(c.id);
                    fetchCampaignDetails(c.id);
                  }}
                  className={`w-full text-left p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-brand/10 border-brand shadow-xs'
                      : 'bg-workspace border-workspace-border hover:border-brand/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-xs text-text-primary truncate">
                      {c.campaign_name || 'Unnamed Campaign'}
                    </span>
                    <StatusBadge type="severity" value={confidenceSeverity(c.campaign_confidence)} label={c.campaign_status} size="sm" />
                  </div>
                  <div className="flex items-center justify-between text-xs text-text-muted mt-2">
                    <span className="flex items-center gap-1 font-medium">
                      <Users className="w-3 h-3 text-brand" /> {c.member_count} member email{c.member_count === 1 ? '' : 's'}
                    </span>
                    <span className="font-mono text-text-secondary text-[11px] font-semibold">
                      {c.campaign_confidence.toFixed(0)}% Conf.
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-text-muted mt-1.5 pt-1.5 border-t border-workspace-border/50">
                    <span>First: {fmtDate(c.first_detected_at)}</span>
                    <span>Last: {fmtDate(c.last_activity_at)}</span>
                  </div>
                </button>
              );
            })}
            {filteredCampaigns.length === 0 && !loading && (
              <div className="py-12 text-center space-y-3">
                <Flag className="w-8 h-8 text-text-muted mx-auto opacity-40" />
                <p className="text-xs font-semibold text-text-primary">No matching campaigns found</p>
                <p className="text-[11px] text-text-muted px-4">
                  {searchQuery || statusFilter !== 'ALL'
                    ? 'Adjust search keywords or status filter.'
                    : 'Run auto-clustering to discover correlated attack groups.'}
                </p>
                {isAnalystOrAdmin && (
                  <button
                    onClick={handleAutoCluster}
                    disabled={clustering}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand text-white text-xs font-bold hover:bg-brand-hover transition-colors"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    Auto-Cluster Now
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Campaign Dossier Details */}
        <div className="lg:col-span-2 space-y-6">
          {campaignDetails ? (
            <div className="space-y-6">
              {/* Executive Overview Card */}
              <div className="rounded-2xl bg-workspace-card border border-workspace-border shadow-xs p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h2 className="text-lg font-bold text-text-primary tracking-tight">
                      {campaignDetails.campaign_name || 'Unnamed Campaign'}
                    </h2>
                    <div className="text-xs text-text-muted font-mono mt-0.5">
                      Campaign Identifier: <strong className="text-text-secondary">{campaignDetails.id}</strong>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    <StatusBadge
                      type="severity"
                      value={confidenceSeverity(campaignDetails.campaign_confidence)}
                      label={`${campaignDetails.campaign_status} · ${campaignDetails.campaign_confidence.toFixed(0)}%`}
                    />
                    {isAnalystOrAdmin && (
                      <div className="flex items-center gap-1">
                        <select
                          value={campaignDetails.campaign_status}
                          onChange={(e) => handleStatusChange(e.target.value)}
                          disabled={updatingStatus}
                          className="bg-workspace border border-workspace-border rounded-lg px-2.5 py-1 text-xs font-semibold text-text-primary focus:outline-none focus:border-brand cursor-pointer"
                        >
                          <option value="ACTIVE">ACTIVE</option>
                          <option value="INVESTIGATING">INVESTIGATING</option>
                          <option value="MITIGATED">MITIGATED</option>
                          <option value="ARCHIVED">ARCHIVED</option>
                        </select>
                        <button
                          onClick={handleArchiveCampaign}
                          className="p-1 rounded-lg bg-workspace border border-workspace-border text-text-muted hover:text-rose-400 transition-colors"
                          title="Archive Campaign"
                        >
                          <Archive className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-workspace border border-workspace-border space-y-1">
                  <div className="text-[11px] font-bold text-text-muted uppercase tracking-wider">Adversary Threat Summary</div>
                  <p className="text-xs text-text-secondary leading-relaxed">
                    {campaignDetails.threat_summary || 'No threat summary provided for this campaign.'}
                  </p>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                  <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                    <div className="text-[10px] font-bold text-text-muted uppercase">First Detected</div>
                    <div className="font-semibold text-text-primary text-xs mt-0.5">{fmtDate(campaignDetails.first_detected_at)}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                    <div className="text-[10px] font-bold text-text-muted uppercase">Last Activity</div>
                    <div className="font-semibold text-text-primary text-xs mt-0.5">{fmtDate(campaignDetails.last_activity_at)}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                    <div className="text-[10px] font-bold text-text-muted uppercase">Correlated Members</div>
                    <div className="font-bold text-brand text-sm mt-0.5">{campaignDetails.total_members}</div>
                  </div>
                  <div className="p-3 rounded-xl bg-workspace border border-workspace-border">
                    <div className="text-[10px] font-bold text-text-muted uppercase">Evidence Links</div>
                    <div className="font-bold text-brand text-sm mt-0.5">{campaignDetails.total_evidence_links}</div>
                  </div>
                </div>
              </div>

              {/* Tactical Transmission Flight Path: Sender Origin -> Multiple Target Receivers */}
              <div className="rounded-2xl bg-workspace-card border border-workspace-border shadow-xs p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center">
                        <Navigation className="w-4 h-4" />
                      </div>
                      <h3 className="text-sm font-bold text-text-primary tracking-tight">
                        Adversary Flight Path: Sender Origin → Multiple Target Receivers
                      </h3>
                    </div>
                    <p className="text-[11px] text-text-muted mt-1">
                      Reconstructed transmission path connecting threat actor dispatch infrastructure to victim organizational inboxes.
                    </p>
                  </div>

                  {geoInfrastructure && (
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2.5 py-1 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-[11px] font-bold flex items-center gap-1 font-mono">
                        <Radio className="w-3 h-3 text-rose-400" />
                        {geoInfrastructure.senders?.length || 1} Attacker Origin{geoInfrastructure.senders?.length === 1 ? '' : 's'}
                      </span>
                      <span className="px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[11px] font-bold flex items-center gap-1 font-mono">
                        <MapPin className="w-3 h-3 text-emerald-400" />
                        {geoInfrastructure.receivers?.length || 1} Target Receiver Location{geoInfrastructure.receivers?.length === 1 ? '' : 's'}
                      </span>
                    </div>
                  )}
                </div>

                {/* Interactive Visual Flight Vectors */}
                {loadingGeo ? (
                  <div className="p-8 text-center text-xs text-text-muted animate-pulse">
                    Resolving international dispatch infrastructure and recipient geolocations…
                  </div>
                ) : geoInfrastructure && geoInfrastructure.transmission_paths && geoInfrastructure.transmission_paths.length > 0 ? (
                  <div className="space-y-3">
                    {geoInfrastructure.transmission_paths.map((path, idx) => (
                      <div
                        key={`${path.email_id}-${path.recipient_address}-${idx}`}
                        className="p-4 rounded-xl bg-workspace border border-workspace-border hover:border-brand/40 transition-all space-y-3 text-xs"
                      >
                        {/* Top: Email Subject & Summary */}
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="font-bold text-text-primary truncate max-w-md">
                            {path.email_subject || 'Threat Transmission'}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-workspace-card border border-workspace-border text-text-muted font-mono text-[10px]">
                            Vector #{idx + 1} · {path.hops_count} Transit Hops
                          </span>
                        </div>

                        {/* 3-Column Flight Path Diagram */}
                        <div className="grid grid-cols-1 md:grid-cols-11 gap-3 items-center pt-1">
                          {/* 1. Attacker Sender Origin Node (5 cols) */}
                          <div className="md:col-span-5 p-3 rounded-xl bg-rose-500/5 border border-rose-500/20 space-y-1.5">
                            <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-wider">
                              <span className="text-rose-400 flex items-center gap-1">
                                <Send className="w-3 h-3" /> Adversary Dispatch Origin
                              </span>
                              <span className="font-mono text-rose-300">
                                [{path.sender_coords[0]?.toFixed(2) || '0.00'}, {path.sender_coords[1]?.toFixed(2) || '0.00'}]
                              </span>
                            </div>
                            <div className="font-bold text-text-primary truncate text-xs">
                              {path.sender_address || 'Unverified Threat Actor'}
                            </div>
                            <div className="text-[11px] text-text-muted flex items-center gap-1.5 flex-wrap">
                              <MapPin className="w-3 h-3 text-rose-400 shrink-0" />
                              <strong className="text-text-secondary">{path.sender_city}, {path.sender_country}</strong>
                              <span className="font-mono text-[10px] bg-workspace-card px-1.5 py-0.5 rounded border border-workspace-border text-text-muted">
                                IP: {path.sender_origin_ip || 'Private/TOR'}
                              </span>
                            </div>
                          </div>

                          {/* 2. Transmission Flight Indicator (1 col) */}
                          <div className="md:col-span-1 flex flex-col items-center justify-center py-1">
                            <div className="hidden md:flex items-center justify-center w-full">
                              <div className="h-0.5 flex-1 bg-gradient-to-r from-rose-500/50 via-amber-500/50 to-emerald-500/50" />
                              <ArrowRight className="w-4 h-4 text-emerald-400 shrink-0 mx-0.5" />
                            </div>
                            <span className="text-[9px] font-mono text-text-muted font-bold mt-1 text-center whitespace-nowrap">
                              INTERNET
                            </span>
                          </div>

                          {/* 3. Targeted Receiver Inbox Node (5 cols) */}
                          <div className="md:col-span-5 p-3 rounded-xl bg-emerald-500/5 border border-emerald-500/20 space-y-1.5">
                            <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-wider">
                              <span className="text-emerald-400 flex items-center gap-1">
                                <MapPin className="w-3 h-3" /> Targeted Receiver Inbox
                              </span>
                              <span className="font-mono text-emerald-300">
                                [{path.recipient_coords[0]?.toFixed(2) || '0.00'}, {path.recipient_coords[1]?.toFixed(2) || '0.00'}]
                              </span>
                            </div>
                            <div className="font-bold text-text-primary truncate text-xs">
                              {path.recipient_address || 'Employee Inbox'}
                            </div>
                            <div className="text-[11px] text-text-muted flex items-center gap-1.5 flex-wrap">
                              <Globe className="w-3 h-3 text-emerald-400 shrink-0" />
                              <strong className="text-text-secondary">{path.recipient_city}, {path.recipient_country}</strong>
                              <span className="font-mono text-[10px] bg-workspace-card px-1.5 py-0.5 rounded border border-workspace-border text-text-muted">
                                Domain: {path.recipient_domain}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-text-muted py-6 text-center rounded-xl bg-workspace border border-dashed border-workspace-border">
                    {campaignDetails.memberships.length > 0
                      ? 'Resolving origin transmission hops and recipient locations for linked campaign emails…'
                      : 'Link emails to this campaign to reconstruct the adversary transmission flight path.'}
                  </div>
                )}
              </div>

              {/* Linked Member Emails */}
              <div className="rounded-2xl bg-workspace-card border border-workspace-border shadow-xs p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-text-primary">
                    Correlated Email Members ({campaignDetails.memberships.length})
                  </h3>
                  <span className="text-[11px] text-text-muted">Click Inspect to explore in DNA Workspace</span>
                </div>

                <div className="space-y-2">
                  {campaignDetails.memberships.map((m) => (
                    <div
                      key={m.id}
                      className="p-3.5 rounded-xl bg-workspace border border-workspace-border flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="font-bold text-text-primary truncate">{m.email_subject || m.email_id}</div>
                        <div className="text-[11px] text-text-muted truncate mt-0.5 font-mono">
                          Sender: <strong className="text-text-secondary">{m.email_sender || 'Unknown'}</strong>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        <span className="px-2 py-0.5 rounded bg-brand/10 border border-brand/20 text-brand font-mono font-bold text-[10px]">
                          {m.membership_confidence.toFixed(0)}% Confidence
                        </span>
                        {onSelectEmail && (
                          <button
                            onClick={() => onSelectEmail(m.email_id)}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-brand hover:bg-brand-hover text-white text-xs font-bold transition-colors cursor-pointer"
                          >
                            Inspect
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                  {campaignDetails.memberships.length === 0 && (
                    <div className="text-xs text-text-muted py-6 text-center rounded-xl bg-workspace border border-dashed border-workspace-border">
                      No emails currently linked to this campaign.
                    </div>
                  )}
                </div>
              </div>

              {/* Correlated Evidence Links */}
              {campaignDetails.evidence.length > 0 && (
                <div className="rounded-2xl bg-workspace-card border border-workspace-border shadow-xs p-5 space-y-3">
                  <h3 className="text-sm font-bold text-text-primary">Forensic Correlated Evidence Links</h3>
                  <div className="space-y-2">
                    {campaignDetails.evidence.map((ev) => (
                      <div
                        key={ev.id}
                        className="p-3.5 rounded-xl bg-workspace border border-workspace-border flex items-center justify-between gap-3 text-xs"
                      >
                        <div className="min-w-0">
                          <div className="font-bold text-text-primary flex items-center gap-1.5">
                            <Link2 className="w-3.5 h-3.5 text-brand shrink-0" />
                            {ev.evidence_type}
                          </div>
                          <div className="text-[11px] text-text-muted mt-0.5">{ev.explanation}</div>
                        </div>
                        <span className="font-mono text-xs text-text-secondary font-bold shrink-0">
                          {ev.confidence.toFixed(0)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Campaign Timeline */}
              {campaignDetails.events.length > 0 && (
                <div className="rounded-2xl bg-workspace-card border border-workspace-border shadow-xs p-5 space-y-3">
                  <h3 className="text-sm font-bold text-text-primary">Campaign Activity Timeline</h3>
                  <div className="space-y-3">
                    {campaignDetails.events.map((ev) => (
                      <div key={ev.id} className="flex gap-3 text-xs">
                        <div className="w-6 h-6 rounded-full bg-brand/10 text-brand flex items-center justify-center shrink-0 mt-0.5">
                          <Clock className="w-3 h-3" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-text-primary font-bold">
                            <span>{ev.event_type.replace(/_/g, ' ')}</span>
                            <span className="text-text-muted font-normal"> — {fmtDateTime(ev.occurred_at)}</span>
                          </div>
                          <div className="text-[11px] text-text-muted mt-0.5">{ev.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-2xl bg-workspace-card border border-workspace-border shadow-xs p-16 text-center space-y-2">
              <Flag className="w-8 h-8 mx-auto text-text-muted opacity-50 mb-2" />
              <h3 className="font-bold text-sm text-text-primary">No Campaign Selected</h3>
              <p className="text-xs text-text-muted max-w-sm mx-auto">
                Select a threat campaign from the list on the left to inspect its linked emails, shared infrastructure, and timeline.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Create Campaign Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-navy-sidebar/70 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-workspace-card border border-workspace-border rounded-2xl max-w-md w-full p-6 shadow-xl space-y-4">
            <h3 className="text-base font-bold text-text-primary flex items-center gap-2">
              <Flag className="w-4 h-4 text-brand" />
              Register New Threat Campaign
            </h3>
            <form onSubmit={handleCreateCampaign} className="space-y-4">
              <div>
                <label className="text-xs font-bold text-text-secondary block mb-1.5">Campaign Name</label>
                <input
                  type="text"
                  value={newCampaignName}
                  onChange={(e) => setNewCampaignName(e.target.value)}
                  placeholder="e.g. Payroll credential phishing campaign"
                  required
                  className="w-full px-3.5 py-2 text-xs bg-workspace border border-workspace-border rounded-xl text-text-primary focus:outline-none focus:border-brand font-medium"
                />
              </div>

              <div>
                <label className="text-xs font-bold text-text-secondary block mb-1.5">Adversary Threat Summary</label>
                <textarea
                  value={newThreatSummary}
                  onChange={(e) => setNewThreatSummary(e.target.value)}
                  placeholder="Describe the attack lure pattern, targets, and shared infrastructure indicators…"
                  rows={3}
                  className="w-full px-3.5 py-2 text-xs bg-workspace border border-workspace-border rounded-xl text-text-primary focus:outline-none focus:border-brand font-medium"
                />
              </div>

              <div className="flex justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl bg-workspace text-text-secondary hover:text-text-primary border border-workspace-border text-xs font-semibold transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-brand text-white text-xs font-bold hover:bg-brand-hover transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  <Check className="w-3.5 h-3.5" />
                  Create Campaign
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default CampaignView;
