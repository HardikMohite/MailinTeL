import React, { useState, useEffect } from 'react';
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
  Network,
  Mail,
  ShieldAlert,
  X,
  ExternalLink,
  ChevronRight,
  UserCheck,
} from 'lucide-react';
import {
  listCampaigns,
  getCampaign,
  createCampaign,
  autoClusterCampaigns,
  CampaignListItemResponse,
  CampaignDetailResponse,
  TargetedUserSummary,
} from '../../services/api';
import { StatusBadge } from '../common/StatusBadge';
import { GeoIntelligenceMap } from '../geo/GeoIntelligenceMap';
import { InvestigationGraphView } from '../graph/InvestigationGraphView';

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
  const [campaigns, setCampaigns] = useState<CampaignListItemResponse[]>([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>('');
  const [campaignDetails, setCampaignDetails] = useState<CampaignDetailResponse | null>(null);
  const [campaignTab, setCampaignTab] = useState<'overview' | 'geo' | 'graph'>('overview');
  const [selectedTargetUser, setSelectedTargetUser] = useState<TargetedUserSummary | null>(null);
  const [minTargets, setMinTargets] = useState<number>(2);

  const [loading, setLoading] = useState<boolean>(false);
  const [clustering, setClustering] = useState<boolean>(false);
  const [clusterNotice, setClusterNotice] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newCampaignName, setNewCampaignName] = useState<string>('');
  const [newThreatSummary, setNewThreatSummary] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadCampaigns();
  }, []);

  const loadCampaigns = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listCampaigns(undefined, 0, 50);
      setCampaigns(data || []);
      if (data && data.length > 0) {
        const isValid = selectedCampaignId && data.some((c) => c.id === selectedCampaignId);
        const targetId = isValid ? selectedCampaignId : data[0].id;
        setSelectedCampaignId(targetId);
        fetchCampaignDetails(targetId, data);
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

  const fetchCampaignDetails = async (campaignId: string, currentCampaignList?: CampaignListItemResponse[]) => {
    if (!campaignId) return;
    try {
      const data = await getCampaign(campaignId);
      setCampaignDetails(data);
      setError(null);
    } catch (err: any) {
      console.warn(`Failed to fetch details for campaign ${campaignId}:`, err);
      const availableList = currentCampaignList || campaigns;
      // If 404 and fallback is available, silently switch to the first campaign
      if (err.response?.status === 404 && availableList.length > 0 && campaignId !== availableList[0].id) {
        const fallbackId = availableList[0].id;
        setSelectedCampaignId(fallbackId);
        try {
          const fallbackData = await getCampaign(fallbackId);
          setCampaignDetails(fallbackData);
          setError(null);
          return;
        } catch {
          // Fall through
        }
      }
      // Graceful fallback: construct basic detail view from existing campaign list item so page never shows blocking Network Error
      const found = availableList.find((c) => c.id === campaignId);
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
      } else {
        setError(err.response?.data?.detail || err.message || 'Failed to load campaign details.');
      }
    }
  };

  const handleAutoCluster = async () => {
    setClustering(true);
    setError(null);
    setClusterNotice(null);
    try {
      const result = await autoClusterCampaigns(60.0, minTargets);
      setClusterNotice(
        result.total_clusters_created > 0
          ? `Auto-clustering created ${result.total_clusters_created} new campaign${result.total_clusters_created === 1 ? '' : 's'} (Target threshold: ${minTargets}+ mailboxes).`
          : `Auto-clustering finished. No new correlated groups or distributed attacks (>= ${minTargets} targets) detected.`
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
    if (!newCampaignName.trim()) return;
    try {
      const created = await createCampaign({
        campaign_name: newCampaignName.trim(),
        threat_summary: newThreatSummary.trim() || undefined,
        campaign_status: 'ACTIVE',
      });
      setShowCreateModal(false);
      setNewCampaignName('');
      setNewThreatSummary('');
      await loadCampaigns();
      setSelectedCampaignId(created.id);
      fetchCampaignDetails(created.id);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to create campaign.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title + Description + Primary Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <Flag className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary tracking-tight">Campaigns</h1>
            <p className="text-sm text-text-muted mt-0.5">
              Correlated threat groups and multi-user targeted phishing attacks clustered by shared infrastructure.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 bg-workspace px-3 py-1.5 rounded-lg border border-workspace-border text-xs text-text-muted">
            <span>Target Threshold:</span>
            <select
              value={minTargets}
              onChange={(e) => setMinTargets(Number(e.target.value))}
              className="bg-workspace-card text-text-primary text-xs font-semibold px-2 py-0.5 rounded border border-workspace-border focus:outline-none focus:border-brand"
              title="Minimum targeted users to auto-create a distributed attack campaign"
            >
              <option value={2}>2+ users</option>
              <option value={3}>3+ users</option>
              <option value={4}>4+ users</option>
              <option value={5}>5+ users</option>
              <option value={6}>6+ users</option>
              <option value={10}>10+ users</option>
            </select>
          </div>

          <button
            onClick={handleAutoCluster}
            disabled={clustering}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-workspace-card text-text-primary border border-workspace-border text-sm font-semibold hover:bg-workspace-secondary transition-colors disabled:opacity-50"
          >
            <Sparkles className={`w-4 h-4 text-brand ${clustering ? 'animate-spin' : ''}`} />
            {clustering ? 'Clustering…' : 'Run Auto-Cluster'}
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-white text-sm font-semibold hover:bg-brand-hover transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Campaign
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-lg bg-severity-high-soft border border-severity-high/20 text-severity-high text-sm flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {clusterNotice && !error && (
        <div className="p-3.5 rounded-lg bg-severity-safe-soft border border-severity-safe/20 text-severity-safe text-sm flex items-center gap-2.5">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{clusterNotice}</span>
        </div>
      )}

      {/* Main Campaign Layout (List + Detail) */}
      <div className={`grid grid-cols-1 ${campaignTab === 'overview' ? 'lg:grid-cols-3' : 'lg:grid-cols-4'} gap-6`}>
        {/* Campaign List */}
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-workspace-border pb-3">
            <h3 className="text-sm font-bold text-text-primary">Campaigns ({campaigns.length})</h3>
            <button
              onClick={loadCampaigns}
              className="text-text-muted hover:text-brand transition-colors p-1"
              title="Refresh"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="space-y-2 max-h-[640px] overflow-y-auto">
            {campaigns.map((c) => {
              const isSelected = selectedCampaignId === c.id;
              return (
                <button
                  key={c.id}
                  onClick={() => {
                    setSelectedCampaignId(c.id);
                    fetchCampaignDetails(c.id);
                  }}
                  className={`w-full text-left p-3.5 rounded-lg border transition-colors ${
                    isSelected
                      ? 'bg-brand-soft border-brand/40'
                      : 'bg-workspace border-workspace-border hover:border-brand/30'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-sm text-text-primary truncate">
                      {c.campaign_name || 'Unnamed campaign'}
                    </span>
                    <StatusBadge type="severity" value={confidenceSeverity(c.campaign_confidence)} label={c.campaign_status} size="sm" />
                  </div>
                  <div className="flex items-center justify-between text-xs text-text-muted mt-2">
                    <span className="flex items-center gap-1">
                      <Users className="w-3 h-3" /> {c.member_count} members
                    </span>
                    <span className="font-mono text-text-secondary font-medium">
                      {c.campaign_confidence.toFixed(0)}% confidence
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-text-muted mt-1.5">
                    <span>First seen {fmtDate(c.first_detected_at)}</span>
                    <span>Last active {fmtDate(c.last_activity_at)}</span>
                  </div>
                </button>
              );
            })}
            {campaigns.length === 0 && !loading && (
              <div className="py-10 text-center space-y-3">
                <Flag className="w-8 h-8 text-text-muted mx-auto opacity-50" />
                <p className="text-sm font-semibold text-text-primary">No campaigns detected yet</p>
                <p className="text-xs text-text-muted px-4">
                  Run auto-clustering to correlate analyzed emails into campaigns based on shared infrastructure or multi-target attacks.
                </p>
                <button
                  onClick={handleAutoCluster}
                  disabled={clustering}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors disabled:opacity-50"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${clustering ? 'animate-spin' : ''}`} />
                  {clustering ? 'Clustering…' : 'Run Auto-Cluster'}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Campaign Detail */}
        <div className={`${campaignTab === 'overview' ? 'lg:col-span-2' : 'lg:col-span-3'} space-y-6`}>
          {campaignDetails ? (
            <div className="space-y-6">
              {/* Campaign Detail Subtabs Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 p-1.5 rounded-xl bg-workspace-card border border-workspace-border shadow-sm">
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => setCampaignTab('overview')}
                    className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition-all ${
                      campaignTab === 'overview'
                        ? 'bg-brand text-white shadow-sm'
                        : 'text-text-muted hover:text-text-primary hover:bg-workspace'
                    }`}
                  >
                    <Users className="w-4 h-4" />
                    <span>Overview & Victims</span>
                    {campaignDetails.targeted_users && campaignDetails.targeted_users.length > 0 && (
                      <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                        campaignTab === 'overview' ? 'bg-white/20 text-white' : 'bg-brand-soft text-brand'
                      }`}>
                        {campaignDetails.targeted_users.length}
                      </span>
                    )}
                  </button>

                  <button
                    onClick={() => setCampaignTab('geo')}
                    className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition-all ${
                      campaignTab === 'geo'
                        ? 'bg-brand text-white shadow-sm'
                        : 'text-text-muted hover:text-text-primary hover:bg-workspace'
                    }`}
                  >
                    <Globe className="w-4 h-4" />
                    <span>Geo Intelligence Map</span>
                  </button>

                  <button
                    onClick={() => setCampaignTab('graph')}
                    className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold transition-all ${
                      campaignTab === 'graph'
                        ? 'bg-brand text-white shadow-sm'
                        : 'text-text-muted hover:text-text-primary hover:bg-workspace'
                    }`}
                  >
                    <Network className="w-4 h-4" />
                    <span>Node Infrastructure Graph</span>
                  </button>
                </div>

                <div className="text-xs text-text-muted px-2 font-mono hidden sm:block">
                  Campaign: <span className="text-text-primary font-semibold">{campaignDetails.campaign_name || campaignDetails.id.slice(0, 8)}</span>
                </div>
              </div>

              {/* Subtab 1: Overview & Victims */}
              {campaignTab === 'overview' && (
                <div className="space-y-6">
                  {/* Campaign Header KPI Card */}
                  <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <h2 className="text-lg font-bold text-text-primary">
                        {campaignDetails.campaign_name || 'Unnamed campaign'}
                      </h2>
                      <StatusBadge
                        type="severity"
                        value={confidenceSeverity(campaignDetails.campaign_confidence)}
                        label={`${campaignDetails.campaign_status} · ${campaignDetails.campaign_confidence.toFixed(0)}%`}
                      />
                    </div>

                    <p className="text-sm text-text-secondary leading-relaxed bg-workspace p-3.5 rounded-lg border border-workspace-border">
                      {campaignDetails.threat_summary || 'No threat summary provided for this campaign.'}
                    </p>

                    {/* Submitter / Reporting Users Attribution */}
                    {campaignDetails.reporting_users && campaignDetails.reporting_users.length > 0 && (
                      <div className="flex flex-wrap items-center gap-2 p-3 rounded-lg bg-workspace border border-workspace-border">
                        <span className="text-xs text-text-muted font-medium flex items-center gap-1.5">
                          <UserCheck className="w-4 h-4 text-brand" />
                          <span>Submitted / Reported by:</span>
                        </span>
                        {campaignDetails.reporting_users.map((u) => (
                          <span
                            key={u.user_id || u.email}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-brand-soft border border-brand/30 text-xs text-brand font-medium"
                          >
                            <span className="font-bold text-text-primary">{u.username || 'User'}</span>
                            <span className="text-text-muted font-mono text-[11px]">({u.email})</span>
                            <span className="px-1.5 py-0.2 rounded-full bg-brand/20 text-brand text-[10px] font-mono font-bold">
                              {u.emails_count} {u.emails_count === 1 ? 'upload' : 'uploads'}
                            </span>
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
                      <div className="p-3 rounded-lg bg-workspace border border-workspace-border">
                        <div className="text-[11px] text-text-muted">First Detected</div>
                        <div className="font-semibold text-text-primary text-xs mt-0.5">{fmtDate(campaignDetails.first_detected_at)}</div>
                      </div>
                      <div className="p-3 rounded-lg bg-workspace border border-workspace-border">
                        <div className="text-[11px] text-text-muted">Last Activity</div>
                        <div className="font-semibold text-text-primary text-xs mt-0.5">{fmtDate(campaignDetails.last_activity_at)}</div>
                      </div>
                      <div className="p-3 rounded-lg bg-workspace border border-workspace-border">
                        <div className="text-[11px] text-text-muted">Member Emails</div>
                        <div className="font-bold text-brand text-sm mt-0.5">{campaignDetails.total_members}</div>
                      </div>
                      <div className="p-3 rounded-lg bg-workspace border border-workspace-border">
                        <div className="text-[11px] text-text-muted">Evidence Links</div>
                        <div className="font-bold text-brand text-sm mt-0.5">{campaignDetails.total_evidence_links}</div>
                      </div>
                      <div className="p-3 rounded-lg bg-workspace border border-workspace-border col-span-2 sm:col-span-1">
                        <div className="text-[11px] text-text-muted">Targeted Victims</div>
                        <div className="font-bold text-severity-high text-sm mt-0.5">
                          {campaignDetails.targeted_users?.length || 0}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Targeted Victims Breakdown */}
                  <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-workspace-border pb-3">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-severity-high/10 text-severity-high flex items-center justify-center shrink-0 border border-severity-high/20">
                          <ShieldAlert className="w-4 h-4" />
                        </div>
                        <div>
                          <h3 className="text-sm font-bold text-text-primary">
                            Targeted Victims & Mailboxes ({campaignDetails.targeted_users?.length || 0})
                          </h3>
                          <p className="text-xs text-text-muted mt-0.5">
                            Internal accounts receiving attack emails in this coordinated campaign. Click any target to inspect the emails sent to them.
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Victim Cards Grid */}
                    {campaignDetails.targeted_users && campaignDetails.targeted_users.length > 0 ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {campaignDetails.targeted_users.map((victim) => (
                          <div
                            key={victim.recipient_address}
                            onClick={() => setSelectedTargetUser(victim)}
                            className="p-4 rounded-xl bg-workspace border border-workspace-border hover:border-brand/50 hover:bg-workspace-secondary/50 transition-all cursor-pointer group space-y-3 shadow-xs"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="font-mono text-sm font-bold text-text-primary truncate group-hover:text-brand transition-colors">
                                    {victim.recipient_address}
                                  </span>
                                  {victim.is_internal_account && (
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shrink-0">
                                      Registered User
                                    </span>
                                  )}
                                </div>
                                {victim.display_name && (
                                  <div className="text-xs text-text-secondary truncate mt-0.5">
                                    {victim.display_name}
                                  </div>
                                )}
                              </div>
                              <span className="px-2 py-0.5 rounded-full text-xs font-bold font-mono bg-severity-high/15 text-severity-high border border-severity-high/30 shrink-0">
                                {victim.emails_count} {victim.emails_count === 1 ? 'target hit' : 'target hits'}
                              </span>
                            </div>

                            <div className="flex items-center justify-between text-[11px] text-text-muted pt-2 border-t border-workspace-border/60">
                              <span>First: {fmtDate(victim.first_targeted_at)}</span>
                              <span>Last: {fmtDate(victim.last_targeted_at)}</span>
                            </div>

                            <div className="flex items-center justify-end text-xs font-semibold text-brand group-hover:translate-x-0.5 transition-transform gap-1">
                              <span>Inspect attack mails</span>
                              <ChevronRight className="w-3.5 h-3.5" />
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-sm text-text-muted py-6 text-center">
                        No distinct victim mailboxes parsed for this campaign yet.
                      </div>
                    )}
                  </div>

                  {/* Member Emails */}
                  <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
                    <h3 className="text-sm font-bold text-text-primary">Member Emails ({campaignDetails.memberships.length})</h3>
                    <div className="space-y-2">
                      {campaignDetails.memberships.map((m) => (
                        <div key={m.id} className="p-3.5 rounded-lg bg-workspace border border-workspace-border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                          <div className="min-w-0 flex-1 space-y-1">
                            <div className="font-medium text-sm text-text-primary truncate">{m.email_subject || m.email_id}</div>
                            <div className="text-xs text-text-muted flex flex-wrap items-center gap-x-3 gap-y-1">
                              <span>From: <strong className="text-text-secondary font-mono">{m.email_sender || 'Unknown sender'}</strong></span>
                              {m.sent_at && <span>Sent: <strong className="text-text-secondary">{fmtDateTime(m.sent_at)}</strong></span>}
                              {m.submitted_by_name && (
                                <span className="inline-flex items-center gap-1 text-brand font-medium">
                                  <UserCheck className="w-3 h-3" />
                                  <span>Submitted by: <strong>{m.submitted_by_name}</strong> {m.submitted_by_email ? `(${m.submitted_by_email})` : ''}</span>
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-3 shrink-0">
                            <span className="font-mono text-xs text-text-secondary font-medium">{m.membership_confidence.toFixed(0)}%</span>
                            {onSelectEmail && (
                              <button
                                onClick={() => onSelectEmail(m.email_id)}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors"
                              >
                                Inspect
                                <ArrowRight className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        </div>
                      ))}
                      {campaignDetails.memberships.length === 0 && (
                        <div className="text-sm text-text-muted py-4 text-center">
                          No emails linked to this campaign yet.
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Evidence Links */}
                  {campaignDetails.evidence.length > 0 && (
                    <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
                      <h3 className="text-sm font-bold text-text-primary">Correlated Evidence</h3>
                      <div className="space-y-2">
                        {campaignDetails.evidence.map((ev) => (
                          <div key={ev.id} className="p-3.5 rounded-lg bg-workspace border border-workspace-border flex items-center justify-between gap-3">
                            <div className="min-w-0">
                              <div className="font-semibold text-sm text-text-primary flex items-center gap-1.5">
                                <Link2 className="w-3.5 h-3.5 text-brand shrink-0" />
                                {ev.evidence_type}
                              </div>
                              <div className="text-xs text-text-secondary mt-0.5">{ev.explanation}</div>
                            </div>
                            <span className="font-mono text-xs text-text-secondary font-medium shrink-0">{ev.confidence.toFixed(0)}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Campaign Timeline */}
                  {campaignDetails.events.length > 0 && (
                    <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
                      <h3 className="text-sm font-bold text-text-primary">Campaign Timeline</h3>
                      <div className="space-y-3">
                        {campaignDetails.events.map((ev) => (
                          <div key={ev.id} className="flex gap-3">
                            <div className="w-6 h-6 rounded-full bg-brand-soft text-brand flex items-center justify-center shrink-0 mt-0.5">
                              <Clock className="w-3 h-3" />
                            </div>
                            <div className="min-w-0">
                              <div className="text-sm text-text-primary">
                                <span className="font-semibold">{ev.event_type.replace(/_/g, ' ')}</span>
                                <span className="text-text-muted"> — {fmtDateTime(ev.occurred_at)}</span>
                              </div>
                              <div className="text-xs text-text-secondary mt-0.5">{ev.description}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Subtab 2: Geo Intelligence Map */}
              {campaignTab === 'geo' && (
                <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-4 space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-workspace-border">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-brand" />
                      <h3 className="text-sm font-bold text-text-primary">
                        Campaign Geographic Threat Distribution & Relay Hops
                      </h3>
                    </div>
                    <span className="text-xs text-text-muted">
                      Campaign: <strong className="text-text-primary">{campaignDetails.campaign_name}</strong>
                    </span>
                  </div>
                  <GeoIntelligenceMap initialCampaignId={selectedCampaignId} embedded={true} />
                </div>
              )}

              {/* Subtab 3: Node Infrastructure Graph */}
              {campaignTab === 'graph' && (
                <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-4 space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-workspace-border">
                    <div className="flex items-center gap-2">
                      <Network className="w-4 h-4 text-brand" />
                      <h3 className="text-sm font-bold text-text-primary">
                        Campaign Relational Infrastructure Graph
                      </h3>
                    </div>
                    <span className="text-xs text-text-muted">
                      Campaign: <strong className="text-text-primary">{campaignDetails.campaign_name}</strong>
                    </span>
                  </div>
                  <InvestigationGraphView initialCampaignId={selectedCampaignId} onSelectEmail={onSelectEmail} embedded={true} />
                </div>
              )}
            </div>
          ) : (
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-16 text-center">
              <Flag className="w-8 h-8 mx-auto text-text-muted opacity-60 mb-2" />
              <h3 className="font-semibold text-sm text-text-primary">No campaign selected</h3>
              <p className="text-sm text-text-muted mt-1">Select a campaign on the left to view its members, targeted victims, and forensics.</p>
            </div>
          )}
        </div>
      </div>

      {/* Target User Attack Emails Modal */}
      {selectedTargetUser && (
        <div className="fixed inset-0 bg-navy-sidebar/70 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-workspace-card border border-workspace-border rounded-xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
            {/* Header */}
            <div className="p-5 border-b border-workspace-border flex items-center justify-between bg-workspace/50">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-severity-high/10 text-severity-high flex items-center justify-center shrink-0 border border-severity-high/20">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-text-primary font-mono truncate max-w-md">
                      {selectedTargetUser.recipient_address}
                    </h3>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-severity-high/20 text-severity-high font-bold border border-severity-high/30">
                      {selectedTargetUser.emails_count} attack {selectedTargetUser.emails_count === 1 ? 'mail' : 'mails'}
                    </span>
                  </div>
                  <p className="text-xs text-text-muted mt-0.5">
                    {selectedTargetUser.display_name ? `Target Name: ${selectedTargetUser.display_name} · ` : ''}
                    Coordinated adversary email targeting history
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedTargetUser(null)}
                className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-workspace transition-colors"
                title="Close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Summary Sub-bar */}
            <div className="px-5 py-3 bg-workspace border-b border-workspace-border flex flex-wrap items-center justify-between text-xs text-text-muted gap-2">
              <span>First Targeted: <strong className="text-text-primary font-mono">{fmtDateTime(selectedTargetUser.first_targeted_at)}</strong></span>
              <span>Last Targeted: <strong className="text-text-primary font-mono">{fmtDateTime(selectedTargetUser.last_targeted_at)}</strong></span>
            </div>

            {/* List of emails sent to this victim */}
            <div className="p-5 overflow-y-auto space-y-3 flex-1">
              <div className="text-xs font-bold text-text-muted uppercase tracking-wider">
                Adversary Emails Sent to This Target ({selectedTargetUser.emails.length})
              </div>
              {selectedTargetUser.emails.map((em, idx) => (
                <div
                  key={em.id || idx}
                  className="p-4 rounded-xl bg-workspace border border-workspace-border hover:border-brand/40 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center gap-2">
                      <Mail className="w-3.5 h-3.5 text-brand shrink-0" />
                      <span className="font-semibold text-sm text-text-primary truncate">
                        {em.subject || '(No Subject)'}
                      </span>
                    </div>
                    <div className="text-xs text-text-muted flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span>From: <strong className="text-text-secondary font-mono">{em.sender_address || 'Unknown Sender'}</strong></span>
                      {em.sent_at && <span>Date: <strong className="text-text-secondary">{fmtDateTime(em.sent_at)}</strong></span>}
                      {em.submitted_by_name && (
                        <span className="inline-flex items-center gap-1 text-brand font-medium">
                          <UserCheck className="w-3 h-3" />
                          <span>Submitted by: <strong>{em.submitted_by_name}</strong> {em.submitted_by_email ? `(${em.submitted_by_email})` : ''}</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {onSelectEmail && (
                    <button
                      onClick={() => {
                        setSelectedTargetUser(null);
                        onSelectEmail(em.id);
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand text-white text-xs font-semibold hover:bg-brand-hover transition-colors shrink-0 shadow-sm"
                    >
                      <span>Inspect in Workspace</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  )}
                </div>
              ))}
              {selectedTargetUser.emails.length === 0 && (
                <div className="py-8 text-center text-text-muted text-sm">
                  No individual email records linked to this target.
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-workspace-border flex justify-end bg-workspace/30">
              <button
                onClick={() => setSelectedTargetUser(null)}
                className="px-4 py-2 rounded-lg bg-workspace border border-workspace-border text-text-secondary hover:text-text-primary text-sm font-medium transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Campaign Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-navy-sidebar/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-workspace-card border border-workspace-border rounded-xl max-w-md w-full p-6 shadow-lg space-y-4">
            <h3 className="text-base font-bold text-text-primary flex items-center gap-2">
              <Flag className="w-4 h-4 text-brand" />
              New Campaign
            </h3>
            <form onSubmit={handleCreateCampaign} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-text-secondary block mb-1.5">Campaign Name</label>
                <input
                  type="text"
                  value={newCampaignName}
                  onChange={(e) => setNewCampaignName(e.target.value)}
                  placeholder="e.g. Payroll credential harvesting"
                  required
                  className="w-full px-3.5 py-2 text-sm bg-workspace border border-workspace-border rounded-lg text-text-primary focus:outline-none focus:border-brand"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-text-secondary block mb-1.5">Threat Summary</label>
                <textarea
                  value={newThreatSummary}
                  onChange={(e) => setNewThreatSummary(e.target.value)}
                  placeholder="Describe the adversary indicators, lure pattern, or targets…"
                  rows={3}
                  className="w-full px-3.5 py-2 text-sm bg-workspace border border-workspace-border rounded-lg text-text-primary focus:outline-none focus:border-brand"
                />
              </div>

              <div className="flex justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-workspace text-text-secondary hover:text-text-primary border border-workspace-border text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-brand text-white text-sm font-semibold hover:bg-brand-hover transition-colors"
                >
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
