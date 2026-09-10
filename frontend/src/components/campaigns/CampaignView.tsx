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
} from 'lucide-react';
import {
  listCampaigns,
  getCampaign,
  createCampaign,
  autoClusterCampaigns,
  CampaignListItemResponse,
  CampaignDetailResponse,
} from '../../services/api';
import { StatusBadge } from '../common/StatusBadge';

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
        const initialId = selectedCampaignId || data[0].id;
        setSelectedCampaignId(initialId);
        fetchCampaignDetails(initialId);
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

  const fetchCampaignDetails = async (campaignId: string) => {
    if (!campaignId) return;
    try {
      const data = await getCampaign(campaignId);
      setCampaignDetails(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to load campaign details.');
    }
  };

  const handleAutoCluster = async () => {
    setClustering(true);
    setError(null);
    setClusterNotice(null);
    try {
      const result = await autoClusterCampaigns(60.0);
      setClusterNotice(
        result.total_clusters_created > 0
          ? `Auto-clustering created ${result.total_clusters_created} new campaign${result.total_clusters_created === 1 ? '' : 's'}.`
          : 'Auto-clustering ran but found no new correlated groups above the confidence threshold.'
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
              Correlated groups of related emails, clustered by shared infrastructure and content signals.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
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
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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

          <div className="space-y-2 max-h-[560px] overflow-y-auto">
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
                  Run auto-clustering to correlate analyzed emails into campaigns based on shared infrastructure.
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
        <div className="lg:col-span-2 space-y-6">
          {campaignDetails ? (
            <div className="space-y-6">
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

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-workspace border border-workspace-border">
                    <div className="text-[11px] text-text-muted">First Detected</div>
                    <div className="font-semibold text-text-primary text-sm mt-0.5">{fmtDate(campaignDetails.first_detected_at)}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-workspace border border-workspace-border">
                    <div className="text-[11px] text-text-muted">Last Activity</div>
                    <div className="font-semibold text-text-primary text-sm mt-0.5">{fmtDate(campaignDetails.last_activity_at)}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-workspace border border-workspace-border">
                    <div className="text-[11px] text-text-muted">Members</div>
                    <div className="font-bold text-brand text-sm mt-0.5">{campaignDetails.total_members}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-workspace border border-workspace-border">
                    <div className="text-[11px] text-text-muted">Evidence Links</div>
                    <div className="font-bold text-brand text-sm mt-0.5">{campaignDetails.total_evidence_links}</div>
                  </div>
                </div>
              </div>

              {/* Member Emails */}
              <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-5 space-y-3">
                <h3 className="text-sm font-bold text-text-primary">Member Emails ({campaignDetails.memberships.length})</h3>
                <div className="space-y-2">
                  {campaignDetails.memberships.map((m) => (
                    <div key={m.id} className="p-3.5 rounded-lg bg-workspace border border-workspace-border flex items-center justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <div className="font-medium text-sm text-text-primary truncate">{m.email_subject || m.email_id}</div>
                        <div className="text-xs text-text-muted truncate mt-0.5">{m.email_sender || 'Unknown sender'}</div>
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
          ) : (
            <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm p-16 text-center">
              <Flag className="w-8 h-8 mx-auto text-text-muted opacity-60 mb-2" />
              <h3 className="font-semibold text-sm text-text-primary">No campaign selected</h3>
              <p className="text-sm text-text-muted mt-1">Select a campaign on the left to view its members and evidence.</p>
            </div>
          )}
        </div>
      </div>

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
