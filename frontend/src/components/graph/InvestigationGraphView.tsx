import React, { useState, useEffect, useMemo, useRef } from 'react';
import * as d3 from 'd3';
import {
  Network,
  Filter,
  RefreshCw,
  Search,
  Layers,
  Mail,
  User,
  Globe,
  Server,
  Paperclip,
  Flag,
  GitMerge,
  AlertTriangle,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Copy,
  Check,
  ExternalLink,
  Link as LinkIcon,
  Workflow,
  Compass,
  Eye,
  EyeOff,
  Maximize2,
  Minimize2,
  Scan,
  ArrowLeft,
  ArrowRight,
  PanelRightClose,
  PanelRightOpen,
  ShieldCheck,
  ShieldAlert,
  ChevronRight,
  X,
  Star,
  CheckSquare,
  Square,
} from 'lucide-react';
import {
  getGlobalInvestigationGraph,
  getInvestigationGraphForEmail,
  getInvestigationGraphForCampaign,
  listEmails,
  listCampaigns,
  InvestigationGraphResponse,
  GraphNodeItem,
  GraphEdgeItem,
  EmailDetailResponse,
  CampaignListItemResponse,
} from '../../services/api';

type GraphMode = 'global' | 'email' | 'campaign';
type LayoutMode = 'pipeline' | 'orbit';

interface LayoutPoint {
  id: string;
  data: GraphNodeItem;
  x: number;
  y: number;
  width: number;
  height: number;
  color: string;
  isFocal: boolean;
  isBridge: boolean;
  isHighRisk: boolean;
  stageLabel?: string;
}

interface BridgeEntity {
  node: GraphNodeItem;
  campaigns: { id: string; name: string }[];
}

const NODE_COLORS: Record<string, string> = {
  EMAIL: '#38BDF8', // Sky
  SENDER: '#FB923C', // Orange
  DOMAIN: '#34D399', // Emerald
  IP: '#FB7185', // Rose
  URL: '#A78BFA', // Violet
  ATTACHMENT: '#818CF8', // Indigo
  CAMPAIGN: '#FCD34D', // Amber
};

const DEFAULT_NODE_COLOR = '#94A3B8';

const getNodeColor = (type: string): string => {
  return NODE_COLORS[type] || DEFAULT_NODE_COLOR;
};

const getNodeIcon = (type: string, color?: string) => {
  const c = color || getNodeColor(type);
  switch (type) {
    case 'EMAIL':
      return <Mail className="w-4 h-4 shrink-0" style={{ color: c }} />;
    case 'SENDER':
      return <User className="w-4 h-4 shrink-0" style={{ color: c }} />;
    case 'DOMAIN':
      return <Globe className="w-4 h-4 shrink-0" style={{ color: c }} />;
    case 'IP':
      return <Server className="w-4 h-4 shrink-0" style={{ color: c }} />;
    case 'URL':
      return <LinkIcon className="w-4 h-4 shrink-0" style={{ color: c }} />;
    case 'ATTACHMENT':
      return <Paperclip className="w-4 h-4 shrink-0" style={{ color: c }} />;
    case 'CAMPAIGN':
      return <Flag className="w-4 h-4 shrink-0" style={{ color: c }} />;
    default:
      return <Layers className="w-4 h-4 shrink-0 text-slate-400" />;
  }
};

const edgeVisuals = (confidence: number) => {
  if (confidence >= 80) return { stroke: '#38BDF8', width: 2, dash: '6, 4', tier: 'High Confidence' };
  if (confidence >= 50) return { stroke: '#FBBF24', width: 1.6, dash: '5, 4', tier: 'Correlated' };
  return { stroke: '#64748B', width: 1.2, dash: '3, 4', tier: 'Investigative Lead' };
};

function computeBridgeEntities(
  nodes: GraphNodeItem[],
  edges: { source: string; target: string; relationship_type: string }[]
): BridgeEntity[] {
  const nodeById: Record<string, GraphNodeItem> = {};
  nodes.forEach((n) => {
    nodeById[n.id] = n;
  });

  const campaignsBySource: Record<string, Set<string>> = {};
  edges
    .filter((e) => e.relationship_type === 'MEMBER_OF_CAMPAIGN')
    .forEach((e) => {
      if (!campaignsBySource[e.source]) campaignsBySource[e.source] = new Set();
      campaignsBySource[e.source].add(e.target);
    });

  const bridges: BridgeEntity[] = [];
  Object.entries(campaignsBySource).forEach(([sourceId, campaignIds]) => {
    if (campaignIds.size > 1 && nodeById[sourceId]) {
      bridges.push({
        node: nodeById[sourceId],
        campaigns: Array.from(campaignIds).map((cid) => ({
          id: cid,
          name: nodeById[cid]?.display_name || cid,
        })),
      });
    }
  });
  return bridges;
}

interface InvestigationGraphViewProps {
  initialEmailId?: string;
  onSelectEmail?: (emailId: string) => void;
  embedded?: boolean;
}

export const InvestigationGraphView: React.FC<InvestigationGraphViewProps> = ({
  initialEmailId,
  onSelectEmail,
  embedded = false,
}) => {
  const [graphMode, setGraphMode] = useState<GraphMode>(initialEmailId ? 'email' : 'global');
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('pipeline');
  const [isFullScreen, setIsFullScreen] = useState<boolean>(false);
  const [showInspectorInFullscreen, setShowInspectorInFullscreen] = useState<boolean>(true);

  const [emails, setEmails] = useState<EmailDetailResponse[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignListItemResponse[]>([]);
  const [selectedEmailId, setSelectedEmailId] = useState<string>(initialEmailId || '');
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>('');
  const [graphData, setGraphData] = useState<InvestigationGraphResponse | null>(null);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);

  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [collapseUrls, setCollapseUrls] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<boolean>(false);
  const [copiedUrlKey, setCopiedUrlKey] = useState<string | null>(null);

  // Canvas Viewport & Zoom Refs
  const svgRef = useRef<SVGSVGElement | null>(null);
  const zoomGroupRef = useRef<SVGGElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  // Manual Drag overrides for nodes: record of id -> { x, y }
  const [dragOffsets, setDragOffsets] = useState<Record<string, { x: number; y: number }>>({});

  // Stack vs Graph View State (Defaults to Gmail-style stack on initial page unless initialEmailId or embedded)
  const [viewState, setViewState] = useState<'stack' | 'graph'>(
    initialEmailId || embedded ? 'graph' : 'stack'
  );
  const [stackFilter, setStackFilter] = useState<'ALL' | 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE'>('ALL');
  const [stackSearch, setStackSearch] = useState<string>('');
  const [selectedStackEmailId, setSelectedStackEmailId] = useState<string | null>(null);
  const [selectedEmailIds, setSelectedEmailIds] = useState<Set<string>>(new Set());
  const [starredIds, setStarredIds] = useState<Set<string>>(new Set());

  const toggleSelectEmail = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedEmailIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedEmailIds.size === filteredStackEmails.length && filteredStackEmails.length > 0) {
      setSelectedEmailIds(new Set());
    } else {
      setSelectedEmailIds(new Set(filteredStackEmails.map((e) => e.id)));
    }
  };

  const toggleStar = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setStarredIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const lastRowClickRef = useRef<{ id: string; time: number }>({ id: '', time: 0 });
  const clientGraphCacheRef = useRef<Map<string, InvestigationGraphResponse>>(new Map());

  const prewarmGraph = (eid: string) => {
    if (!eid || clientGraphCacheRef.current.has(eid)) return;
    getInvestigationGraphForEmail(eid)
      .then((g) => {
        clientGraphCacheRef.current.set(eid, g);
      })
      .catch(() => {});
  };

  const handleOpenEmailGraph = (emailId: string) => {
    setSelectedEmailId(emailId);
    setSelectedStackEmailId(emailId);
    setGraphMode('email');
    setViewState('graph');

    if (clientGraphCacheRef.current.has(emailId)) {
      applyGraph(clientGraphCacheRef.current.get(emailId)!);
      setLoading(false);
      return;
    }

    fetchEmailGraph(emailId);
  };

  const handleRowClick = (id: string) => {
    const now = Date.now();
    if (lastRowClickRef.current.id === id && now - lastRowClickRef.current.time < 350) {
      handleOpenEmailGraph(id);
      lastRowClickRef.current = { id: '', time: 0 };
    } else {
      lastRowClickRef.current = { id, time: now };
      setSelectedStackEmailId(id);
    }
  };

  const handleGenerateMultiEmailGraph = async () => {
    if (selectedEmailIds.size === 0) return;
    const ids = Array.from(selectedEmailIds);
    if (ids.length === 1) {
      handleOpenEmailGraph(ids[0]);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const graphs = await Promise.all(
        ids.map((id) => getInvestigationGraphForEmail(id).catch(() => null))
      );
      const validGraphs = graphs.filter((g): g is InvestigationGraphResponse => g !== null);
      if (validGraphs.length === 0) {
        throw new Error('Could not retrieve graph models for the selected emails.');
      }

      // Merge nodes deduplicating by ID
      const mergedNodesMap = new Map<string, GraphNodeItem>();
      const entityToEmails = new Map<string, Set<string>>();

      validGraphs.forEach((g) => {
        const emailNode = g.nodes.find((n) => n.node_type === 'EMAIL');
        const emailId = emailNode ? emailNode.id : g.email_id || 'unknown';

        g.nodes.forEach((n) => {
          if (!mergedNodesMap.has(n.id)) {
            mergedNodesMap.set(n.id, { ...n });
          } else {
            const existing = mergedNodesMap.get(n.id)!;
            if (n.risk_level === 'CRITICAL' || existing.risk_level === 'CRITICAL') {
              existing.risk_level = 'CRITICAL';
            } else if (n.risk_level === 'HIGH' || existing.risk_level === 'HIGH') {
              existing.risk_level = 'HIGH';
            }
          }

          if (n.node_type !== 'EMAIL') {
            if (!entityToEmails.has(n.id)) {
              entityToEmails.set(n.id, new Set());
            }
            entityToEmails.get(n.id)!.add(emailId);
          }
        });
      });

      // Mark shared nodes across multiple emails as cross-case bridges
      const crossCorrelatedNodeIds = new Set<string>();
      entityToEmails.forEach((emailSet, entityId) => {
        if (emailSet.size > 1) {
          crossCorrelatedNodeIds.add(entityId);
          const node = mergedNodesMap.get(entityId);
          if (node) {
            node.metadata = {
              ...(node.metadata || {}),
              is_cross_email_correlation: true,
              correlated_email_count: emailSet.size,
              shared_across_cases: Array.from(emailSet),
            };
          }
        }
      });

      // Merge edges deduplicating by composite key
      const mergedEdgesMap = new Map<string, GraphEdgeItem>();
      validGraphs.forEach((g) => {
        g.edges.forEach((e) => {
          const key = `${e.source}__${e.target}__${e.relationship_type}`;
          if (!mergedEdgesMap.has(key)) {
            const isBridgeEdge = crossCorrelatedNodeIds.has(e.source) || crossCorrelatedNodeIds.has(e.target);
            mergedEdgesMap.set(key, {
              ...e,
              id: e.id || key,
              confidence: isBridgeEdge ? Math.max(e.confidence, 85) : e.confidence,
            });
          }
        });
      });

      const allMergedNodes = Array.from(mergedNodesMap.values());
      const allMergedEdges = Array.from(mergedEdgesMap.values());
      const highRiskNodes = allMergedNodes.filter((n) => n.risk_level === 'CRITICAL' || n.risk_level === 'HIGH');

      const stats: Record<string, number> = {};
      allMergedNodes.forEach((n) => {
        stats[n.node_type] = (stats[n.node_type] || 0) + 1;
      });

      const correlationGraph: InvestigationGraphResponse = {
        email_id: ids.join(','),
        focal_node_id: undefined,
        total_nodes: allMergedNodes.length,
        total_edges: allMergedEdges.length,
        nodes: allMergedNodes,
        edges: allMergedEdges,
        high_risk_nodes: highRiskNodes,
        bridge_entities: Array.from(crossCorrelatedNodeIds),
        stages: {},
        statistics: stats,
      };

      setGraphData(correlationGraph);
      setGraphMode('email');
      setViewState('graph');
    } catch (err: any) {
      setError(err.message || 'Failed to generate cross-mail correlation graph.');
    } finally {
      setLoading(false);
    }
  };

  const filteredStackEmails = useMemo(() => {
    return emails.filter((em) => {
      const score = em.threat_risk_score ?? 0;
      if (stackFilter === 'MALICIOUS' && score < 65) return false;
      if (stackFilter === 'SUSPICIOUS' && (score < 35 || score >= 65)) return false;
      if (stackFilter === 'SAFE' && score >= 35) return false;

      if (stackSearch.trim()) {
        const q = stackSearch.toLowerCase();
        const matchSub = em.subject?.toLowerCase().includes(q);
        const matchSender = (em.sender_address || em.sender_display_name)?.toLowerCase().includes(q);
        const matchSha = em.sha256_hash?.toLowerCase().includes(q);
        const matchFile = em.original_filename?.toLowerCase().includes(q);
        if (!matchSub && !matchSender && !matchSha && !matchFile) return false;
      }
      return true;
    });
  }, [emails, stackFilter, stackSearch]);

  const maliciousCount = useMemo(() => emails.filter((e) => (e.threat_risk_score ?? 0) >= 65).length, [emails]);
  const suspiciousCount = useMemo(() => emails.filter((e) => (e.threat_risk_score ?? 0) >= 35 && (e.threat_risk_score ?? 0) < 65).length, [emails]);
  const safeCount = useMemo(() => emails.filter((e) => (e.threat_risk_score ?? 0) < 35).length, [emails]);

  useEffect(() => {
    loadGraphContext();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (initialEmailId && initialEmailId !== selectedEmailId) {
      setSelectedEmailId(initialEmailId);
      setGraphMode('email');
      setViewState('graph');
      fetchEmailGraph(initialEmailId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialEmailId]);

  // Keyboard shortcut listener: Esc to exit fullscreen, F to toggle
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const targetTag = (e.target as HTMLElement)?.tagName;
      if (['INPUT', 'SELECT', 'TEXTAREA'].includes(targetTag)) return;

      if (e.key === 'Escape' && isFullScreen) {
        setIsFullScreen(false);
      } else if (e.key === 'f' || e.key === 'F') {
        setIsFullScreen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isFullScreen]);

  // Auto-refit graph when toggling fullscreen
  useEffect(() => {
    const timer = setTimeout(() => {
      handleFitToScreen();
    }, 150);
    return () => clearTimeout(timer);
  }, [isFullScreen]);

  const loadGraphContext = async () => {
    setLoading(true);
    setError(null);
    try {
      const [emailRes, campRes] = await Promise.allSettled([
        listEmails(0, 50),
        listCampaigns(undefined, 0, 50),
      ]);
      const emailItems = emailRes.status === 'fulfilled' ? emailRes.value.items || [] : [];
      const campItems = campRes.status === 'fulfilled' ? campRes.value || [] : [];
      setEmails(emailItems);
      setCampaigns(campItems);
      if (!initialEmailId && emailItems.length > 0) setSelectedEmailId(emailItems[0].id);
      if (campItems.length > 0) setSelectedCampaignId(campItems[0].id);

      // Instantly unblock table rendering
      setLoading(false);

      if (initialEmailId) {
        setGraphMode('email');
        setViewState('graph');
        const g = await getInvestigationGraphForEmail(initialEmailId);
        clientGraphCacheRef.current.set(initialEmailId, g);
        applyGraph(g);
      }

      // Pre-warm client cache for top 5 email graphs in background idle time
      if (emailItems.length > 0) {
        setTimeout(() => {
          emailItems.slice(0, 5).forEach((item) => {
            prewarmGraph(item.id);
          });
        }, 150);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Could not load the investigation graph context.');
      setGraphData(null);
      setLoading(false);
    }
  };

  const applyGraph = (g: InvestigationGraphResponse) => {
    setGraphData(g);
    setSelectedEdgeId(null);
    setDragOffsets({});
    setSelectedNodeId(g.focal_node_id || (g.nodes.length > 0 ? g.nodes[0].id : null));
    setLoading(false);
    setTimeout(() => {
      handleFitToScreen();
    }, 100);
  };

  const fetchGlobal = async () => {
    setGraphMode('global');
    if (clientGraphCacheRef.current.has('__global__')) {
      applyGraph(clientGraphCacheRef.current.get('__global__')!);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const g = await getGlobalInvestigationGraph(30);
      clientGraphCacheRef.current.set('__global__', g);
      applyGraph(g);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to load the global graph.');
    } finally {
      setLoading(false);
    }
  };

  const fetchEmailGraph = async (eid: string) => {
    if (!eid) return;
    setGraphMode('email');
    if (clientGraphCacheRef.current.has(eid)) {
      applyGraph(clientGraphCacheRef.current.get(eid)!);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const g = await getInvestigationGraphForEmail(eid);
      clientGraphCacheRef.current.set(eid, g);
      applyGraph(g);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to load graph for this email.');
    } finally {
      setLoading(false);
    }
  };

  const fetchCampaignGraph = async (cid: string) => {
    if (!cid) return;
    setGraphMode('campaign');
    const cKey = `campaign:${cid}`;
    if (clientGraphCacheRef.current.has(cKey)) {
      applyGraph(clientGraphCacheRef.current.get(cKey)!);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const g = await getInvestigationGraphForCampaign(cid);
      clientGraphCacheRef.current.set(cKey, g);
      applyGraph(g);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to load graph for this campaign.');
    } finally {
      setLoading(false);
    }
  };

  // Node and edge maps
  const rawNodes = useMemo(() => graphData?.nodes || [], [graphData]);
  const rawEdges = useMemo(() => graphData?.edges || [], [graphData]);

  const bridgeEntities = useMemo(() => computeBridgeEntities(rawNodes, rawEdges), [rawNodes, rawEdges]);
  const bridgeNodeIds = useMemo(() => new Set(bridgeEntities.map((b) => b.node.id)), [bridgeEntities]);

  // Optional: Collapse URLs if > 3 URLs exist to prevent cluttered view
  const { nodes, edges } = useMemo(() => {
    if (!collapseUrls) {
      return { nodes: rawNodes, edges: rawEdges };
    }

    const urlNodes = rawNodes.filter((n) => n.node_type === 'URL');
    if (urlNodes.length <= 3) {
      return { nodes: rawNodes, edges: rawEdges };
    }

    // Replace multiple URLs with 1 aggregate summary cluster card
    const keptNodes: GraphNodeItem[] = [];
    const removedUrlIds = new Set<string>();

    urlNodes.forEach((u) => {
      removedUrlIds.add(u.id);
    });

    rawNodes.forEach((n) => {
      if (!removedUrlIds.has(n.id)) {
        keptNodes.push(n);
      }
    });

    // Build rich, structured URL items list for forensic inspection
    const urlItems = urlNodes.map((u) => {
      const meta = (u.metadata || {}) as Record<string, any>;
      return {
        id: u.id,
        display_name: u.display_name,
        label: u.label,
        url: (meta.url as string) || u.label,
        defanged_url: (meta.defanged_url as string) || (meta.url as string) || u.label,
        url_hash: (meta.url_hash as string) || '',
        domain: (meta.domain as string) || '',
        root_domain: (meta.root_domain as string) || '',
        context: (meta.context as string) || 'BODY_LINK',
        category: (meta.category as string) || 'Body Hyperlink',
        verdict: (meta.verdict as string) || 'BENIGN',
        confidence: typeof meta.confidence === 'number' ? meta.confidence : 0.5,
        risk_level: u.risk_level || 'LOW',
        status: (meta.status as string) || 'ACTIVE',
      };
    });

    const hasHighRisk = urlItems.some((i) => i.risk_level === 'HIGH' || i.risk_level === 'CRITICAL');
    const hasMedRisk = urlItems.some((i) => i.risk_level === 'MEDIUM');

    // Create aggregate node with comprehensive telemetry
    const aggregateUrlNode: GraphNodeItem = {
      id: 'cluster:extracted-urls',
      label: `Extracted URLs (${urlNodes.length})`,
      display_name: `${urlNodes.length} Extracted URLs`,
      node_type: 'URL',
      risk_level: hasHighRisk ? 'HIGH' : hasMedRisk ? 'MEDIUM' : 'LOW',
      metadata: {
        total_urls: urlNodes.length,
        url_items: urlItems,
        domains: Array.from(new Set(urlItems.map((i) => i.domain).filter(Boolean))),
        benign_count: urlItems.filter((i) => i.verdict === 'BENIGN').length,
        suspicious_count: urlItems.filter((i) => i.verdict === 'SUSPICIOUS').length,
        malicious_count: urlItems.filter((i) => i.verdict === 'MALICIOUS').length,
        notice: 'Aggregated to maintain uncluttered graph view. Click to inspect all URLs and threat intelligence.',
      },
    };
    keptNodes.push(aggregateUrlNode);

    // Rewire edges:
    // 1) From emails -> cluster:extracted-urls
    // 2) From cluster:extracted-urls -> hosting domains
    const keptEdges: GraphEdgeItem[] = [];
    const addedAggEdge = new Set<string>();
    const domainCounts: Record<string, number> = {};

    rawEdges.forEach((e) => {
      const isSourceUrl = removedUrlIds.has(e.source);
      const isTargetUrl = removedUrlIds.has(e.target);

      if (!isSourceUrl && !isTargetUrl) {
        keptEdges.push(e);
      } else if (isTargetUrl && !isSourceUrl) {
        // Inbound edge pointing to an extracted URL (e.g. Email -> URL)
        const key = `${e.source}->cluster:extracted-urls`;
        if (!addedAggEdge.has(key)) {
          addedAggEdge.add(key);
          keptEdges.push({
            id: `edge:cluster-urls-${e.source}`,
            source: e.source,
            target: 'cluster:extracted-urls',
            relationship_type: 'CONTAINS_URLS',
            label: `Contains ${urlNodes.length} URLs`,
            confidence: 95.0,
            evidence: { count: urlNodes.length },
          });
        }
      } else if (isSourceUrl && !isTargetUrl) {
        // Outbound edge from an extracted URL to a target (e.g. URL -> Domain)
        domainCounts[e.target] = (domainCounts[e.target] || 0) + 1;
      }
    });

    // Stitched connection from cluster to every hosting domain
    Object.entries(domainCounts).forEach(([domainTargetId, count]) => {
      keptEdges.push({
        id: `edge:cluster-to-${domainTargetId}`,
        source: 'cluster:extracted-urls',
        target: domainTargetId,
        relationship_type: 'HOSTED_ON_DOMAIN',
        label: `Hosts ${count} URL${count > 1 ? 's' : ''}`,
        confidence: 95.0,
        evidence: { count },
      });
    });

    return { nodes: keptNodes, edges: keptEdges };
  }, [rawNodes, rawEdges, collapseUrls]);

  const nodeById = useMemo(() => {
    const map: Record<string, GraphNodeItem> = {};
    nodes.forEach((n) => {
      map[n.id] = n;
    });
    return map;
  }, [nodes]);

  // Filtered nodes based on type & search term
  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      if (filterType !== 'ALL' && n.node_type !== filterType) return false;
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        const matchesName = n.display_name.toLowerCase().includes(q);
        const matchesLabel = n.label.toLowerCase().includes(q);
        const matchesId = n.id.toLowerCase().includes(q);
        return matchesName || matchesLabel || matchesId;
      }
      return true;
    });
  }, [nodes, filterType, searchTerm]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  // Visible edges whose source and target are in filteredNodes
  const visibleEdges = useMemo(() => {
    return edges.filter((e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target));
  }, [edges, filteredNodeIds]);

  // Active selections
  const selectedNode = useMemo(() => {
    return selectedNodeId ? nodeById[selectedNodeId] || null : null;
  }, [selectedNodeId, nodeById]);

  const selectedEdge = useMemo(() => {
    return selectedEdgeId ? edges.find((e) => e.id === selectedEdgeId) || null : null;
  }, [selectedEdgeId, edges]);

  // Edges directly connected to selected node
  const connectedEdges = useMemo(() => {
    if (!selectedNode) return [];
    return edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id);
  }, [selectedNode, edges]);

  // Set of neighbor node IDs connected to selected node
  const neighborNodeIds = useMemo(() => {
    const set = new Set<string>();
    if (!selectedNode) return set;
    set.add(selectedNode.id);
    connectedEdges.forEach((e) => {
      set.add(e.source);
      set.add(e.target);
    });
    return set;
  }, [selectedNode, connectedEdges]);

  // COMPUTE HIGH-FIDELITY COMPACT LAYOUT
  const computedLayout = useMemo((): Record<string, LayoutPoint> => {
    const layout: Record<string, LayoutPoint> = {};
    if (filteredNodes.length === 0) return layout;

    const CARD_W = 160;
    const CARD_H = 42;

    if (layoutMode === 'pipeline') {
      const colOrigin: GraphNodeItem[] = [];
      const colTransit: GraphNodeItem[] = [];
      const colMessage: GraphNodeItem[] = [];
      const colPayloads: GraphNodeItem[] = [];
      const colInfrastructure: GraphNodeItem[] = [];

      filteredNodes.forEach((n) => {
        if (n.node_type === 'SENDER') colOrigin.push(n);
        else if (n.node_type === 'IP') colTransit.push(n);
        else if (n.node_type === 'EMAIL') colMessage.push(n);
        else if (n.node_type === 'URL' || n.node_type === 'ATTACHMENT') colPayloads.push(n);
        else if (n.node_type === 'DOMAIN' || n.node_type === 'CAMPAIGN') colInfrastructure.push(n);
        else colInfrastructure.push(n);
      });

      // Fixed 5-Stage Killchain Pipeline Architecture
      const stageColumns: { name: string; items: GraphNodeItem[]; x: number }[] = [
        { name: '1. Inbound Origin', items: colOrigin, x: 95 },
        { name: '2. Relay Transit', items: colTransit, x: 280 },
        { name: '3. Focal Message', items: colMessage, x: 470 },
        { name: '4. Extracted Payload', items: colPayloads, x: 670 },
        { name: '5. Infrastructure & Attribution', items: colInfrastructure, x: 865 },
      ];

      stageColumns.forEach((col) => {
        const totalItems = col.items.length;
        if (totalItems === 0) return;
        const totalH = totalItems * (CARD_H + 16);
        const startY = Math.max(80, (520 - totalH) / 2);

        col.items.forEach((item, rIdx) => {
          const isFocal = graphData?.focal_node_id === item.id || item.node_type === 'EMAIL';
          const isBridge = bridgeNodeIds.has(item.id);
          const isHighRisk = item.risk_level === 'CRITICAL' || item.risk_level === 'HIGH';

          const baseX = col.x;
          const baseY = startY + rIdx * (CARD_H + 16);
          const drag = dragOffsets[item.id] || { x: 0, y: 0 };

          layout[item.id] = {
            id: item.id,
            data: item,
            x: baseX + drag.x,
            y: baseY + drag.y,
            width: isFocal ? 175 : CARD_W,
            height: isFocal ? 46 : CARD_H,
            color: getNodeColor(item.node_type),
            isFocal,
            isBridge,
            isHighRisk,
            stageLabel: col.name,
          };
        });
      });
    } else {
      // SOC Orbit Mode
      const centerX = 470;
      const centerY = 270;

      const focal = filteredNodes.find((n) => graphData?.focal_node_id === n.id || n.node_type === 'EMAIL');
      const others = filteredNodes.filter((n) => n.id !== focal?.id);

      if (focal) {
        const isBridge = bridgeNodeIds.has(focal.id);
        const isHighRisk = focal.risk_level === 'CRITICAL' || focal.risk_level === 'HIGH';
        const drag = dragOffsets[focal.id] || { x: 0, y: 0 };
        layout[focal.id] = {
          id: focal.id,
          data: focal,
          x: centerX + drag.x,
          y: centerY + drag.y,
          width: 180,
          height: 48,
          color: getNodeColor(focal.node_type),
          isFocal: true,
          isBridge,
          isHighRisk,
        };
      }

      const radius = 210;
      others.forEach((item, idx) => {
        const angle = (idx / others.length) * Math.PI * 2 - Math.PI / 2;
        const isBridge = bridgeNodeIds.has(item.id);
        const isHighRisk = item.risk_level === 'CRITICAL' || item.risk_level === 'HIGH';
        const drag = dragOffsets[item.id] || { x: 0, y: 0 };

        layout[item.id] = {
          id: item.id,
          data: item,
          x: centerX + Math.cos(angle) * radius + drag.x,
          y: centerY + Math.sin(angle) * radius + drag.y,
          width: CARD_W,
          height: CARD_H,
          color: getNodeColor(item.node_type),
          isFocal: false,
          isBridge,
          isHighRisk,
        };
      });
    }

    return layout;
  }, [filteredNodes, layoutMode, graphData, bridgeNodeIds, dragOffsets]);

  // Setup D3 Zoom & Pan
  useEffect(() => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    const zoomGroup = d3.select(zoomGroupRef.current);

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 3.5])
      .wheelDelta((event) => {
        return -event.deltaY * (event.deltaMode === 1 ? 0.05 : event.deltaMode ? 1 : 0.002);
      })
      .on('zoom', (event) => {
        zoomGroup.attr('transform', event.transform);
      });

    svg.call(zoom);
    zoomBehaviorRef.current = zoom;
  }, []);

  const handleZoomIn = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 1.25);
  };

  const handleZoomOut = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 0.8);
  };

  const handlePan = (dx: number, dy: number) => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(200).call(zoomBehaviorRef.current.translateBy, dx, dy);
  };

  const handleResetZoom = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(350)
      .call(zoomBehaviorRef.current.transform, d3.zoomIdentity.translate(0, 0).scale(1));
    setDragOffsets({});
  };

  const handleFitToScreen = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    const nodeValues = Object.values(computedLayout);
    if (nodeValues.length === 0) return;

    const minX = Math.min(...nodeValues.map((n) => n.x - n.width / 2));
    const maxX = Math.max(...nodeValues.map((n) => n.x + n.width / 2));
    const minY = Math.min(...nodeValues.map((n) => n.y - n.height / 2));
    const maxY = Math.max(...nodeValues.map((n) => n.y + n.height / 2));

    const graphWidth = Math.max(100, maxX - minX);
    const graphHeight = Math.max(100, maxY - minY);

    const svgRect = svgRef.current.getBoundingClientRect();
    const svgWidth = svgRect.width || 900;
    const svgHeight = svgRect.height || 560;

    const padding = 60;
    const scale = Math.min(
      1.2,
      Math.max(0.35, Math.min((svgWidth - padding * 2) / graphWidth, (svgHeight - padding * 2) / graphHeight))
    );

    const midX = (minX + maxX) / 2;
    const midY = (minY + maxY) / 2;

    const translateX = svgWidth / 2 - midX * scale;
    const translateY = svgHeight / 2 - midY * scale;

    d3.select(svgRef.current)
      .transition()
      .duration(400)
      .call(zoomBehaviorRef.current.transform, d3.zoomIdentity.translate(translateX, translateY).scale(scale));
  };

  // Node Drag Handler (allows dragging cards freely)
  const handleNodePointerDown = (e: React.PointerEvent, nodeId: string) => {
    e.stopPropagation();
    const startX = e.clientX;
    const startY = e.clientY;
    const initialOffset = dragOffsets[nodeId] || { x: 0, y: 0 };

    const onPointerMove = (moveEvt: PointerEvent) => {
      const dx = moveEvt.clientX - startX;
      const dy = moveEvt.clientY - startY;
      setDragOffsets((prev) => ({
        ...prev,
        [nodeId]: { x: initialOffset.x + dx, y: initialOffset.y + dy },
      }));
    };

    const onPointerUp = () => {
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
    };

    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 1600);
  };

  const isEmpty = !loading && rawNodes.length === 0;

  // Render Inspector Rail / Drawer
  const renderInspectorContent = () => {
    const activeEmail = emails.find((e) => e.id === selectedEmailId);

    return (
      <div className="h-full flex flex-col overflow-hidden text-xs">
        {/* Panel Header */}
        <div className={`px-4 py-3 border-b flex items-center justify-between shrink-0 ${
          isFullScreen ? 'bg-slate-900/90 border-slate-800' : 'bg-slate-50/90 border-slate-200/80'
        }`}>
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-600" />
            <h3 className={`font-bold uppercase tracking-wide text-xs ${isFullScreen ? 'text-slate-200' : 'text-slate-800'}`}>
              {selectedNode ? 'Entity Telemetry' : selectedEdge ? 'Connection Telemetry' : 'Investigation Telemetry'}
            </h3>
          </div>

          <div className="flex items-center gap-2">
            {selectedNode ? (
              <span
                className="text-[10px] font-bold px-2 py-0.5 rounded-full font-mono border"
                style={{
                  backgroundColor: `${getNodeColor(selectedNode.node_type)}15`,
                  color: getNodeColor(selectedNode.node_type),
                  borderColor: `${getNodeColor(selectedNode.node_type)}35`,
                }}
              >
                {selectedNode.node_type}
              </span>
            ) : selectedEdge ? (
              <span className="text-[10px] font-mono font-bold text-blue-600 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded-full">
                RELATION
              </span>
            ) : (
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                isFullScreen ? 'bg-slate-800 text-slate-300 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
                OVERVIEW
              </span>
            )}

            {(selectedNode || selectedEdge) && (
              <button
                onClick={() => {
                  setSelectedNodeId(null);
                  setSelectedEdgeId(null);
                }}
                className="p-1 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-200/60 transition-colors"
                title="Clear selection"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Scrollable Content Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {selectedNode ? (
            <div className="space-y-3.5">
              {/* Node Identity */}
              <div className={`p-3 rounded-xl border ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-lg shrink-0" style={{ backgroundColor: `${getNodeColor(selectedNode.node_type)}15` }}>
                    {getNodeIcon(selectedNode.node_type)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <h4 className={`text-sm font-bold truncate ${isFullScreen ? 'text-slate-100' : 'text-slate-900'}`} title={selectedNode.display_name}>
                      {selectedNode.display_name}
                    </h4>
                    <div className="flex items-center justify-between gap-2 mt-0.5">
                      <span className="text-[10px] text-slate-400 font-mono truncate max-w-[190px]">
                        {selectedNode.id}
                      </span>
                      <button
                        onClick={() => handleCopy(selectedNode.id)}
                        className="text-[10px] text-slate-400 hover:text-blue-600 flex items-center gap-1 shrink-0 font-medium transition-colors"
                        title="Copy Entity ID"
                      >
                        {copiedId ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedId ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>
                </div>

                {/* Status & Risk Row */}
                <div className={`grid grid-cols-2 gap-2 mt-3 pt-3 border-t ${isFullScreen ? 'border-slate-800' : 'border-slate-200'}`}>
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">Risk Assessment</div>
                    <div className={`font-bold mt-0.5 flex items-center gap-1 ${
                      selectedNode.risk_level === 'CRITICAL' || selectedNode.risk_level === 'HIGH'
                        ? 'text-rose-600'
                        : selectedNode.risk_level === 'MEDIUM'
                        ? 'text-amber-600'
                        : 'text-emerald-600'
                    }`}>
                      {selectedNode.risk_level === 'CRITICAL' || selectedNode.risk_level === 'HIGH' ? (
                        <ShieldAlert className="w-3.5 h-3.5" />
                      ) : selectedNode.risk_level === 'MEDIUM' ? (
                        <AlertTriangle className="w-3.5 h-3.5" />
                      ) : (
                        <ShieldCheck className="w-3.5 h-3.5" />
                      )}
                      <span>{selectedNode.risk_level || 'LOW'}</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">Direct Links</div>
                    <div className={`font-bold font-mono mt-0.5 ${isFullScreen ? 'text-slate-200' : 'text-slate-800'}`}>
                      {connectedEdges.length} connection{connectedEdges.length === 1 ? '' : 's'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Bridge Pivot Alert */}
              {bridgeNodeIds.has(selectedNode.id) && (
                <div className="flex items-center gap-2 p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-xs font-semibold">
                  <GitMerge className="w-4 h-4 shrink-0 text-amber-600" />
                  <div>
                    <div>Bridge Pivot Identified</div>
                    <div className="text-[10px] text-amber-700 font-normal">
                      This entity links multiple independent threat campaigns.
                    </div>
                  </div>
                </div>
              )}

              {/* SPECIALIZED PAYLOAD INSPECTOR: Extracted URLs Cluster */}
              {selectedNode.id === 'cluster:extracted-urls' && (
                <div className="space-y-2.5 pt-1">
                  <div className="flex items-center justify-between">
                    <div className="text-[10px] font-bold text-blue-600 uppercase tracking-wider flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5" />
                      <span>Extracted Payload Intelligence</span>
                    </div>
                    <button
                      onClick={() => setCollapseUrls(!collapseUrls)}
                      className="text-[10px] text-blue-600 hover:underline font-mono font-semibold"
                    >
                      {collapseUrls ? 'Expand All on Graph' : 'Collapse Cluster'}
                    </button>
                  </div>

                  <div className="grid grid-cols-3 gap-1.5 text-center text-[10px]">
                    <div className={`p-2 rounded-lg border ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <div className="text-slate-400 font-medium">Payloads</div>
                      <div className={`font-bold text-xs mt-0.5 font-mono ${isFullScreen ? 'text-slate-200' : 'text-slate-900'}`}>
                        {String(selectedNode.metadata?.total_urls ?? 0)} URLs
                      </div>
                    </div>
                    <div className="p-2 rounded-lg bg-sky-50 border border-sky-200">
                      <div className="text-sky-700 font-medium">Domains</div>
                      <div className="font-bold text-sky-800 text-xs mt-0.5 font-mono">
                        {Array.isArray(selectedNode.metadata?.domains) ? selectedNode.metadata.domains.length : 0} Hosts
                      </div>
                    </div>
                    <div className="p-2 rounded-lg bg-emerald-50 border border-emerald-200">
                      <div className="text-emerald-700 font-medium">IOC Verdict</div>
                      <div className="font-bold text-emerald-800 text-xs mt-0.5 font-mono">
                        {String(selectedNode.metadata?.benign_count ?? 0)} Clean
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                    {((selectedNode.metadata?.url_items as any[]) || []).map((item, idx) => {
                      const isCopied = copiedUrlKey === item.url;
                      const isBenign = item.verdict === 'BENIGN';
                      const isMalicious = item.verdict === 'MALICIOUS';

                      return (
                        <div
                          key={item.id || idx}
                          className={`p-2.5 rounded-lg border text-xs space-y-2 ${
                            isFullScreen ? 'bg-slate-900/60 border-slate-800' : 'bg-slate-50/70 border-slate-200'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-1.5">
                            <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border truncate max-w-[160px] ${
                              isFullScreen ? 'bg-slate-800 border-slate-700 text-slate-300' : 'bg-white border-slate-200 text-slate-700'
                            }`}>
                              {item.category || 'Body Hyperlink'}
                            </span>
                            <span
                              className={`text-[9px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1 shrink-0 ${
                                isMalicious
                                  ? 'bg-rose-100 text-rose-700 border border-rose-200'
                                  : isBenign
                                  ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                                  : 'bg-amber-100 text-amber-800 border border-amber-200'
                              }`}
                            >
                              {isMalicious ? <ShieldAlert className="w-2.5 h-2.5" /> : <ShieldCheck className="w-2.5 h-2.5" />}
                              {item.verdict || 'BENIGN'} ({Math.round((item.confidence || 0.5) * 100)}%)
                            </span>
                          </div>

                          <div className={`flex items-center justify-between gap-2 p-2 rounded-md border text-[10px] font-mono ${
                            isFullScreen ? 'bg-slate-950 border-slate-800 text-slate-300' : 'bg-white border-slate-200 text-slate-700'
                          }`}>
                            <span className="truncate select-all" title={item.defanged_url || item.url}>
                              {item.defanged_url || item.url}
                            </span>
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(item.url);
                                setCopiedUrlKey(item.url);
                                setTimeout(() => setCopiedUrlKey(null), 2000);
                              }}
                              className="text-slate-400 hover:text-blue-600 flex items-center gap-0.5 shrink-0"
                              title="Copy Defanged URL"
                            >
                              {isCopied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>

                          <div className="flex items-center justify-between text-[10px] text-slate-400 pt-0.5">
                            <div className="flex items-center gap-1 truncate">
                              <span>Host:</span>
                              {item.domain ? (
                                <button
                                  onClick={() => {
                                    const domId = `domain:${item.domain.toLowerCase()}`;
                                    if (nodeById[domId]) {
                                      setSelectedNodeId(domId);
                                      setSelectedEdgeId(null);
                                    }
                                  }}
                                  className="text-sky-600 hover:text-sky-800 font-mono underline truncate max-w-[130px] font-semibold"
                                  title="Locate Domain in Investigation Graph"
                                >
                                  {item.domain}
                                </button>
                              ) : (
                                <span className="font-mono text-slate-400">Unresolved</span>
                              )}
                            </div>
                            <span className={`font-mono text-[9px] px-1.5 py-0.5 rounded font-medium border ${
                              isFullScreen ? 'bg-slate-800 border-slate-700 text-slate-300' : 'bg-white border-slate-200 text-slate-600'
                            }`}>
                              {item.context}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* SPECIALIZED SINGLE URL INSPECTOR */}
              {selectedNode.node_type === 'URL' && selectedNode.id !== 'cluster:extracted-urls' && (
                <div className="space-y-2.5 pt-1">
                  <div className="text-[10px] font-bold text-blue-600 uppercase tracking-wider flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                    <span>URL Threat Profile</span>
                  </div>

                  <div className={`p-3 rounded-xl border space-y-2.5 ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                    <div className="flex items-center justify-between">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono border ${
                        isFullScreen ? 'bg-slate-800 text-slate-200 border-slate-700' : 'bg-white text-slate-700 border-slate-200'
                      }`}>
                        {(selectedNode.metadata?.category as string) || 'Body Hyperlink'}
                      </span>
                      <span className="text-[10px] font-bold text-emerald-800 bg-emerald-100 border border-emerald-200 px-2 py-0.5 rounded-full flex items-center gap-1">
                        <ShieldCheck className="w-3 h-3 text-emerald-600" />
                        {(selectedNode.metadata?.verdict as string) || 'BENIGN'}
                      </span>
                    </div>

                    <div className="space-y-1">
                      <div className="text-[10px] text-slate-400 font-mono flex items-center justify-between">
                        <span>Defanged URL:</span>
                        <button
                          onClick={() => {
                            const u = (selectedNode.metadata?.url as string) || selectedNode.label;
                            navigator.clipboard.writeText(u);
                            setCopiedUrlKey(u);
                            setTimeout(() => setCopiedUrlKey(null), 2000);
                          }}
                          className="text-slate-400 hover:text-blue-600 flex items-center gap-1 text-[10px]"
                        >
                          {copiedUrlKey ? <Check className="w-2.5 h-2.5 text-emerald-600" /> : <Copy className="w-2.5 h-2.5" />}
                          <span>{copiedUrlKey ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <div className={`p-2 rounded-md border font-mono text-[10px] break-all select-all ${
                        isFullScreen ? 'bg-slate-950 border-slate-800 text-slate-300' : 'bg-white border-slate-200 text-slate-800'
                      }`}>
                        {(selectedNode.metadata?.defanged_url as string) || selectedNode.label}
                      </div>
                    </div>

                    <div className={`grid grid-cols-2 gap-2 text-[10px] pt-1.5 border-t ${isFullScreen ? 'border-slate-800' : 'border-slate-200/80'}`}>
                      <div>
                        <span className="text-slate-400 block">Placement:</span>
                        <span className={`font-mono font-bold ${isFullScreen ? 'text-slate-200' : 'text-slate-800'}`}>
                          {(selectedNode.metadata?.context as string) || 'BODY_LINK'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block">Host Domain:</span>
                        {selectedNode.metadata?.domain ? (
                          <button
                            onClick={() => {
                              const domId = `domain:${(selectedNode.metadata?.domain as string).toLowerCase()}`;
                              if (nodeById[domId]) {
                                setSelectedNodeId(domId);
                                setSelectedEdgeId(null);
                              }
                            }}
                            className="font-mono text-sky-600 hover:underline truncate max-w-[120px] block font-semibold"
                          >
                            {String(selectedNode.metadata?.domain)}
                          </button>
                        ) : (
                          <span className="font-mono text-slate-400">—</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* EMAIL NODE PAYLOAD OVERVIEW */}
              {selectedNode.node_type === 'EMAIL' && (
                <div className={`p-3 rounded-xl border space-y-2 ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5 text-blue-600" />
                      <span>Payload Overview</span>
                    </span>
                    <button
                      onClick={() => {
                        if (nodeById['cluster:extracted-urls']) {
                          setSelectedNodeId('cluster:extracted-urls');
                          setSelectedEdgeId(null);
                        }
                      }}
                      className="text-[10px] text-blue-600 hover:underline font-mono font-semibold"
                    >
                      Inspect URLs →
                    </button>
                  </div>
                  <div className={`text-[11px] leading-relaxed ${isFullScreen ? 'text-slate-300' : 'text-slate-600'}`}>
                    Correlated message payload with extracted hyperlinks and embedded telemetry indicators.
                  </div>
                  <div className="flex items-center gap-1.5 pt-1">
                    <span className="text-[9px] font-mono bg-emerald-100 text-emerald-800 border border-emerald-200 px-2 py-0.5 rounded font-semibold">
                      ✓ Clean Verdict
                    </span>
                    <span className={`text-[9px] font-mono border px-2 py-0.5 rounded ${
                      isFullScreen ? 'bg-slate-800 border-slate-700 text-slate-300' : 'bg-white border-slate-200 text-slate-600'
                    }`}>
                      ESP Deliverability
                    </span>
                  </div>
                </div>
              )}

              {/* Formatted Attributes */}
              {selectedNode.id !== 'cluster:extracted-urls' && Object.keys(selectedNode.metadata || {}).filter(k => !['url_items', 'urls', 'domains', 'total_urls', 'benign_count', 'suspicious_count', 'malicious_count', 'notice'].includes(k)).length > 0 && (
                <div className={`p-3 rounded-xl border space-y-2 ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                  <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                    Observed Attributes
                  </div>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {Object.entries(selectedNode.metadata)
                      .filter(([k]) => !['url_items', 'urls', 'domains', 'total_urls', 'benign_count', 'suspicious_count', 'malicious_count', 'notice'].includes(k))
                      .map(([k, v]) => (
                        <div key={k} className={`flex justify-between gap-2 text-[11px] py-1 border-b ${isFullScreen ? 'border-slate-800' : 'border-slate-200/60'}`}>
                          <span className="text-slate-400 font-mono truncate">{k}</span>
                          <span className={`font-mono font-medium truncate max-w-[170px] ${isFullScreen ? 'text-slate-200' : 'text-slate-800'}`} title={String(v)}>
                            {String(v == null || v === '' ? '—' : typeof v === 'object' ? JSON.stringify(v) : v)}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Connected Relationships List */}
              {connectedEdges.length > 0 && (
                <div className={`p-3 rounded-xl border space-y-2 ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                  <div className="flex items-center justify-between border-b pb-1.5 border-slate-200/60">
                    <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                      Connected Links ({connectedEdges.length})
                    </h4>
                  </div>
                  <div className="space-y-1 max-h-40 overflow-y-auto pr-1">
                    {connectedEdges.map((e) => {
                      const otherId = e.source === selectedNode.id ? e.target : e.source;
                      const otherNode = nodeById[otherId];
                      return (
                        <button
                          key={e.id}
                          onClick={() => {
                            setSelectedNodeId(otherId);
                            setSelectedEdgeId(e.id);
                          }}
                          className={`w-full text-left p-2 rounded-lg border transition-all ${
                            isFullScreen
                              ? 'bg-slate-950 border-slate-800 hover:border-blue-500'
                              : 'bg-white border-slate-200 hover:border-blue-300 hover:bg-blue-50/30'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-1">
                            <span className={`text-xs font-semibold truncate ${isFullScreen ? 'text-slate-200' : 'text-slate-800'}`}>
                              {otherNode?.display_name || otherId}
                            </span>
                            <span className="text-[10px] font-mono font-bold shrink-0 text-blue-600">
                              {Math.round(e.confidence)}%
                            </span>
                          </div>
                          <div className="text-[10px] text-slate-400 truncate mt-0.5">
                            {e.label} · <span className="font-mono text-slate-500">{otherNode?.node_type || 'ENTITY'}</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          ) : selectedEdge ? (
            <div className={`p-4 rounded-xl border space-y-3 ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Selected Connection</div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className={`text-xs font-bold font-mono ${isFullScreen ? 'text-slate-100' : 'text-slate-900'}`}>{selectedEdge.label}</span>
                  <span className="text-xs font-bold font-mono text-blue-600">
                    {Math.round(selectedEdge.confidence)}% Confidence
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 truncate">
                  From: <strong className={isFullScreen ? 'text-slate-200' : 'text-slate-800'}>{nodeById[selectedEdge.source]?.display_name || selectedEdge.source}</strong>
                </div>
                <div className="text-[11px] text-slate-500 truncate">
                  To: <strong className={isFullScreen ? 'text-slate-200' : 'text-slate-800'}>{nodeById[selectedEdge.target]?.display_name || selectedEdge.target}</strong>
                </div>
                <div className={`text-[10px] text-slate-400 pt-2 border-t ${isFullScreen ? 'border-slate-800' : 'border-slate-200'}`}>
                  Relationship: <span className="font-mono text-blue-600 font-semibold">{selectedEdge.relationship_type}</span>
                </div>
              </div>
            </div>
          ) : (
            /* DEFAULT CASE OVERVIEW WHEN NO NODE IS SELECTED */
            <div className="space-y-4">
              <div className={`p-3.5 rounded-xl border space-y-3 ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Investigated Case</span>
                  {activeEmail && (
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      (activeEmail.threat_risk_score ?? 0) >= 65
                        ? 'bg-rose-100 text-rose-700 border border-rose-200'
                        : (activeEmail.threat_risk_score ?? 0) >= 35
                        ? 'bg-amber-100 text-amber-700 border border-amber-200'
                        : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                    }`}>
                      {activeEmail.threat_classification || 'INVESTIGATED'} ({activeEmail.threat_risk_score ?? 0})
                    </span>
                  )}
                </div>
                <div>
                  <h4 className={`text-xs font-bold truncate ${isFullScreen ? 'text-slate-100' : 'text-slate-900'}`} title={activeEmail?.subject || selectedEmailId}>
                    {activeEmail?.subject || activeEmail?.original_filename || 'Email Forensic Graph'}
                  </h4>
                  <p className="text-[11px] text-slate-400 truncate mt-0.5 font-mono">
                    From: {activeEmail?.sender_address || activeEmail?.sender_display_name || 'Ingested Artifact'}
                  </p>
                </div>
                {onSelectEmail && selectedEmailId && (
                  <button
                    onClick={() => {
                      if (isFullScreen) setIsFullScreen(false);
                      onSelectEmail(selectedEmailId);
                    }}
                    className="w-full py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs flex items-center justify-center gap-1.5 transition-colors shadow-2xs"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    <span>Inspect Stored Results</span>
                  </button>
                )}
              </div>

              {/* Topology Breakdown */}
              {graphData && Object.keys(graphData.statistics || {}).length > 0 && (
                <div className="space-y-2.5">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                    <span>Topology Breakdown</span>
                    <span className="text-[10px] font-mono text-slate-500 font-normal">{filteredNodes.length} Nodes</span>
                  </h4>
                  <div className="grid grid-cols-2 gap-2 text-center text-xs">
                    {Object.entries(graphData.statistics).map(([type, count]) => (
                      <button
                        key={type}
                        onClick={() => setFilterType(type)}
                        className={`p-2.5 rounded-xl border text-left transition-colors group ${
                          isFullScreen
                            ? 'bg-slate-900/60 border-slate-800 hover:border-blue-500'
                            : 'bg-slate-50 hover:bg-blue-50/50 border-slate-200 hover:border-blue-200'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-[9px] text-slate-400 font-bold font-mono uppercase group-hover:text-blue-600">{type}</span>
                          <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: NODE_COLORS[type] || '#3B82F6' }} />
                        </div>
                        <div className={`text-base font-bold mt-1 font-mono group-hover:text-blue-600 ${isFullScreen ? 'text-slate-100' : 'text-slate-900'}`}>{count}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className={`p-3 rounded-xl border text-xs space-y-1 ${
                isFullScreen ? 'bg-slate-900/80 border-slate-800 text-slate-300' : 'bg-blue-50/60 border-blue-100 text-blue-900'
              }`}>
                <span className="font-semibold block flex items-center gap-1.5">
                  💡 <span>Canvas Guidance</span>
                </span>
                <p className={`text-[11px] leading-relaxed ${isFullScreen ? 'text-slate-400' : 'text-blue-700/90'}`}>
                  Click any entity card in the canvas to inspect its direct hops, IOC threat reputation, and extracted attributes.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Pinned Action Footer (if EMAIL Node) */}
        {selectedNode?.node_type === 'EMAIL' && onSelectEmail && (
          <div className={`p-3 border-t shrink-0 ${isFullScreen ? 'bg-slate-900 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
            <button
              onClick={() => {
                const rawId = String(selectedNode.metadata?.email_id || selectedNode.id.replace('email:', ''));
                if (isFullScreen) setIsFullScreen(false);
                onSelectEmail(rawId);
              }}
              className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs flex items-center justify-center gap-2 transition-all"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Open Full Email Dossier</span>
            </button>
          </div>
        )}
      </div>
    );
  };

  // Render Gmail-style email stack on initial page
  if (viewState === 'stack' && !embedded) {
    return (
      <div className="space-y-5 animate-fade-in">
        {/* Header Strip */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-brand/10 border border-brand/20 text-brand flex items-center justify-center shrink-0">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl sm:text-2xl font-bold text-text-primary tracking-tight">
                  Investigation Operations
                </h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-brand/10 text-brand border border-brand/20">
                  Email Investigation Stack
                </span>
              </div>
              <p className="text-xs sm:text-sm text-text-muted mt-0.5">
                Double-click any email case below to inspect its interactive relational graph, multi-hop routing, and evidence strands.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-start md:self-auto">
            <button
              onClick={() => {
                setGraphMode('global');
                setViewState('graph');
                fetchGlobal();
              }}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-workspace border border-workspace-border hover:border-brand/40 text-text-primary text-xs font-semibold transition-all hover:bg-workspace-card shadow-xs"
              title="Explore all analyzed entities in global correlation network"
            >
              <Globe className="w-3.5 h-3.5 text-brand" />
              <span>Global Topology Graph</span>
            </button>
            <button
              onClick={loadGraphContext}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-workspace border border-workspace-border hover:bg-workspace-card text-text-muted hover:text-text-primary text-xs transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-workspace-card rounded-xl border border-workspace-border shadow-xs">
          {/* Quick Filter Pills */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
            <button
              onClick={() => setStackFilter('ALL')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
                stackFilter === 'ALL'
                  ? 'bg-slate-800 text-white border border-slate-700 shadow-xs'
                  : 'text-text-muted hover:text-text-primary hover:bg-workspace'
              }`}
            >
              All Cases ({emails.length})
            </button>
            <button
              onClick={() => setStackFilter('MALICIOUS')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all flex items-center gap-1.5 ${
                stackFilter === 'MALICIOUS'
                  ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-xs'
                  : 'text-text-muted hover:text-red-400 hover:bg-red-500/10'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-red-400 inline-block animate-pulse" />
              Malicious ({maliciousCount})
            </button>
            <button
              onClick={() => setStackFilter('SUSPICIOUS')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all flex items-center gap-1.5 ${
                stackFilter === 'SUSPICIOUS'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-xs'
                  : 'text-text-muted hover:text-amber-400 hover:bg-amber-500/10'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-amber-400 inline-block" />
              Suspicious ({suspiciousCount})
            </button>
            <button
              onClick={() => setStackFilter('SAFE')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all flex items-center gap-1.5 ${
                stackFilter === 'SAFE'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-xs'
                  : 'text-text-muted hover:text-emerald-400 hover:bg-emerald-500/10'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
              Clean / Safe ({safeCount})
            </button>
          </div>

          {/* Search Box */}
          <div className="relative min-w-[240px] sm:w-80">
            <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search subject, sender address, or hash..."
              value={stackSearch}
              onChange={(e) => setStackSearch(e.target.value)}
              className="w-full pl-9 pr-8 py-1.5 bg-workspace border border-workspace-border rounded-lg text-xs text-text-primary focus:outline-none focus:border-brand placeholder:text-text-muted"
            />
            {stackSearch && (
              <button
                onClick={() => setStackSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Multi-Select Batch Correlation Action Bar */}
        {selectedEmailIds.size > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-brand/10 border border-brand/30 text-xs animate-fade-in shadow-xs">
            <div className="flex items-center gap-2">
              <CheckSquare className="w-4 h-4 text-brand shrink-0" />
              <span className="font-semibold text-text-primary">
                {selectedEmailIds.size} email case{selectedEmailIds.size > 1 ? 's' : ''} selected
              </span>
              <span className="text-text-muted font-mono">(out of {filteredStackEmails.length})</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleGenerateMultiEmailGraph}
                disabled={loading}
                className="px-4 py-1.5 rounded-lg bg-brand hover:bg-brand-hover text-white font-semibold transition-all flex items-center gap-2 shadow-xs disabled:opacity-50"
              >
                <GitMerge className="w-4 h-4" />
                <span>Generate Multi-Case Correlation Graph ({selectedEmailIds.size} Mails)</span>
              </button>
              <button
                onClick={() => setSelectedEmailIds(new Set())}
                className="px-3 py-1.5 rounded-lg bg-workspace border border-workspace-border text-text-muted hover:text-text-primary font-medium transition-colors"
              >
                Clear Selection
              </button>
            </div>
          </div>
        )}

        {/* Gmail-Style Email Stack */}
        <div className="rounded-xl bg-workspace-card border border-workspace-border shadow-sm overflow-hidden">
          {/* Table Header Bar - Modern Light SOC Style */}
          <div className="grid grid-cols-12 gap-2 px-4 py-3 bg-slate-50/90 border-b border-slate-200/80 text-[11px] font-bold text-slate-600 uppercase tracking-wider items-center select-none">
            <div className="col-span-4 sm:col-span-3 flex items-center gap-2.5">
              <button
                onClick={toggleSelectAll}
                className="text-slate-400 hover:text-blue-600 flex items-center transition-colors"
                title={selectedEmailIds.size === filteredStackEmails.length && filteredStackEmails.length > 0 ? 'Deselect All' : 'Select All'}
              >
                {selectedEmailIds.size > 0 && selectedEmailIds.size === filteredStackEmails.length ? (
                  <CheckSquare className="w-4 h-4 text-blue-600" />
                ) : (
                  <Square className="w-4 h-4 text-slate-400 hover:text-slate-600" />
                )}
              </button>
              <span>Sender</span>
            </div>
            <div className="col-span-5 sm:col-span-5">Subject & Case Evidence</div>
            <div className="hidden sm:block sm:col-span-2 text-center">Verdict</div>
            <div className="hidden sm:block sm:col-span-1 text-right">Received</div>
            <div className="col-span-3 sm:col-span-1 text-right">Graph</div>
          </div>

          {/* Stack Body */}
          {loading ? (
            <div className="p-16 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-brand/30 border-t-brand rounded-full animate-spin mx-auto" />
              <p className="text-xs text-text-muted">Loading email investigation cases…</p>
            </div>
          ) : filteredStackEmails.length === 0 ? (
            <div className="p-16 text-center space-y-2">
              <Mail className="w-10 h-10 text-text-muted/40 mx-auto" />
              <p className="text-sm font-semibold text-text-primary">No matching email cases found</p>
              <p className="text-xs text-text-muted">
                {stackSearch ? 'Try clearing your search query' : 'Upload .eml files to start forensic investigations.'}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-workspace-border/60">
              {filteredStackEmails.map((em) => {
                const score = em.threat_risk_score ?? 0;
                const isMalicious = score >= 65;
                const isSuspicious = score >= 35 && score < 65;
                const isSelected = selectedStackEmailId === em.id;
                const isChecked = selectedEmailIds.has(em.id);
                const isStarred = starredIds.has(em.id);

                // Platform color scheme tweaks: light green for legitimate, light red for phishing
                const rowBgClass = isMalicious
                  ? 'bg-red-500/[0.08] hover:bg-red-500/[0.14] border-l-[4px] border-l-red-500'
                  : isSuspicious
                  ? 'bg-amber-500/[0.08] hover:bg-amber-500/[0.14] border-l-[4px] border-l-amber-500'
                  : 'bg-emerald-500/[0.08] hover:bg-emerald-500/[0.14] border-l-[4px] border-l-emerald-500';

                const senderText = em.sender_display_name || em.sender_address || 'Unknown Sender';
                const snippetText = em.sender_address ? `From: ${em.sender_address}` : (em.sha256_hash ? `SHA: ${em.sha256_hash.slice(0, 12)}…` : 'Evidence Strands Sealed');

                return (
                  <div
                    key={em.id}
                    onClick={() => handleRowClick(em.id)}
                    onDoubleClick={() => handleOpenEmailGraph(em.id)}
                    onMouseEnter={() => prewarmGraph(em.id)}
                    className={`grid grid-cols-12 gap-2 px-4 py-2.5 items-center cursor-pointer transition-colors group select-none ${rowBgClass} ${
                      isChecked ? 'ring-1 ring-brand/50' : ''
                    } ${isSelected ? 'shadow-inner' : ''}`}
                    title="Click checkbox to correlate multiple mails • Double-click to open investigation graph"
                  >
                    {/* Checkbox + Star + Sender */}
                    <div className="col-span-4 sm:col-span-3 flex items-center gap-2 min-w-0">
                      <button
                        onClick={(e) => toggleSelectEmail(em.id, e)}
                        className="text-text-muted hover:text-brand shrink-0"
                        title={isChecked ? 'Deselect' : 'Select for Multi-Mail Correlation'}
                      >
                        {isChecked ? (
                          <CheckSquare className="w-4 h-4 text-brand" />
                        ) : (
                          <Square className="w-4 h-4 text-slate-500 hover:text-text-primary" />
                        )}
                      </button>
                      <button
                        onClick={(e) => toggleStar(em.id, e)}
                        className="text-text-muted hover:text-amber-400 shrink-0"
                        title={isStarred ? 'Unstar' : 'Star Case'}
                      >
                        <Star className={`w-4 h-4 ${isStarred ? 'text-amber-400 fill-amber-400' : 'text-slate-500'}`} />
                      </button>
                      <span className="font-bold text-xs sm:text-sm text-text-primary truncate group-hover:text-brand transition-colors">
                        {senderText}
                      </span>
                    </div>

                    {/* Subject + Snippet Preview */}
                    <div className="col-span-5 sm:col-span-5 flex items-center gap-2 min-w-0 pr-2">
                      <div className="text-xs truncate">
                        <span className="font-semibold text-text-primary">
                          {em.subject || em.original_filename || 'Untitled Forensic Case'}
                        </span>
                        <span className="text-text-muted font-normal ml-1.5 opacity-80">
                          — {snippetText}
                        </span>
                      </div>
                    </div>

                    {/* Risk Verdict Badge */}
                    <div className="hidden sm:flex sm:col-span-2 items-center justify-center">
                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-tight ${
                          isMalicious
                            ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                            : isSuspicious
                            ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        }`}
                      >
                        {isMalicious ? (
                          <ShieldAlert className="w-2.5 h-2.5" />
                        ) : isSuspicious ? (
                          <AlertTriangle className="w-2.5 h-2.5" />
                        ) : (
                          <ShieldCheck className="w-2.5 h-2.5" />
                        )}
                        <span>{em.threat_classification || (isMalicious ? 'PHISHING' : isSuspicious ? 'SUSPICIOUS' : 'LEGITIMATE')}</span>
                        <span className="opacity-75 font-normal">({score.toFixed(0)})</span>
                      </span>
                    </div>

                    {/* Received Date */}
                    <div className="hidden sm:block sm:col-span-1 text-right">
                      <span className="text-xs font-mono text-text-muted whitespace-nowrap">
                        {em.received_at ? new Date(em.received_at).toLocaleDateString([], { month: 'short', day: 'numeric' }) : 'Recent'}
                      </span>
                    </div>

                    {/* Action Button: Graph */}
                    <div className="col-span-3 sm:col-span-1 flex justify-end">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenEmailGraph(em.id);
                        }}
                        className="px-2.5 py-1 rounded bg-brand/10 hover:bg-brand text-brand hover:text-white border border-brand/20 text-[11px] font-semibold transition-all flex items-center gap-1 shadow-xs"
                        title="Double-click row or click here to explore evidence graph"
                      >
                        <span>Graph</span>
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Footer Bar with Hint */}
          <div className="px-4 py-3 bg-slate-50/90 border-t border-slate-200/80 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-600 select-none">
            <span className="flex items-center gap-1.5">
              💡 <span className="font-semibold text-slate-800">Multi-Case Tip:</span> Check multiple email boxes to generate cross-mail correlation graphs, or double-click any row to view individual case evidence.
            </span>
            <span className="font-mono text-slate-500 font-medium bg-slate-100 px-2.5 py-1 rounded-md border border-slate-200/70">
              Showing {filteredStackEmails.length} of {emails.length} total cases
            </span>
          </div>
        </div>
      </div>
    );
  }

  const activeEmail = emails.find((e) => e.id === selectedEmailId);

  return (
    <div className={isFullScreen ? 'fixed inset-0 z-50 bg-[#050B18] flex flex-col p-4 w-screen h-screen overflow-hidden animate-fade-in' : embedded ? 'space-y-3 h-[640px] flex flex-col' : 'space-y-4'}>
      {/* Top Header & Investigation Control Toolbar */}
      <div className={`p-3 rounded-2xl border shadow-xs space-y-2.5 shrink-0 ${
        isFullScreen ? 'bg-slate-900/90 border-slate-800' : 'bg-white border-slate-200/90'
      }`}>
        {/* Tier 1: Case Identity & Global Navigation */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Left: Back button & Active Case Badge */}
          <div className="flex items-center gap-2.5 min-w-0">
            {!isFullScreen && !embedded && (
              <button
                onClick={() => setViewState('stack')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 hover:text-slate-900 text-xs font-semibold transition-all shadow-2xs"
                title="Return to Email Cases Stack"
              >
                <ArrowLeft className="w-3.5 h-3.5 text-blue-600" />
                <span>Case Stack</span>
              </button>
            )}

            <div className="flex items-center gap-2 min-w-0">
              <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shrink-0">
                <Network className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h1 className={`text-sm font-bold tracking-tight ${isFullScreen ? 'text-white' : 'text-slate-900'}`}>
                    Investigation Graph
                  </h1>
                  {activeEmail && (
                    <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-medium bg-slate-100 text-slate-700 border border-slate-200 truncate max-w-[280px]">
                      <Mail className="w-3 h-3 text-slate-500 shrink-0" />
                      <span className="truncate">{activeEmail.subject || activeEmail.original_filename}</span>
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Right: Graph Scope Tabs + Fullscreen */}
          <div className="flex items-center gap-2">
            <div className={`inline-flex p-0.5 rounded-xl border ${isFullScreen ? 'bg-slate-950 border-slate-800' : 'bg-slate-100 border-slate-200/80'}`}>
              <button
                onClick={() => {
                  setGraphMode('email');
                  if (selectedEmailId) fetchEmailGraph(selectedEmailId);
                }}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                  graphMode === 'email'
                    ? isFullScreen ? 'bg-slate-800 text-white font-bold shadow-2xs' : 'bg-white text-blue-700 font-bold shadow-2xs'
                    : 'text-slate-500 hover:text-slate-900'
                }`}
              >
                Email Flow
              </button>
              <button
                onClick={fetchGlobal}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                  graphMode === 'global'
                    ? isFullScreen ? 'bg-slate-800 text-white font-bold shadow-2xs' : 'bg-white text-blue-700 font-bold shadow-2xs'
                    : 'text-slate-500 hover:text-slate-900'
                }`}
              >
                Global Topology
              </button>
              <button
                onClick={() => {
                  setGraphMode('campaign');
                  if (selectedCampaignId) fetchCampaignGraph(selectedCampaignId);
                }}
                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                  graphMode === 'campaign'
                    ? isFullScreen ? 'bg-slate-800 text-white font-bold shadow-2xs' : 'bg-white text-blue-700 font-bold shadow-2xs'
                    : 'text-slate-500 hover:text-slate-900'
                }`}
              >
                Campaigns
              </button>
            </div>

            {/* Fullscreen Toggle */}
            <button
              onClick={() => setIsFullScreen(!isFullScreen)}
              className={`p-1.5 rounded-xl border text-xs font-semibold transition-all ${
                isFullScreen
                  ? 'bg-amber-500/20 border-amber-500/40 text-amber-400 hover:bg-amber-500/30'
                  : 'border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700'
              }`}
              title={isFullScreen ? 'Exit Fullscreen (Esc)' : 'Expand Fullscreen (F)'}
            >
              {isFullScreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Tier 2: Interactive Controls & Filters */}
        <div className={`flex flex-wrap items-center justify-between gap-2.5 pt-2 border-t text-xs ${
          isFullScreen ? 'border-slate-800' : 'border-slate-100'
        }`}>
          {/* Left tools: Case selector + Layout Mode + Cluster Toggle */}
          <div className="flex flex-wrap items-center gap-2">
            {graphMode === 'email' && emails.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Case:</span>
                <select
                  value={selectedEmailId}
                  onChange={(e) => {
                    setSelectedEmailId(e.target.value);
                    fetchEmailGraph(e.target.value);
                  }}
                  className={`px-2.5 py-1 text-xs border rounded-lg font-semibold focus:outline-none focus:border-blue-500 max-w-xs truncate ${
                    isFullScreen ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200 text-slate-800'
                  }`}
                >
                  {emails.map((em) => (
                    <option key={em.id} value={em.id}>
                      {em.subject ? em.subject.substring(0, 36) : em.original_filename || em.id}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {graphMode === 'campaign' && campaigns.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Campaign:</span>
                <select
                  value={selectedCampaignId}
                  onChange={(e) => {
                    setSelectedCampaignId(e.target.value);
                    fetchCampaignGraph(e.target.value);
                  }}
                  className={`px-2.5 py-1 text-xs border rounded-lg font-semibold focus:outline-none focus:border-blue-500 max-w-xs truncate ${
                    isFullScreen ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200 text-slate-800'
                  }`}
                >
                  {campaigns.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.campaign_name || 'Unnamed Campaign'}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Layout switch: Pipeline Flow vs SOC Orbit */}
            <div className={`inline-flex p-0.5 rounded-lg border ${isFullScreen ? 'bg-slate-950 border-slate-800' : 'bg-slate-100 border-slate-200'}`}>
              <button
                onClick={() => setLayoutMode('pipeline')}
                className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
                  layoutMode === 'pipeline'
                    ? isFullScreen ? 'bg-slate-800 text-white shadow-2xs' : 'bg-white text-blue-700 shadow-2xs'
                    : 'text-slate-500 hover:text-slate-900'
                }`}
                title="Forensic Pipeline (Left-to-Right Flow)"
              >
                <Workflow className="w-3.5 h-3.5" />
                <span>Forensic Flow</span>
              </button>
              <button
                onClick={() => setLayoutMode('orbit')}
                className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
                  layoutMode === 'orbit'
                    ? isFullScreen ? 'bg-slate-800 text-white shadow-2xs' : 'bg-white text-blue-700 shadow-2xs'
                    : 'text-slate-500 hover:text-slate-900'
                }`}
                title="Radial Orbit View"
              >
                <Compass className="w-3.5 h-3.5" />
                <span>SOC Orbit</span>
              </button>
            </div>

            {/* Cluster URLs toggle */}
            <button
              onClick={() => setCollapseUrls(!collapseUrls)}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-lg border text-[11px] font-semibold transition-all ${
                collapseUrls
                  ? 'bg-blue-50 border-blue-200 text-blue-700'
                  : isFullScreen ? 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200' : 'bg-slate-50 border-slate-200 text-slate-600 hover:text-slate-900'
              }`}
            >
              {collapseUrls ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
              <span>{collapseUrls ? 'Cluster URLs' : 'All URLs'}</span>
            </button>

            {/* Refresh */}
            <button
              onClick={() => {
                if (graphMode === 'global') fetchGlobal();
                else if (graphMode === 'email' && selectedEmailId) fetchEmailGraph(selectedEmailId);
                else if (graphMode === 'campaign' && selectedCampaignId) fetchCampaignGraph(selectedCampaignId);
              }}
              className={`p-1.5 rounded-lg border transition-colors ${
                isFullScreen ? 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white' : 'bg-slate-50 border-slate-200 text-slate-600 hover:text-blue-600'
              }`}
              title="Reload Graph Data"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {/* Right tools: Search & Node type filter */}
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search node…"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className={`pl-7 pr-3 py-1 border rounded-lg text-xs focus:outline-none focus:border-blue-500 w-36 sm:w-44 placeholder:text-slate-400 ${
                  isFullScreen ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200 text-slate-800'
                }`}
              />
            </div>

            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className={`px-2 py-1 border rounded-lg text-xs font-semibold focus:outline-none focus:border-blue-500 ${
                  isFullScreen ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200 text-slate-800'
                }`}
              >
                <option value="ALL">All Types ({nodes.length})</option>
                <option value="EMAIL">Emails</option>
                <option value="SENDER">Senders</option>
                <option value="DOMAIN">Domains</option>
                <option value="IP">IP Hops</option>
                <option value="URL">URLs</option>
                <option value="ATTACHMENT">Attachments</option>
                <option value="CAMPAIGN">Campaigns</option>
              </select>
            </div>

            {/* Toggle Inspector Drawer in Fullscreen Mode */}
            {isFullScreen && (
              <button
                onClick={() => setShowInspectorInFullscreen(!showInspectorInFullscreen)}
                className={`p-1.5 rounded-lg border text-xs font-semibold flex items-center gap-1 transition-colors ${
                  showInspectorInFullscreen
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                }`}
                title={showInspectorInFullscreen ? 'Hide Telemetry Panel' : 'Show Telemetry Panel'}
              >
                {showInspectorInFullscreen ? <PanelRightClose className="w-3.5 h-3.5" /> : <PanelRightOpen className="w-3.5 h-3.5" />}
                <span className="hidden sm:inline">Telemetry</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => {
              setError(null);
              fetchGlobal();
            }}
            className="px-2.5 py-1 bg-rose-600 text-white text-[11px] font-semibold rounded-lg hover:bg-rose-700 transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="flex-1 p-20 rounded-2xl bg-white border border-slate-200 shadow-sm text-center flex flex-col items-center justify-center space-y-3">
          <div className="w-10 h-10 border-3 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
          <p className="text-sm font-semibold text-slate-800">Rendering structured investigation graph…</p>
          <p className="text-xs text-slate-500">Arranging transmission flow and forensic indicators</p>
        </div>
      ) : isEmpty ? (
        <div className="flex-1 p-20 rounded-2xl bg-white border border-slate-200 shadow-sm text-center flex flex-col items-center justify-center">
          <Network className="w-10 h-10 mx-auto text-slate-400 mb-3" />
          <h3 className="text-sm font-bold text-slate-800">No correlated graph relationships found</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
            Analyze an email with URLs, domains, or relay transit hops to automatically generate forensic graph clusters.
          </p>
        </div>
      ) : (
        /* Main View Container: Side-by-side or Fullscreen Flex with matching equal height */
        <div className={`flex flex-col lg:flex-row gap-4 ${isFullScreen ? 'flex-1 min-h-0' : 'h-[640px] xl:h-[700px]'}`}>
          {/* Main Professional Graph Viewport */}
          <div className="flex-1 h-full rounded-2xl bg-gradient-to-br from-[#060D1E] via-[#0A1633] to-[#081024] border border-slate-800 shadow-xl relative overflow-hidden flex flex-col select-none min-w-0 transition-all duration-300">
            {/* Top Status Header */}
            <div className="flex items-center justify-between px-4 py-2 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 text-[11px] z-10">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sky-400 font-bold">
                  {filteredNodes.length} Entities
                </span>
                <span className="text-slate-600">·</span>
                <span className="font-mono text-emerald-400 font-bold">
                  {visibleEdges.length} Stitched Connections
                </span>
                {bridgeEntities.length > 0 && (
                  <>
                    <span className="text-slate-600">·</span>
                    <span className="font-mono text-amber-400 font-bold flex items-center gap-1">
                      <GitMerge className="w-3 h-3" />
                      {bridgeEntities.length} Bridge Pivot{bridgeEntities.length === 1 ? '' : 's'}
                    </span>
                  </>
                )}
              </div>

              {/* Legend & Fullscreen shortcut button */}
              <div className="flex items-center gap-3">
                <div className="hidden sm:flex items-center gap-2.5 text-[10px] text-slate-300">
                  {Object.entries(NODE_COLORS).map(([type, color]) => (
                    <span key={type} className="flex items-center gap-1 font-medium">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                      {type}
                    </span>
                  ))}
                </div>

                <button
                  onClick={() => setIsFullScreen(!isFullScreen)}
                  className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
                  title={isFullScreen ? 'Exit Fullscreen (Esc)' : 'Expand to Fullscreen (F)'}
                >
                  {isFullScreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {/* Stage Column Headers (in Pipeline Flow mode) */}
            {layoutMode === 'pipeline' && (
              <div className="grid grid-cols-5 px-3 py-1.5 bg-slate-950/85 border-b border-slate-800 text-[10px] text-slate-400 font-mono tracking-wider z-10 text-center uppercase">
                <div className="flex items-center justify-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8]" />
                  <span>1. Origin</span>
                </div>
                <div className="flex items-center justify-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#EC4899]" />
                  <span>2. Transit</span>
                </div>
                <div className="flex items-center justify-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#2563B8]" />
                  <span>3. Message</span>
                </div>
                <div className="flex items-center justify-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#8B5CF6]" />
                  <span>4. Payload</span>
                </div>
                <div className="flex items-center justify-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" />
                  <span>5. Infrastructure</span>
                </div>
              </div>
            )}

            {/* Tactical Floating View Controls (Zoom, Pan, Fit) */}
            <div className="absolute top-14 right-3 z-10 flex flex-col gap-1 bg-slate-900/90 backdrop-blur-md p-1 rounded-xl border border-slate-700/60 shadow-xl">
              <button
                onClick={handleZoomIn}
                className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                title="Zoom In"
              >
                <ZoomIn className="w-4 h-4" />
              </button>
              <button
                onClick={handleZoomOut}
                className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                title="Zoom Out"
              >
                <ZoomOut className="w-4 h-4" />
              </button>
              <button
                onClick={handleFitToScreen}
                className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                title="Fit to Screen (Auto-Center All)"
              >
                <Scan className="w-4 h-4 text-brand" />
              </button>
              <button
                onClick={handleResetZoom}
                className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                title="Reset View"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
              <div className="w-full h-px bg-slate-800 my-0.5" />
              <div className="flex items-center gap-0.5">
                <button
                  onClick={() => handlePan(90, 0)}
                  className="p-1 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors"
                  title="Pan Left"
                >
                  <ArrowLeft className="w-3 h-3" />
                </button>
                <button
                  onClick={() => handlePan(-90, 0)}
                  className="p-1 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors"
                  title="Pan Right"
                >
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            </div>

            {/* SVG Canvas Area with Responsive Auto-Scaling ViewBox */}
            <div className="flex-1 w-full h-full cursor-grab active:cursor-grabbing overflow-hidden">
              <svg
                ref={svgRef}
                viewBox="0 0 940 560"
                preserveAspectRatio="xMidYMid meet"
                className="w-full h-full"
                onClick={() => {
                  setSelectedEdgeId(null);
                }}
              >
                <defs>
                  {/* Tactical Dot Matrix Stitch Pattern */}
                  <pattern
                    id="tactical-grid-pattern"
                    width="32"
                    height="32"
                    patternUnits="userSpaceOnUse"
                  >
                    <circle cx="16" cy="16" r="1.1" fill="#334155" opacity="0.35" />
                  </pattern>

                  {/* High Glow Filter */}
                  <filter id="neon-glow" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="5" result="blur" />
                    <feMerge>
                      <feMergeNode in="blur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                </defs>

                {/* Background Grid */}
                <rect width="100%" height="100%" fill="url(#tactical-grid-pattern)" />

                {/* Transform Group controlled by D3 Zoom & Pan */}
                <g ref={zoomGroupRef}>
                  {/* 1. Connecting Lines Layer */}
                  {visibleEdges.map((edge) => {
                    const src = computedLayout[edge.source];
                    const tgt = computedLayout[edge.target];
                    if (!src || !tgt) return null;

                    const visuals = edgeVisuals(edge.confidence);
                    const isSelected = selectedEdgeId === edge.id;
                    const isHovered = hoveredEdgeId === edge.id;
                    const isConnectedToSelectedNode =
                      selectedNode && (src.id === selectedNode.id || tgt.id === selectedNode.id);
                    const isDimmed =
                      selectedNode && !isConnectedToSelectedNode && !isSelected;

                    let pathD = '';
                    if (layoutMode === 'pipeline') {
                      const x1 = src.x < tgt.x ? src.x + src.width / 2 : src.x - src.width / 2;
                      const y1 = src.y;
                      const x2 = tgt.x > src.x ? tgt.x - tgt.width / 2 : tgt.x + tgt.width / 2;
                      const y2 = tgt.y;
                      const dx = (x2 - x1) / 2;
                      pathD = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
                    } else {
                      const dx = (tgt.x - src.x) * 0.2;
                      const dy = (tgt.y - src.y) * 0.2;
                      pathD = `M ${src.x} ${src.y} Q ${(src.x + tgt.x) / 2 + dy} ${(src.y + tgt.y) / 2 - dx} ${tgt.x} ${tgt.y}`;
                    }

                    const midX = (src.x + tgt.x) / 2;
                    const midY = (src.y + tgt.y) / 2;

                    return (
                      <g
                        key={edge.id}
                        className="cursor-pointer"
                        onMouseEnter={() => setHoveredEdgeId(edge.id)}
                        onMouseLeave={() => setHoveredEdgeId(null)}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEdgeId(edge.id);
                          setSelectedNodeId(null);
                        }}
                      >
                        {/* Invisible wider hit area for easy hovering */}
                        <path
                          d={pathD}
                          fill="none"
                          stroke="transparent"
                          strokeWidth={14}
                        />

                        {/* Stitched line */}
                        <path
                          d={pathD}
                          fill="none"
                          stroke={isSelected || isHovered ? '#FFFFFF' : visuals.stroke}
                          strokeWidth={isSelected || isHovered ? visuals.width + 1.5 : visuals.width}
                          strokeDasharray={visuals.dash}
                          opacity={isDimmed ? 0.12 : isSelected || isHovered ? 1 : visuals.stroke === '#38BDF8' ? 0.8 : 0.55}
                          className={isSelected || isHovered || edge.confidence >= 80 ? 'animate-stitch-flow' : ''}
                        />

                        {/* Stitched Label Badge shown only when hovered or selected */}
                        {(isSelected || isHovered) && (
                          <g transform={`translate(${midX}, ${midY})`}>
                            <rect
                              x="-50"
                              y="-10"
                              width="100"
                              height="20"
                              rx="6"
                              fill="#09132A"
                              stroke={isSelected ? '#FFFFFF' : visuals.stroke}
                              strokeWidth={1.2}
                              filter="url(#neon-glow)"
                            />
                            <text
                              textAnchor="middle"
                              y="3.5"
                              fill="#FFFFFF"
                              fontSize="9"
                              fontFamily="monospace"
                              fontWeight="bold"
                            >
                              {edge.label} ({Math.round(edge.confidence)}%)
                            </text>
                          </g>
                        )}
                      </g>
                    );
                  })}

                  {/* 2. Structured Tactical Entity Cards Layer */}
                  {Object.values(computedLayout).map((node) => {
                    const isSelected = selectedNodeId === node.id;
                    const isNeighbor = neighborNodeIds.has(node.id);
                    const isDimmed = selectedNode && !isSelected && !isNeighbor;
                    const isHovered = hoveredNodeId === node.id;

                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x}, ${node.y})`}
                        className="cursor-pointer transition-all duration-150"
                        opacity={isDimmed ? 0.22 : 1}
                        onPointerDown={(e) => handleNodePointerDown(e, node.id)}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedNodeId(node.id);
                          setSelectedEdgeId(null);
                        }}
                        onMouseEnter={() => setHoveredNodeId(node.id)}
                        onMouseLeave={() => setHoveredNodeId(null)}
                      >
                        {/* Outer Glow Halo on Selection / Focal */}
                        {(isSelected || node.isFocal) && (
                          <rect
                            x={-node.width / 2 - 4}
                            y={-node.height / 2 - 4}
                            width={node.width + 8}
                            height={node.height + 8}
                            rx={12}
                            fill={node.color}
                            opacity={isSelected ? 0.25 : 0.15}
                            filter="url(#neon-glow)"
                          />
                        )}

                        {/* Bridge Entity Golden Dashed Outline */}
                        {node.isBridge && (
                          <rect
                            x={-node.width / 2 - 3}
                            y={-node.height / 2 - 3}
                            width={node.width + 6}
                            height={node.height + 6}
                            rx={10}
                            fill="none"
                            stroke="#F59E0B"
                            strokeWidth={1.5}
                            strokeDasharray="4, 3"
                          />
                        )}

                        {/* Main Card Background */}
                        <rect
                          x={-node.width / 2}
                          y={-node.height / 2}
                          width={node.width}
                          height={node.height}
                          rx={8}
                          fill="#0C1733"
                          stroke={isSelected ? '#FFFFFF' : isHovered ? '#38BDF8' : node.color}
                          strokeWidth={isSelected ? 2 : node.isFocal ? 1.8 : 1}
                        />

                        {/* Left Icon Badge Container */}
                        <rect
                          x={-node.width / 2 + 5}
                          y={-node.height / 2 + 5}
                          width={node.height - 10}
                          height={node.height - 10}
                          rx={6}
                          fill={node.color}
                          fillOpacity={0.16}
                        />

                        {/* ForeignObject for HTML icon rendering */}
                        <foreignObject
                          x={-node.width / 2 + 6}
                          y={-node.height / 2 + 6}
                          width={node.height - 12}
                          height={node.height - 12}
                          className="pointer-events-none"
                        >
                          <div className="w-full h-full flex items-center justify-center">
                            {getNodeIcon(node.data.node_type, node.color)}
                          </div>
                        </foreignObject>

                        {/* Text: Category Tag (Top Line) */}
                        <text
                          x={-node.width / 2 + node.height - 1}
                          y={-node.height / 2 + 14}
                          fill={node.color}
                          fontSize="8"
                          fontFamily="monospace"
                          fontWeight="700"
                          letterSpacing="0.05em"
                        >
                          {node.data.node_type}
                        </text>

                        {/* Risk Dot on Top Right */}
                        {node.isHighRisk && (
                          <circle
                            cx={node.width / 2 - 9}
                            cy={-node.height / 2 + 12}
                            r="3"
                            fill="#EF4444"
                          />
                        )}

                        {/* Text: Primary Entity Label (Bottom Line) */}
                        <text
                          x={-node.width / 2 + node.height - 1}
                          y={-node.height / 2 + 28}
                          fill={isSelected ? '#FFFFFF' : '#E2E8F0'}
                          fontSize="10"
                          fontFamily="monospace"
                          fontWeight="600"
                        >
                          {node.data.display_name.length > 18
                            ? `${node.data.display_name.slice(0, 16)}…`
                            : node.data.display_name}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            </div>

            {/* Bottom Insight Footer */}
            <div className="px-4 py-2 bg-slate-950/85 border-t border-slate-800 text-[10px] text-slate-400 flex items-center justify-between z-10">
              <span>
                💡 Drag canvas to pan · Scroll wheel to zoom · Click [Scan] to fit all cards · Press [F] for Fullscreen · Press [Esc] to exit
              </span>
              <span className="font-mono text-slate-500">
                {layoutMode === 'pipeline' ? 'Forensic Flow' : 'SOC Orbit'}
              </span>
            </div>
          </div>

          {/* Right Rail: Entity & Relationship Inspector (or Slide-over in Fullscreen) */}
          {(!isFullScreen || showInspectorInFullscreen) && (
            <div
              className={`w-full lg:w-[380px] xl:w-[410px] h-full flex flex-col shrink-0 rounded-2xl border shadow-sm overflow-hidden ${
                isFullScreen
                  ? 'bg-slate-950/95 border-slate-800'
                  : 'bg-white border-slate-200/90'
              }`}
            >
              {renderInspectorContent()}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default InvestigationGraphView;
