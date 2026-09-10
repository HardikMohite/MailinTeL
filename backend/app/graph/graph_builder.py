import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str  # EMAIL, SENDER, URL, DOMAIN, IP, ASN, ATTACHMENT, CAMPAIGN
    display_name: str
    risk_level: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW, BENIGN, UNKNOWN
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    relationship_type: str  # SENT_BY, CONTAINS_URL, HOSTED_ON_DOMAIN, RESOLVES_TO_IP, ROUTED_THROUGH_IP, LOCATED_IN_ASN, CONTAINS_ATTACHMENT, MEMBER_OF_CAMPAIGN, CORRELATED_WITH, SIMILAR_TO
    label: str
    confidence: float = 100.0
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationGraph:
    focal_node_id: Optional[str] = None
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0
    statistics: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "focal_node_id": self.focal_node_id,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "statistics": self.statistics,
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "node_type": n.node_type,
                    "display_name": n.display_name,
                    "risk_level": n.risk_level,
                    "metadata": n.metadata,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "id": e.id,
                    "source": e.source,
                    "target": e.target,
                    "relationship_type": e.relationship_type,
                    "label": e.label,
                    "confidence": e.confidence,
                    "evidence": e.evidence,
                }
                for e in self.edges
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationGraph":
        nodes = [
            GraphNode(
                id=n["id"],
                label=n["label"],
                node_type=n["node_type"],
                display_name=n["display_name"],
                risk_level=n.get("risk_level", "UNKNOWN"),
                metadata=n.get("metadata", {}),
            )
            for n in data.get("nodes", [])
        ]
        edges = [
            GraphEdge(
                id=e["id"],
                source=e["source"],
                target=e["target"],
                relationship_type=e["relationship_type"],
                label=e["label"],
                confidence=float(e.get("confidence", 100.0)),
                evidence=e.get("evidence", {}),
            )
            for e in data.get("edges", [])
        ]
        return cls(
            focal_node_id=data.get("focal_node_id"),
            nodes=nodes,
            edges=edges,
            total_nodes=len(nodes),
            total_edges=len(edges),
            statistics=data.get("statistics", {}),
        )


class InvestigationGraphBuilder:
    """
    Constructs rich, interactive entity-relationship graphs connecting emails,
    senders, URLs, domains, IP addresses, ASNs, attachments, and threat campaigns.
    """

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}

    def add_node(
        self,
        node_id: str,
        node_type: str,
        display_name: str,
        label: Optional[str] = None,
        risk_level: str = "UNKNOWN",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Adds or updates a node in the graph."""
        clean_id = str(node_id)
        if clean_id not in self._nodes:
            node = GraphNode(
                id=clean_id,
                label=label or display_name,
                node_type=node_type,
                display_name=display_name,
                risk_level=risk_level,
                metadata=metadata or {},
            )
            self._nodes[clean_id] = node
        else:
            # Update metadata if newer/richer
            if metadata:
                self._nodes[clean_id].metadata.update(metadata)
            if risk_level != "UNKNOWN":
                self._nodes[clean_id].risk_level = risk_level
        return self._nodes[clean_id]

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        label: Optional[str] = None,
        confidence: float = 100.0,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Optional[GraphEdge]:
        """Adds a directed edge between two existing or referenced nodes."""
        s_id = str(source_id)
        t_id = str(target_id)
        if s_id == t_id:
            return None  # avoid self-loops

        edge_id = f"{s_id}--[{relationship_type}]-->{t_id}"
        if edge_id not in self._edges:
            edge = GraphEdge(
                id=edge_id,
                source=s_id,
                target=t_id,
                relationship_type=relationship_type,
                label=label or relationship_type.replace("_", " ").title(),
                confidence=confidence,
                evidence=evidence or {},
            )
            self._edges[edge_id] = edge
        return self._edges[edge_id]

    def build(self, focal_node_id: Optional[str] = None) -> InvestigationGraph:
        """Compiles the added nodes and edges into an InvestigationGraph package."""
        node_list = list(self._nodes.values())
        edge_list = list(self._edges.values())

        # Compute statistics by node type
        stats: Dict[str, int] = {}
        for n in node_list:
            stats[n.node_type] = stats.get(n.node_type, 0) + 1

        return InvestigationGraph(
            focal_node_id=str(focal_node_id) if focal_node_id else None,
            nodes=node_list,
            edges=edge_list,
            total_nodes=len(node_list),
            total_edges=len(edge_list),
            statistics=stats,
        )
