"""
cnsl/graph_correlation.py — Graph-structured attack correlation.

cnsl/fingerprint.py already clusters IPs by DIRECT pairwise behavioral
similarity. This module answers a different question: which IPs are
correlated *transitively*, through the attack graph itself, even when
no two of them look similar to each other?

The graph is heterogeneous -- three node types, not just IPs:
  - "ip"    nodes: attacker source IPs
  - "rule"  nodes: the TTP keyword each incident's reason names
                   (e.g. "brute_force", "sql_injection")
  - "stage" nodes: kill-chain stages an IP has reached

Edges connect an IP to every rule it triggered and every stage it
reached. Two IPs with nothing directly in common can still land in the
same connected component if they're both linked through a *shared*
rule or stage node -- e.g. IP A and IP C never interact, but both
trigger "sql_injection" and both reach the "Delivery" stage, so the
graph connects them through those shared nodes. That's the actual
conceptual step a Graph Neural Network would also be modeling (nodes,
edges, message-passing/propagation across them) -- implemented here
with classical, explainable connected-components instead of a trained
model, in keeping with the rest of CNSL's correlation/fingerprinting
code: no training, no model file, no heavy ML dependency, every result
traces back to inspectable graph edges.

Usage:
    graph = build_attack_graph(incidents, kill_chains)
    campaigns = find_campaigns(graph, min_ips=3)
    why = explain_connection("45.33.32.1", "91.108.4.88", graph)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from .kill_chain import STAGE_NAMES


def _reason_keyword(reason: str) -> str:
    return reason.split(":", 1)[0].strip().lower() if reason else "unknown"


def build_attack_graph(
    incidents: List[Dict[str, Any]],
    kill_chains: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """
    Build the heterogeneous attack graph from incident rows (shaped
    like store.recent_incidents()'s output) and, optionally, a list of
    KillChain objects (cnsl.kill_chain.KillChain -- from
    KillChainTracker.get_all()).

    Returns {"nodes": [...], "edges": [...]}, each node/edge a plain
    dict, ready for JSON serialization.
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    seen_edges: Set[tuple] = set()

    def _add_node(node_id: str, node_type: str, label: str) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": node_type, "label": label}

    def _add_edge(source: str, target: str, edge_type: str) -> None:
        key = (source, target, edge_type)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({"source": source, "target": target, "type": edge_type})

    ip_ids: Set[str] = set()
    for r in incidents:
        ip = r.get("src_ip")
        if not ip:
            continue
        ip_id = f"ip:{ip}"
        _add_node(ip_id, "ip", ip)
        ip_ids.add(ip_id)

        for reason in (r.get("reasons") or []):
            keyword = _reason_keyword(reason)
            rule_id = f"rule:{keyword}"
            _add_node(rule_id, "rule", keyword)
            _add_edge(ip_id, rule_id, "triggered")

    if kill_chains:
        for chain in kill_chains:
            ip_id = f"ip:{chain.ip}"
            if ip_id not in ip_ids:
                # Only attach stage nodes for IPs that already showed up
                # via incidents -- a kill chain with no incident history
                # in this window isn't part of the graph we're building.
                continue
            for stage_num in chain.stages:
                stage_id = f"stage:{stage_num}"
                _add_node(stage_id, "stage", STAGE_NAMES.get(stage_num, str(stage_num)))
                _add_edge(ip_id, stage_id, "reached_stage")

    return {"nodes": list(nodes.values()), "edges": edges}


def _adjacency(graph: Dict[str, Any]) -> Dict[str, Set[str]]:
    adj: Dict[str, Set[str]] = defaultdict(set)
    for e in graph["edges"]:
        adj[e["source"]].add(e["target"])
        adj[e["target"]].add(e["source"])
    return adj


def find_campaigns(
    graph: Dict[str, Any],
    min_ips: int = 3,
    min_shared_degree: int = 2,
) -> List[Dict[str, Any]]:
    """
    Find "campaigns" -- groups of 3+ distinct IPs connected through the
    graph, via connected components over rule/stage nodes that are
    actually SHARED by more than one IP.

    A rule/stage node triggered by only one IP is a dead end, not
    correlation -- `min_shared_degree` (default 2) requires a node to
    have at least that many distinct IP neighbors before it's allowed
    to link IPs together into a campaign. This is what keeps campaign
    detection from trivially grouping every IP that ever triggered any
    rule into one giant meaningless cluster.

    Returns campaigns with >= min_ips IPs, largest first. Each entry:
    {"ips": [...], "shared_nodes": [{"id", "type", "label"}, ...]}.
    """
    ip_nodes = {n["id"] for n in graph["nodes"] if n["type"] == "ip"}
    non_ip_nodes = {n["id"]: n for n in graph["nodes"] if n["type"] != "ip"}

    # For each non-IP node, find which IPs connect to it directly.
    node_to_ips: Dict[str, Set[str]] = defaultdict(set)
    for e in graph["edges"]:
        src, tgt = e["source"], e["target"]
        if src in ip_nodes and tgt in non_ip_nodes:
            node_to_ips[tgt].add(src)
        elif tgt in ip_nodes and src in non_ip_nodes:
            node_to_ips[src].add(tgt)

    bridge_nodes = {
        node_id for node_id, ips in node_to_ips.items()
        if len(ips) >= min_shared_degree
    }

    parent = {ip: ip for ip in ip_nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for node_id in bridge_nodes:
        ips = list(node_to_ips[node_id])
        for other in ips[1:]:
            union(ips[0], other)

    groups: Dict[str, Set[str]] = defaultdict(set)
    for ip in ip_nodes:
        groups[find(ip)].add(ip)

    campaigns = []
    for members in groups.values():
        if len(members) < min_ips:
            continue
        shared_nodes = [
            non_ip_nodes[node_id]
            for node_id in bridge_nodes
            if node_to_ips[node_id] & members
        ]
        campaigns.append({
            "ips": sorted(ip.split(":", 1)[1] for ip in members),
            "size": len(members),
            "shared_nodes": shared_nodes,
        })

    campaigns.sort(key=lambda c: c["size"], reverse=True)
    return campaigns


def explain_connection(
    ip_a: str,
    ip_b: str,
    graph: Dict[str, Any],
) -> List[Dict[str, str]]:
    """
    Return the rule/stage nodes directly shared by ip_a and ip_b (both
    connect to it) -- a human-readable "why are these two correlated"
    for the dashboard. Empty list if they share nothing directly (they
    may still be in the same campaign transitively, through a chain of
    other IPs -- this only reports *direct* shared nodes).
    """
    adj = _adjacency(graph)
    neighbors_a = adj.get(f"ip:{ip_a}", set())
    neighbors_b = adj.get(f"ip:{ip_b}", set())
    shared_ids = neighbors_a & neighbors_b

    nodes_by_id = {n["id"]: n for n in graph["nodes"]}
    return [nodes_by_id[nid] for nid in shared_ids if nid in nodes_by_id]