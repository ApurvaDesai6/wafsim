// WAFSim v3 — Traffic-flow simulation engine
//
// Computes, for a given HTTP request and WebACL configuration, which nodes in
// a topology are reachable (green), which are blocked (red), and the
// per-WAF terminating action. Runs from entry nodes through the topology,
// evaluating each WAF as traffic arrives at its protected resource and
// treating WAF-blocked resources as full blockers for downstream
// reachability.
//
// Correctly handles:
//   - A single WebACL protecting multiple resources (e.g. same regional
//     WebACL attached to an ALB and an API Gateway). Prior implementations
//     used Map<wafId, resourceId>, overwriting on each outgoing edge, so
//     only the last-iterated resource saw the WAF evaluation.
//   - Fan-in (a node reachable via multiple paths; one path is blocked,
//     another isn't; the node should be shown as reachable).
//   - Fan-out (one node with multiple downstream backends; all should
//     cascade as blocked if the upstream resource is blocked).

import type {
  AWSResourceNode,
  TopologyEdge,
  WebACL,
  HttpRequest,
  IPSet,
  RegexPatternSet,
  EvaluationResult,
} from "@/lib/types";
import { evaluateWebACL } from "./wafEngine";

export interface PathResult {
  wafId: string;
  wafName: string;
  resourceId: string;
  result: EvaluationResult;
}

export interface TrafficFlowResult {
  /** Per-edge flow state: "passed" if traffic flowed through, "blocked" if stopped */
  edgeFlow: Map<string, "passed" | "blocked">;
  /** Per-WAF terminating action (used for WAF-node tooltips and badges) */
  wafResults: Map<string, string>;
  /** Nodes where traffic was blocked (either directly by a WAF or cascaded downstream with no alt path) */
  blockedNodes: Set<string>;
  /** Nodes that received traffic successfully */
  reachableNodes: Set<string>;
  /** One PathResult per (waf, resource) pair evaluated — used for the sampled-requests table */
  pathResults: PathResult[];
  /** The result shown in the primary EvaluationTrace panel — prefers the first blocking result */
  displayResult: PathResult | null;
}

interface SimulateOptions {
  nodes: AWSResourceNode[];
  edges: TopologyEdge[];
  wafs: WebACL[];
  ipSets?: IPSet[];
  regexPatternSets?: RegexPatternSet[];
  request: HttpRequest;
  /**
   * v3 rc.9 — optional per-WAF action overrides. When set, the engine uses
   * the override instead of evaluating the WAF against the (single) request.
   * This is how the Flood tab feeds its final outcome (rate-limit tripped /
   * not tripped) into topology coloring, without the flood logic needing
   * to reimplement the topology reachability algorithm. Rate-based rules
   * can only fire with multi-request context, so without this hook the
   * single-request simulation path would always show them as ALLOW.
   *
   * Map key = WAF id. The override describes the action that would terminate
   * for this WAF at end-of-flood. Typical usage:
   *   - BLOCK when flood tripped the rate rule
   *   - ALLOW when flood ran to completion without tripping
   */
  wafOutcomeOverrides?: Map<string, { action: string; reason: string }>;
}

export function simulateTrafficFlow(options: SimulateOptions): TrafficFlowResult {
  const { nodes, edges, wafs, request } = options;

  // -------------------------------------------------------------
  // 1. Index the topology.
  // -------------------------------------------------------------
  const wafNodeById = new Map<string, AWSResourceNode>();
  for (const node of nodes) {
    if (node.type === "WAF") wafNodeById.set(node.id, node);
  }

  // Adjacency maps:
  //   normalChildren[nodeId] = list of downstream nodes via normal traffic edges
  //   wafExpansion[wafNodeId] = list of resources the WAF protects
  const normalChildren = new Map<string, string[]>();
  const wafExpansion = new Map<string, string[]>();
  for (const edge of edges) {
    const sourceIsWaf = wafNodeById.has(edge.source);
    if (sourceIsWaf) {
      if (!wafExpansion.has(edge.source)) wafExpansion.set(edge.source, []);
      wafExpansion.get(edge.source)!.push(edge.target);
    } else {
      if (!normalChildren.has(edge.source)) normalChildren.set(edge.source, []);
      normalChildren.get(edge.source)!.push(edge.target);
    }
  }

  // Entry nodes = nodes with no incoming non-WAF-expansion edge. Typically
  // Internet nodes. Both normal edges and Internet → WAF edges count as
  // incoming; only WAF → resource (expansion) edges don't.
  const incomingCount = new Map<string, number>();
  for (const edge of edges) {
    if (wafNodeById.has(edge.source)) continue; // skip WAF expansion
    incomingCount.set(edge.target, (incomingCount.get(edge.target) ?? 0) + 1);
  }
  const entryNodeIds = nodes
    .filter((n) => n.type !== "WAF" && (incomingCount.get(n.id) ?? 0) === 0)
    .map((n) => n.id);

  // -------------------------------------------------------------
  // 2. Evaluate every WAF against each of its protected resources.
  //
  // A WAF's WebACL is evaluated once per (resource, request) pair. For a
  // single simulation request the result is the same for every resource,
  // but we record each (waf, resource) pair so the UI can attribute the
  // BLOCK to the correct edge.
  // -------------------------------------------------------------
  const pathResults: PathResult[] = [];
  const wafResults = new Map<string, string>();
  const directlyBlockedResources = new Set<string>();

  for (const wafNode of wafNodeById.values()) {
    if (!wafNode.wafId) continue;
    const waf = wafs.find((w) => w.id === wafNode.wafId);
    if (!waf) continue;
    const protectedResources = wafExpansion.get(wafNode.id) ?? [];
    for (const resourceId of protectedResources) {
      // rc.9: honor override if provided for this WAF. The override lets
      // the Flood tab color the topology based on whether the rate limit
      // tripped, without this engine needing to do multi-request simulation.
      const override = options.wafOutcomeOverrides?.get(waf.id);
      const result: EvaluationResult = override
        ? {
            finalAction: override.action as EvaluationResult["finalAction"],
            terminatingRule: null,
            allMatchedRules: [],
            labelsApplied: [],
            ruleTrace: [
              {
                ruleName: "(flood outcome)",
                priority: -1,
                matched: override.action !== "ALLOW",
                action: override.action as EvaluationResult["finalAction"],
                labelsAdded: [],
                terminates: true,
                reason: override.reason,
              },
            ],
            requestWithTransformations: request,
            approximatedManagedRules: false,
          }
        : evaluateWebACL(request, waf, {
            ipSets: options.ipSets,
            regexPatternSets: options.regexPatternSets,
          });
      pathResults.push({ wafId: waf.id, wafName: waf.name, resourceId, result });

      // Track terminating action per-WAF. If the same WAF has mixed
      // results across resources (shouldn't happen with a single request
      // but defensively handle it), the terminating one wins.
      const existing = wafResults.get(waf.id);
      if (
        !existing ||
        existing === "ALLOW" ||
        (existing === "COUNT" && ["BLOCK", "CAPTCHA", "CHALLENGE"].includes(result.finalAction))
      ) {
        wafResults.set(waf.id, result.finalAction);
      }

      if (["BLOCK", "CAPTCHA", "CHALLENGE"].includes(result.finalAction)) {
        directlyBlockedResources.add(resourceId);
      }
    }
  }

  // -------------------------------------------------------------
  // 3. Compute reachability.
  //
  // "reachable" = traffic from any entry can arrive here via some path
  // that doesn't pass through a directly-blocked resource.
  //
  // BFS from entries. When encountering a WAF node, expand to its
  // protected resources. Directly-blocked resources are SINKS: traffic
  // arrives at them (they are reachable themselves) but does not
  // propagate further.
  // -------------------------------------------------------------
  const reachableNodes = new Set<string>(entryNodeIds);
  const queue: string[] = [...entryNodeIds];
  while (queue.length > 0) {
    const current = queue.shift()!;
    // Blocked resources are reachable (traffic arrived) but don't propagate
    if (directlyBlockedResources.has(current)) continue;

    const currentNode = nodes.find((n) => n.id === current);
    if (!currentNode) continue;

    const targets =
      currentNode.type === "WAF"
        ? wafExpansion.get(current) ?? []
        : normalChildren.get(current) ?? [];
    for (const t of targets) {
      if (!reachableNodes.has(t)) {
        reachableNodes.add(t);
        queue.push(t);
      }
    }
  }

  // -------------------------------------------------------------
  // 4. Derive final blocked-node set.
  //
  // A node is "blocked" if it's a directly blocked resource, OR if it is
  // NOT reachable at all AND it has at least one incoming edge (i.e. it's
  // a dead downstream path, not an isolated island).
  // -------------------------------------------------------------
  const blockedNodes = new Set<string>(directlyBlockedResources);
  const allNodeIds = new Set(nodes.map((n) => n.id));
  for (const n of nodes) {
    if (!reachableNodes.has(n.id) && !blockedNodes.has(n.id) && n.type !== "WAF") {
      // Only mark as "blocked" if it's actually downstream of a blocked
      // path. An isolated node with no incoming edges stays as neither
      // blocked nor reachable (edge coloring below handles it).
      const hasIncoming = edges.some((e) => !wafNodeById.has(e.source) && e.target === n.id);
      if (hasIncoming) blockedNodes.add(n.id);
    }
  }
  void allNodeIds; // kept for potential future use

  // -------------------------------------------------------------
  // 5. Build the edge flow map.
  // -------------------------------------------------------------
  const edgeFlow = new Map<string, "passed" | "blocked">();
  for (const edge of edges) {
    const sourceIsWaf = wafNodeById.has(edge.source);
    if (sourceIsWaf) {
      // WAF → resource: reflects whether the resource was directly blocked
      edgeFlow.set(
        edge.id,
        directlyBlockedResources.has(edge.target) ? "blocked" : "passed"
      );
    } else if (directlyBlockedResources.has(edge.source)) {
      // Source was a directly-blocked resource → no traffic flows out
      edgeFlow.set(edge.id, "blocked");
    } else if (reachableNodes.has(edge.source)) {
      // Source received traffic → this edge carried traffic downstream
      edgeFlow.set(edge.id, "passed");
    } else {
      // Source never received traffic (dead path)
      edgeFlow.set(edge.id, "blocked");
    }
  }

  const displayResult =
    pathResults.find((p) =>
      ["BLOCK", "CAPTCHA", "CHALLENGE"].includes(p.result.finalAction)
    ) ?? pathResults[pathResults.length - 1] ?? null;

  return {
    edgeFlow,
    wafResults,
    blockedNodes,
    reachableNodes,
    pathResults,
    displayResult,
  };
}
