// WAFSim v3 — Topology validator
//
// Pre-simulation static analysis of a WAFSim topology. Finds:
//   1. Cycles (a component -> a component that eventually reaches back).
//      Uses Kahn's algorithm: if after removing zero-in-degree nodes in a
//      loop, any edges remain, the graph has a cycle.
//   2. Invalid WAF attachment points — WAF can only attach to the edge
//      leading to CloudFront, ALB, API Gateway, AppSync, Cognito User Pool,
//      App Runner, or Verified Access (AWS documented list).
//   3. Scope mismatches — a WAF node on an edge leading to CloudFront must
//      have scope=CLOUDFRONT; leading to ALB/APIGW/AppSync must be REGIONAL.
//   4. Dangling WAF nodes — WAF nodes without upstream/downstream connections.
//   5. Unreachable components — nodes with no path from any Internet entry.
//
// Designed to be run synchronously against the current topology state before
// a simulation kicks off, and to surface findings in the UI.

export type NodeKind =
  | "INTERNET"
  | "CLOUDFRONT"
  | "ALB"
  | "API_GATEWAY"
  | "APPSYNC"
  | "COGNITO"
  | "APP_RUNNER"
  | "VERIFIED_ACCESS"
  | "EC2"
  | "ECS"
  | "LAMBDA"
  | "S3"
  | "NAT_GATEWAY"
  | "WAF";

export interface TopoNode {
  id: string;
  kind: NodeKind;
  label?: string;
  // For WAF nodes: the scope the WebACL is set to
  wafScope?: "CLOUDFRONT" | "REGIONAL";
}

export interface TopoEdge {
  id: string;
  source: string;     // node id
  target: string;     // node id
}

export type FindingSeverity = "info" | "warning" | "error";

export interface TopoFinding {
  severity: FindingSeverity;
  code: string;        // machine-readable tag
  message: string;
  nodeIds?: string[];  // nodes implicated
  edgeIds?: string[];  // edges implicated
  recommendation?: string;
}

export interface TopoReport {
  valid: boolean;
  findings: TopoFinding[];
  stats: {
    nodeCount: number;
    edgeCount: number;
    wafNodeCount: number;
    hasCycle: boolean;
    unreachableNodeCount: number;
  };
}

const WAF_ATTACHABLE: Record<NodeKind, boolean> = {
  INTERNET: false,
  CLOUDFRONT: true,
  ALB: true,
  API_GATEWAY: true,
  APPSYNC: true,
  COGNITO: true,
  APP_RUNNER: true,
  VERIFIED_ACCESS: true,
  EC2: false,
  ECS: false,
  LAMBDA: false,
  S3: false,
  NAT_GATEWAY: false,
  WAF: false,
};

const CLOUDFRONT_ONLY: Record<NodeKind, boolean> = {
  INTERNET: false,
  CLOUDFRONT: true,
  ALB: false,
  API_GATEWAY: false,
  APPSYNC: false,
  COGNITO: false,
  APP_RUNNER: false,
  VERIFIED_ACCESS: false,
  EC2: false,
  ECS: false,
  LAMBDA: false,
  S3: false,
  NAT_GATEWAY: false,
  WAF: false,
};

/**
 * Validate a topology graph.
 */
export function validateTopology(nodes: TopoNode[], edges: TopoEdge[]): TopoReport {
  const findings: TopoFinding[] = [];
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const incoming = new Map<string, string[]>(); // node id -> list of source ids
  const outgoing = new Map<string, string[]>(); // node id -> list of target ids

  for (const n of nodes) {
    incoming.set(n.id, []);
    outgoing.set(n.id, []);
  }
  for (const e of edges) {
    if (nodeById.has(e.source) && nodeById.has(e.target)) {
      outgoing.get(e.source)!.push(e.target);
      incoming.get(e.target)!.push(e.source);
    } else {
      findings.push({
        severity: "warning",
        code: "DANGLING_EDGE",
        message: `Edge ${e.id} references a node that doesn't exist`,
        edgeIds: [e.id],
      });
    }
  }

  // ---- Cycle detection via Kahn's topological sort ----
  const inDegree = new Map<string, number>();
  for (const n of nodes) inDegree.set(n.id, incoming.get(n.id)!.length);
  const queue: string[] = [];
  for (const [id, deg] of inDegree.entries()) {
    if (deg === 0) queue.push(id);
  }
  let visited = 0;
  while (queue.length > 0) {
    const nodeId = queue.shift()!;
    visited++;
    for (const target of outgoing.get(nodeId) ?? []) {
      const nextDeg = (inDegree.get(target) ?? 0) - 1;
      inDegree.set(target, nextDeg);
      if (nextDeg === 0) queue.push(target);
    }
  }
  const hasCycle = visited < nodes.length;
  if (hasCycle) {
    const cyclicNodeIds = [...inDegree.entries()]
      .filter(([, deg]) => deg > 0)
      .map(([id]) => id);
    findings.push({
      severity: "error",
      code: "CYCLE_DETECTED",
      message:
        "Topology contains a cycle. WAF evaluation follows a directed request path (Internet → resource) so cycles make the flow ambiguous.",
      nodeIds: cyclicNodeIds,
      recommendation: "Remove one edge in the cycle so there is a clear request direction.",
    });
  }

  // ---- WAF attachment validation ----
  const wafNodes = nodes.filter((n) => n.kind === "WAF");
  for (const wafNode of wafNodes) {
    const downstream = outgoing.get(wafNode.id) ?? [];
    const upstream = incoming.get(wafNode.id) ?? [];

    // Dangling WAF: only fires if the WAF has no downstream (isn't
    // protecting anything). WAF nodes in WAFSim's canonical model are
    // side-attached — they have no upstream, just a "protects" edge
    // pointing to the resource they're attached to. The previous rule
    // fired on normal WAF nodes constantly, which made the banner
    // useless.
    if (downstream.length === 0) {
      findings.push({
        severity: "warning",
        code: "WAF_DANGLING",
        message: `WAF node "${wafNode.label ?? wafNode.id}" is not attached to any resource.`,
        nodeIds: [wafNode.id],
        recommendation:
          "Connect this WAF to a CloudFront distribution, ALB, API Gateway, AppSync, Cognito User Pool, App Runner, or Verified Access.",
      });
      continue;
    }
    // Suppress the upstream check entirely — side-attached WAFs never have it.
    void upstream;

    // WAF must not be attached to a non-attachable resource
    for (const targetId of downstream) {
      const target = nodeById.get(targetId);
      if (!target) continue;
      if (!WAF_ATTACHABLE[target.kind]) {
        findings.push({
          severity: "error",
          code: "WAF_INVALID_ATTACHMENT",
          message: `WAF cannot be attached to a ${target.kind} (${target.label ?? target.id}).`,
          nodeIds: [wafNode.id, target.id],
          recommendation:
            "AWS WAF attaches only to CloudFront, ALB, API Gateway, AppSync, Cognito User Pool, App Runner, or Verified Access. Remove this WAF node or move it upstream of a supported resource.",
        });
      }
    }

    // Scope mismatch
    if (wafNode.wafScope) {
      for (const targetId of downstream) {
        const target = nodeById.get(targetId);
        if (!target) continue;
        if (CLOUDFRONT_ONLY[target.kind] && wafNode.wafScope !== "CLOUDFRONT") {
          findings.push({
            severity: "error",
            code: "WAF_SCOPE_MISMATCH",
            message: `WAF "${wafNode.label ?? wafNode.id}" has scope=REGIONAL but is attached to a CloudFront distribution.`,
            nodeIds: [wafNode.id, target.id],
            recommendation:
              "CloudFront distributions require a CLOUDFRONT-scope WebACL. Change this WAF's scope to CLOUDFRONT.",
          });
        }
        if (!CLOUDFRONT_ONLY[target.kind] && WAF_ATTACHABLE[target.kind] && wafNode.wafScope !== "REGIONAL") {
          findings.push({
            severity: "error",
            code: "WAF_SCOPE_MISMATCH",
            message: `WAF "${wafNode.label ?? wafNode.id}" has scope=CLOUDFRONT but is attached to a ${target.kind}.`,
            nodeIds: [wafNode.id, target.id],
            recommendation: "REGIONAL resources (ALB, API Gateway, etc.) require a REGIONAL-scope WebACL.",
          });
        }
      }
    }
  }

  // ---- Unreachable nodes (no path from any INTERNET node) ----
  // rc.9: Exclude WAF nodes from this check. WAFSim's canonical model has
  // WAF nodes side-attached to the resources they protect, so they never
  // appear on the Internet→resource traffic path. Flagging them as
  // unreachable fires constantly on well-formed topologies.
  const internetIds = nodes.filter((n) => n.kind === "INTERNET").map((n) => n.id);
  const reachable = new Set<string>();
  const stack = [...internetIds];
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (reachable.has(id)) continue;
    reachable.add(id);
    for (const t of outgoing.get(id) ?? []) stack.push(t);
  }
  const unreachableNodes = nodes.filter(
    (n) =>
      n.kind !== "INTERNET" &&
      n.kind !== "WAF" &&
      !reachable.has(n.id) &&
      (outgoing.get(n.id)!.length > 0 || incoming.get(n.id)!.length > 0)
  );
  if (unreachableNodes.length > 0) {
    findings.push({
      severity: "info",
      code: "UNREACHABLE_NODES",
      message: `${unreachableNodes.length} node(s) have no path from an Internet entry.`,
      nodeIds: unreachableNodes.map((n) => n.id),
      recommendation:
        "Connect an Internet node upstream of these components, or remove them if they are not part of the request path you want to simulate.",
    });
  }

  return {
    valid: !findings.some((f) => f.severity === "error"),
    findings,
    stats: {
      nodeCount: nodes.length,
      edgeCount: edges.length,
      wafNodeCount: wafNodes.length,
      hasCycle,
      unreachableNodeCount: unreachableNodes.length,
    },
  };
}
