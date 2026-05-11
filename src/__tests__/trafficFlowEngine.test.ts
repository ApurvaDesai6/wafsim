// WAFSim v3 — Traffic flow engine tests
//
// The main motivating case is the bug Apurva reported: one regional WebACL
// attached to BOTH an ALB and an API Gateway. After running a SQLi attack,
// only the APIGW-side edges turned red; the ALB-side edges stayed green
// even though the WAF should have blocked traffic on both paths.
//
// Root cause (previous implementation): Map<wafId, resourceId> overwrote
// on each outgoing edge, so only the last resource got the WAF evaluation.
// Fix (this engine): iterate WAF → resource edges individually and
// evaluate per-protected-resource.

import { describe, expect, it } from "vitest";
import { simulateTrafficFlow } from "@/engines/trafficFlowEngine";
import type { AWSResourceNode, TopologyEdge, WebACL, Rule } from "@/lib/types";
import { baseRequest, makeRule, makeWebACL } from "./_fixtures";

function node(
  id: string,
  type: AWSResourceNode["type"],
  overrides: Partial<AWSResourceNode> = {}
): AWSResourceNode {
  return {
    id,
    type,
    label: id,
    icon: type,
    wafAttachable: false,
    position: { x: 0, y: 0 },
    ...overrides,
  } as AWSResourceNode;
}

function edge(id: string, source: string, target: string, wafId?: string): TopologyEdge {
  return { id, source, target, wafId } as TopologyEdge;
}

function sqliBlockingWebACL(): WebACL {
  return makeWebACL({
    name: "sqli-blocker",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: "BlockSQLi",
        priority: 0,
        action: "BLOCK",
        statement: {
          type: "SqliMatchStatement",
          fieldToMatch: { type: "QUERY_STRING" },
          textTransformations: [{ type: "URL_DECODE", priority: 0 }],
          sensitivityLevel: "LOW",
        } as Rule["statement"],
      }),
    ],
  });
}

describe("simulateTrafficFlow — reported bug: one WAF protecting multiple resources", () => {
  it("blocks BOTH ALB and APIGW paths when one WAF protects both", () => {
    const acl = sqliBlockingWebACL();
    const nodes: AWSResourceNode[] = [
      node("internet", "INTERNET"),
      node("waf", "WAF", { wafId: acl.id }),
      node("alb", "ALB", { wafAttachable: true, scope: "REGIONAL" }),
      node("apigw", "API_GATEWAY", { wafAttachable: true, scope: "REGIONAL" }),
      node("alb-backend", "ECS"),
      node("apigw-backend", "LAMBDA"),
    ];
    const edges: TopologyEdge[] = [
      edge("e1", "internet", "waf"),
      edge("e2", "waf", "alb", acl.id),
      edge("e3", "waf", "apigw", acl.id),
      edge("e4", "alb", "alb-backend"),
      edge("e5", "apigw", "apigw-backend"),
    ];

    const sqli = baseRequest({
      uri: "/api/users?id=1%27%20OR%201%3D1--",
      queryParams: { id: "1' OR 1=1--" },
    });

    const result = simulateTrafficFlow({
      nodes,
      edges,
      wafs: [acl],
      request: sqli,
    });

    // Both protected resources must be flagged as blocked
    expect(result.blockedNodes.has("alb")).toBe(true);
    expect(result.blockedNodes.has("apigw")).toBe(true);

    // Downstream of both must cascade blocked
    expect(result.blockedNodes.has("alb-backend")).toBe(true);
    expect(result.blockedNodes.has("apigw-backend")).toBe(true);

    // Both WAF → resource edges reported as blocked
    expect(result.edgeFlow.get("e2")).toBe("blocked"); // waf → alb
    expect(result.edgeFlow.get("e3")).toBe("blocked"); // waf → apigw

    // Downstream of each blocked resource: blocked
    expect(result.edgeFlow.get("e4")).toBe("blocked"); // alb → alb-backend
    expect(result.edgeFlow.get("e5")).toBe("blocked"); // apigw → apigw-backend

    // Internet → WAF still shows traffic arriving at the WAF
    expect(result.edgeFlow.get("e1")).toBe("passed");

    // Two path results recorded (one per protected resource)
    expect(result.pathResults).toHaveLength(2);
    const resourceIds = result.pathResults.map((p) => p.resourceId).sort();
    expect(resourceIds).toEqual(["alb", "apigw"].sort());
    expect(result.pathResults.every((p) => p.result.finalAction === "BLOCK")).toBe(true);
  });

  it("allows BOTH paths for a benign request (inverse case)", () => {
    const acl = sqliBlockingWebACL();
    const nodes: AWSResourceNode[] = [
      node("internet", "INTERNET"),
      node("waf", "WAF", { wafId: acl.id }),
      node("alb", "ALB", { wafAttachable: true, scope: "REGIONAL" }),
      node("apigw", "API_GATEWAY", { wafAttachable: true, scope: "REGIONAL" }),
    ];
    const edges: TopologyEdge[] = [
      edge("e1", "internet", "waf"),
      edge("e2", "waf", "alb", acl.id),
      edge("e3", "waf", "apigw", acl.id),
    ];

    const benign = baseRequest({ uri: "/healthcheck" });

    const result = simulateTrafficFlow({
      nodes,
      edges,
      wafs: [acl],
      request: benign,
    });

    expect(result.blockedNodes.size).toBe(0);
    expect(result.edgeFlow.get("e2")).toBe("passed");
    expect(result.edgeFlow.get("e3")).toBe("passed");
  });
});

describe("simulateTrafficFlow — single-WAF-single-resource baseline", () => {
  it("blocks downstream when WAF blocks", () => {
    const acl = sqliBlockingWebACL();
    const nodes: AWSResourceNode[] = [
      node("internet", "INTERNET"),
      node("waf", "WAF", { wafId: acl.id }),
      node("alb", "ALB", { wafAttachable: true, scope: "REGIONAL" }),
      node("ec2", "EC2"),
    ];
    const edges: TopologyEdge[] = [
      edge("e1", "internet", "waf"),
      edge("e2", "waf", "alb", acl.id),
      edge("e3", "alb", "ec2"),
    ];

    const sqli = baseRequest({
      uri: "/api/users?id=1%27%20OR%201%3D1--",
      queryParams: { id: "1' OR 1=1--" },
    });

    const result = simulateTrafficFlow({ nodes, edges, wafs: [acl], request: sqli });

    expect(result.blockedNodes.has("alb")).toBe(true);
    expect(result.blockedNodes.has("ec2")).toBe(true);
    expect(result.edgeFlow.get("e3")).toBe("blocked");
  });
});

describe("simulateTrafficFlow — fan-out/fan-in topologies", () => {
  it("handles ALB with multiple downstream backends (fan-out)", () => {
    const acl = sqliBlockingWebACL();
    const nodes: AWSResourceNode[] = [
      node("internet", "INTERNET"),
      node("waf", "WAF", { wafId: acl.id }),
      node("alb", "ALB", { wafAttachable: true, scope: "REGIONAL" }),
      node("svc1", "ECS"),
      node("svc2", "LAMBDA"),
      node("svc3", "EC2"),
    ];
    const edges: TopologyEdge[] = [
      edge("e1", "internet", "waf"),
      edge("e2", "waf", "alb", acl.id),
      edge("e3", "alb", "svc1"),
      edge("e4", "alb", "svc2"),
      edge("e5", "alb", "svc3"),
    ];

    const sqli = baseRequest({
      uri: "/api?q=1%27%20OR%201%3D1",
      queryParams: { q: "1' OR 1=1" },
    });
    const result = simulateTrafficFlow({ nodes, edges, wafs: [acl], request: sqli });

    for (const svc of ["svc1", "svc2", "svc3"]) {
      expect(result.blockedNodes.has(svc)).toBe(true);
    }
    expect(result.edgeFlow.get("e3")).toBe("blocked");
    expect(result.edgeFlow.get("e4")).toBe("blocked");
    expect(result.edgeFlow.get("e5")).toBe("blocked");
  });

  it("handles fan-in — same target reachable via two WAF-protected paths", () => {
    // Internet → WAF1 → ALB → S3
    //         → WAF2 → APIGW → Lambda → S3 (same S3)
    const aclPermissive = makeWebACL({
      name: "permissive",
      defaultAction: "ALLOW",
      rules: [],
    });
    const aclStrict = sqliBlockingWebACL();
    const nodes: AWSResourceNode[] = [
      node("internet", "INTERNET"),
      node("waf-a", "WAF", { wafId: aclPermissive.id }),
      node("waf-b", "WAF", { wafId: aclStrict.id }),
      node("alb", "ALB", { wafAttachable: true, scope: "REGIONAL" }),
      node("apigw", "API_GATEWAY", { wafAttachable: true, scope: "REGIONAL" }),
      node("lambda", "LAMBDA"),
      node("s3", "S3"),
    ];
    const edges: TopologyEdge[] = [
      edge("e1", "internet", "waf-a"),
      edge("e2", "waf-a", "alb", aclPermissive.id),
      edge("e3", "alb", "s3"),
      edge("e4", "internet", "waf-b"),
      edge("e5", "waf-b", "apigw", aclStrict.id),
      edge("e6", "apigw", "lambda"),
      edge("e7", "lambda", "s3"),
    ];

    const sqli = baseRequest({
      uri: "/x?q=1%27%20OR%201%3D1",
      queryParams: { q: "1' OR 1=1" },
    });
    const result = simulateTrafficFlow({
      nodes,
      edges,
      wafs: [aclPermissive, aclStrict],
      request: sqli,
    });

    // ALB path permissive → reaches S3
    expect(result.reachableNodes.has("alb")).toBe(true);
    expect(result.reachableNodes.has("s3")).toBe(true);

    // APIGW path strict → blocked before S3
    expect(result.blockedNodes.has("apigw")).toBe(true);
    expect(result.blockedNodes.has("lambda")).toBe(true);

    // S3 should NOT be in blockedNodes because one path still reaches it.
    // (It was added to reachableNodes via the ALB path.)
    expect(result.blockedNodes.has("s3")).toBe(false);
  });
});

describe("simulateTrafficFlow — entry node detection", () => {
  it("starts BFS from nodes without incoming traffic edges", () => {
    const nodes: AWSResourceNode[] = [
      node("internet", "INTERNET"),
      node("alb", "ALB"),
    ];
    const edges: TopologyEdge[] = [edge("e1", "internet", "alb")];

    const result = simulateTrafficFlow({
      nodes,
      edges,
      wafs: [],
      request: baseRequest(),
    });

    expect(result.reachableNodes.has("internet")).toBe(true);
    expect(result.reachableNodes.has("alb")).toBe(true);
    expect(result.edgeFlow.get("e1")).toBe("passed");
  });
});
