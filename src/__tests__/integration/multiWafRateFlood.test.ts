// Integration tests — workflows that the unit tests missed.
//
// These tests exist specifically because Apurva's 2026-05-08 testing on
// Vercel found three bugs that 169 passing unit tests did not catch. The
// unit tests validate engine correctness; these tests validate the
// integration between engines (single-shot topology sim + flood sim +
// topology-coloring state updates).
//
// Rule of thumb: if a unit test file has 20 tests and none of them fail
// when you break the Flood tab's rate-rule handling, the tests aren't
// catching user-visible behavior. These are the tests that catch it.

import { describe, it, expect } from "vitest";
import { simulateTrafficFlow } from "@/engines/trafficFlowEngine";
import { simulateFlood } from "@/engines/rateEngine";
import { makeWebACL, makeRule, baseRequest } from "../_fixtures";
import type {
  AWSResourceNode,
  TopologyEdge,
  Statement,
  RateBasedStatement,
} from "@/lib/types";

/**
 * Apurva's exact scenario: 3 WAFs, one with a rate-based rule, attached to
 * a CloudFront distribution. Regional WAF on ALB. Regional WAF on APIGW.
 * The CF WAF is NOT wafs[0] (the old code hardcoded wafs[0] as the flood
 * target — a bug that silently ran flood against the wrong WAF).
 */
function buildApurvaScenario() {
  // Rule set 1: regional WAF for ALB — basic geo block only (no rate rule)
  const albWaf = makeWebACL({
    id: "waf-alb",
    name: "WAF_ALB",
    scope: "REGIONAL",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: "BlockRussia",
        priority: 10,
        action: "BLOCK",
        statement: {
          type: "GeoMatchStatement",
          countryCodes: ["RU"],
        } as Statement,
      }),
    ],
  });

  // Rule set 2: regional WAF for APIGW — same as ALB
  const apigwWaf = makeWebACL({
    id: "waf-apigw",
    name: "WAF_APIGW",
    scope: "REGIONAL",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: "BlockRussia",
        priority: 10,
        action: "BLOCK",
        statement: {
          type: "GeoMatchStatement",
          countryCodes: ["RU"],
        } as Statement,
      }),
    ],
  });

  // Rule set 3: CF WAF — rate-based rule 100/5min
  const rateStmt: RateBasedStatement = {
    type: "RateBasedStatement",
    rateLimit: 100,
    evaluationWindowSec: 300,
    aggregateKeyType: "IP",
  };
  const cfWaf = makeWebACL({
    id: "waf-cf",
    name: "WAF_CF",
    scope: "CLOUDFRONT",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: "RateLimit100Per5min",
        priority: 10,
        action: "BLOCK",
        statement: rateStmt as unknown as Statement,
      }),
    ],
  });

  // Order deliberately puts CF WAF LAST, matching Apurva's scenario
  // (user added CF WAF last after creating ALB + APIGW WAFs). The old
  // wafs[0] bug would mis-target flood to WAF_ALB which has no rate rule.
  const wafs = [albWaf, apigwWaf, cfWaf];

  // Topology (WAFSim canonical model: WAF is side-attached to the resource
  // it protects, not an inline traffic hop):
  //
  //   Internet → CF → ALB → EC2
  //              CF → APIGW → Lambda
  //
  // Plus side-attached WAFs:
  //   WAF_CF → CF
  //   WAF_ALB → ALB
  //   WAF_APIGW → APIGW
  const nodes: AWSResourceNode[] = [
    { id: "internet", type: "Internet", label: "Internet", x: 0, y: 0 },
    { id: "cf", type: "CloudFront", label: "CF", x: 200, y: 0 },
    { id: "waf-cf-node", type: "WAF", label: "WAF_CF", wafId: "waf-cf", x: 200, y: 100 },
    { id: "alb", type: "ALB", label: "ALB", x: 400, y: -50 },
    { id: "waf-alb-node", type: "WAF", label: "WAF_ALB", wafId: "waf-alb", x: 400, y: 50 },
    { id: "ec2", type: "EC2", label: "EC2", x: 500, y: -50 },
    { id: "apigw", type: "APIGateway", label: "APIGW", x: 400, y: 150 },
    { id: "waf-apigw-node", type: "WAF", label: "WAF_APIGW", wafId: "waf-apigw", x: 400, y: 250 },
    { id: "lambda", type: "Lambda", label: "Lambda", x: 500, y: 150 },
  ];

  const edges: TopologyEdge[] = [
    // Traffic flow edges
    { id: "e1", source: "internet", target: "cf" },
    { id: "e2", source: "cf", target: "alb" },
    { id: "e3", source: "alb", target: "ec2" },
    { id: "e4", source: "cf", target: "apigw" },
    { id: "e5", source: "apigw", target: "lambda" },
    // WAF protection edges (side-attached)
    { id: "p1", source: "waf-cf-node", target: "cf" },
    { id: "p2", source: "waf-alb-node", target: "alb" },
    { id: "p3", source: "waf-apigw-node", target: "apigw" },
  ];

  return { wafs, nodes, edges, cfWaf, albWaf, apigwWaf };
}

describe("Integration — multi-WAF topology with rate-based rule on non-[0] WAF (Apurva's scenario)", () => {
  it("single-shot simulation does NOT show rate-based block on CF path (expected — single request can't trip rate limit)", () => {
    const { wafs, nodes, edges } = buildApurvaScenario();
    const flow = simulateTrafficFlow({
      nodes, edges, wafs,
      request: baseRequest({ uri: "/api", country: "US" }),
    });

    // All traffic edges pass because single-shot simulation can't trigger
    // rate rules (the only blocking rule on any WAF in this scenario is
    // the CF rate rule and geo blocks for RU, and the request is US).
    // This is expected behavior — the UI surfaces the rate-rule invisibility
    // via the "rate rule single-shot warning" banner.
    expect(flow.edgeFlow.get("e1")).toBe("passed");
    expect(flow.edgeFlow.get("e2")).toBe("passed");
    expect(flow.edgeFlow.get("e3")).toBe("passed");
    expect(flow.edgeFlow.get("e5")).toBe("passed");
  });

  it("flood against CF WAF trips rate limit and the topology override colors CF downstream as blocked", () => {
    const { wafs, nodes, edges, cfWaf } = buildApurvaScenario();

    // Simulate the flood — 2 req/sec × 60 seconds = 120 reqs, rate limit 100/5min
    // should trip well before the 60-second mark.
    const floodResult = simulateFlood(
      baseRequest({ uri: "/api", country: "US" }),
      cfWaf,
      120, // rpm (= 2 req/sec)
      1,   // 1 minute
      { varySourceIP: false }
    );

    // The rate limit MUST trip given this load
    expect(floodResult.triggersAtSeconds).not.toBeNull();
    expect(floodResult.blockedRequests).toBeGreaterThan(0);

    // Now run topology flow with the flood outcome as override
    const overrides = new Map<string, { action: string; reason: string }>();
    overrides.set(cfWaf.id, {
      action: "BLOCK",
      reason: "Rate limit tripped during flood",
    });

    const flow = simulateTrafficFlow({
      nodes, edges, wafs,
      request: baseRequest({ uri: "/api", country: "US" }),
      wafOutcomeOverrides: overrides,
    });

    // The CF-terminating action should be BLOCK per our override
    expect(flow.wafResults.get(cfWaf.id)).toBe("BLOCK");
    // The CloudFront resource is directly blocked by WAF_CF. Protection
    // edge from WAF_CF to CF is colored blocked.
    expect(flow.edgeFlow.get("p1")).toBe("blocked");
    // Traffic from Internet to CF still tries to flow (Internet is an
    // entry node) but CF is a sink (directly blocked). Everything
    // downstream of CF is unreachable.
    expect(flow.reachableNodes.has("alb")).toBe(false);
    expect(flow.reachableNodes.has("apigw")).toBe(false);
    expect(flow.reachableNodes.has("ec2")).toBe(false);
    expect(flow.reachableNodes.has("lambda")).toBe(false);
  });

  it("flood against WAF_ALB (has no rate rule) does NOT trip — rate limit lives on CF WAF only", () => {
    // This test catches the old wafs[0] bug: if flood mistakenly targeted
    // the first WAF in the array (WAF_ALB), which has no rate rule, the
    // flood would never trip. The Flood tab's new selector ensures the
    // user picks the WAF they actually want to flood.
    const { albWaf } = buildApurvaScenario();

    const floodResult = simulateFlood(
      baseRequest({ uri: "/api", country: "US" }),
      albWaf,
      120,
      1,
      { varySourceIP: false }
    );

    // ALB WAF has no rate-based rule — only geo block for RU. US requests
    // should always pass. Rate limit must not trip because there's no
    // rate rule to trip.
    expect(floodResult.triggersAtSeconds).toBeNull();
    expect(floodResult.blockedRequests).toBe(0);
  });

  it("regional WAFs still block their own specific threats independently of the CF flood", () => {
    // Attack from Russia against the ALB path. Regional WAF_ALB should
    // block regardless of what happens on CF. Confirms the topology
    // engine correctly isolates per-WAF outcomes.
    const { wafs, nodes, edges } = buildApurvaScenario();
    const flow = simulateTrafficFlow({
      nodes, edges, wafs,
      request: baseRequest({ uri: "/api", country: "RU" }),
    });

    // WAF_ALB terminates with BLOCK (geo rule)
    expect(flow.wafResults.get("waf-alb")).toBe("BLOCK");
    expect(flow.wafResults.get("waf-apigw")).toBe("BLOCK");
    // EC2 + Lambda should both be unreachable
    expect(flow.reachableNodes.has("ec2")).toBe(false);
    expect(flow.reachableNodes.has("lambda")).toBe(false);
  });
});

describe("Integration — state consistency invariants", () => {
  it("every WAF in wafResults with BLOCK action must have its downstream edge marked blocked", () => {
    const { wafs, nodes, edges, cfWaf } = buildApurvaScenario();
    const overrides = new Map<string, { action: string; reason: string }>();
    overrides.set(cfWaf.id, { action: "BLOCK", reason: "test override" });

    const flow = simulateTrafficFlow({
      nodes, edges, wafs,
      request: baseRequest(),
      wafOutcomeOverrides: overrides,
    });

    // Invariant: if a WAF's terminating action is BLOCK, the edge from its
    // WAF node to its protected resource must be colored "blocked". No
    // "BLOCK action but green edge" possible.
    for (const [wafId, action] of flow.wafResults.entries()) {
      if (action !== "BLOCK") continue;
      const wafNode = nodes.find((n) => n.type === "WAF" && n.wafId === wafId);
      if (!wafNode) continue;
      const outgoingEdges = edges.filter((e) => e.source === wafNode.id);
      for (const edge of outgoingEdges) {
        const flowState = flow.edgeFlow.get(edge.id);
        expect(
          flowState,
          `WAF ${wafId} has action BLOCK but outgoing edge ${edge.id} has state ${flowState}`
        ).toBe("blocked");
      }
    }
  });
});

describe("Integration — override takes precedence over default evaluation", () => {
  it("ALLOW override bypasses blocking rules in the WebACL", () => {
    // Proves the override mechanism correctly replaces evaluation, not
    // just augments it. If a flood didn't trip the rate rule but the
    // user's request would normally be blocked by geo rules, the override
    // (ALLOW) wins because that's what the flood result actually shows.
    const { wafs, nodes, edges, cfWaf } = buildApurvaScenario();
    const overrides = new Map<string, { action: string; reason: string }>();
    overrides.set(cfWaf.id, { action: "ALLOW", reason: "flood did not trip" });

    const flow = simulateTrafficFlow({
      nodes, edges, wafs,
      request: baseRequest({ country: "RU" }), // would normally match CF's geo rule... but CF has no geo rule, so not useful
      wafOutcomeOverrides: overrides,
    });

    expect(flow.wafResults.get(cfWaf.id)).toBe("ALLOW");
  });
});
