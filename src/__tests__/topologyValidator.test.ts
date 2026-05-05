// WAFSim v3 — Topology validator tests

import { describe, expect, it } from "vitest";
import { validateTopology, type TopoNode, type TopoEdge } from "@/engines/topologyValidator";

const N = (id: string, kind: TopoNode["kind"], extra: Partial<TopoNode> = {}): TopoNode => ({
  id,
  kind,
  ...extra,
});

const E = (source: string, target: string, id = `${source}->${target}`): TopoEdge => ({
  id,
  source,
  target,
});

describe("topologyValidator — simple valid topology", () => {
  it("passes with Internet → ALB → EC2 chain", () => {
    const nodes = [N("i", "INTERNET"), N("alb", "ALB"), N("ec2", "EC2")];
    const edges = [E("i", "alb"), E("alb", "ec2")];
    const r = validateTopology(nodes, edges);
    expect(r.valid).toBe(true);
    expect(r.stats.hasCycle).toBe(false);
    expect(r.findings).toEqual([]);
  });

  it("passes with WAF on edge to ALB", () => {
    const nodes = [
      N("i", "INTERNET"),
      N("waf", "WAF", { wafScope: "REGIONAL" }),
      N("alb", "ALB"),
      N("ec2", "EC2"),
    ];
    const edges = [E("i", "waf"), E("waf", "alb"), E("alb", "ec2")];
    const r = validateTopology(nodes, edges);
    expect(r.valid).toBe(true);
    expect(r.stats.wafNodeCount).toBe(1);
  });
});

describe("topologyValidator — cycle detection", () => {
  it("detects a 3-node cycle", () => {
    const nodes = [N("a", "ALB"), N("b", "API_GATEWAY"), N("c", "LAMBDA")];
    const edges = [E("a", "b"), E("b", "c"), E("c", "a")];
    const r = validateTopology(nodes, edges);
    expect(r.valid).toBe(false);
    expect(r.stats.hasCycle).toBe(true);
    expect(r.findings.some((f) => f.code === "CYCLE_DETECTED")).toBe(true);
  });

  it("does not false-positive on fan-in (multiple sources to one target)", () => {
    const nodes = [N("i", "INTERNET"), N("a", "ALB"), N("b", "ALB"), N("db", "LAMBDA")];
    const edges = [E("i", "a"), E("i", "b"), E("a", "db"), E("b", "db")];
    const r = validateTopology(nodes, edges);
    expect(r.stats.hasCycle).toBe(false);
  });
});

describe("topologyValidator — WAF attachment rules", () => {
  it("allows WAF before CloudFront / ALB / API Gateway / AppSync / Cognito / App Runner / Verified Access", () => {
    const attachable: TopoNode["kind"][] = [
      "CLOUDFRONT",
      "ALB",
      "API_GATEWAY",
      "APPSYNC",
      "COGNITO",
      "APP_RUNNER",
      "VERIFIED_ACCESS",
    ];
    for (const kind of attachable) {
      const scope = kind === "CLOUDFRONT" ? "CLOUDFRONT" : "REGIONAL";
      const nodes = [
        N("i", "INTERNET"),
        N("w", "WAF", { wafScope: scope }),
        N("r", kind),
      ];
      const edges = [E("i", "w"), E("w", "r")];
      const r = validateTopology(nodes, edges);
      expect(r.valid, `${kind} should accept WAF`).toBe(true);
    }
  });

  it("rejects WAF before EC2", () => {
    const nodes = [N("i", "INTERNET"), N("w", "WAF", { wafScope: "REGIONAL" }), N("e", "EC2")];
    const edges = [E("i", "w"), E("w", "e")];
    const r = validateTopology(nodes, edges);
    expect(r.valid).toBe(false);
    expect(r.findings.some((f) => f.code === "WAF_INVALID_ATTACHMENT")).toBe(true);
  });

  it("rejects WAF before NAT Gateway", () => {
    const nodes = [N("i", "INTERNET"), N("w", "WAF", { wafScope: "REGIONAL" }), N("n", "NAT_GATEWAY")];
    const edges = [E("i", "w"), E("w", "n")];
    const r = validateTopology(nodes, edges);
    expect(r.valid).toBe(false);
    expect(r.findings.some((f) => f.code === "WAF_INVALID_ATTACHMENT")).toBe(true);
  });

  it("flags dangling WAF", () => {
    const nodes = [N("i", "INTERNET"), N("w", "WAF"), N("alb", "ALB")];
    const edges = [E("i", "alb")]; // w has no edges
    const r = validateTopology(nodes, edges);
    expect(r.findings.some((f) => f.code === "WAF_DANGLING")).toBe(true);
  });
});

describe("topologyValidator — scope mismatches", () => {
  it("flags CLOUDFRONT resource with REGIONAL WAF scope", () => {
    const nodes = [
      N("i", "INTERNET"),
      N("w", "WAF", { wafScope: "REGIONAL" }),
      N("cf", "CLOUDFRONT"),
    ];
    const edges = [E("i", "w"), E("w", "cf")];
    const r = validateTopology(nodes, edges);
    expect(r.valid).toBe(false);
    expect(r.findings.some((f) => f.code === "WAF_SCOPE_MISMATCH")).toBe(true);
  });

  it("flags REGIONAL resource with CLOUDFRONT WAF scope", () => {
    const nodes = [
      N("i", "INTERNET"),
      N("w", "WAF", { wafScope: "CLOUDFRONT" }),
      N("alb", "ALB"),
    ];
    const edges = [E("i", "w"), E("w", "alb")];
    const r = validateTopology(nodes, edges);
    expect(r.valid).toBe(false);
    expect(r.findings.some((f) => f.code === "WAF_SCOPE_MISMATCH")).toBe(true);
  });

  it("does not flag when scope matches", () => {
    const nodes = [
      N("i", "INTERNET"),
      N("w1", "WAF", { wafScope: "CLOUDFRONT" }),
      N("cf", "CLOUDFRONT"),
      N("w2", "WAF", { wafScope: "REGIONAL" }),
      N("alb", "ALB"),
    ];
    const edges = [E("i", "w1"), E("w1", "cf"), E("i", "w2", "e2"), E("w2", "alb")];
    const r = validateTopology(nodes, edges);
    expect(r.findings.some((f) => f.code === "WAF_SCOPE_MISMATCH")).toBe(false);
  });
});

describe("topologyValidator — unreachable nodes", () => {
  it("flags nodes with no Internet path", () => {
    const nodes = [
      N("i", "INTERNET"),
      N("alb", "ALB"),
      N("orphan", "LAMBDA"),
      N("orphan2", "S3"),
    ];
    const edges = [E("i", "alb"), E("orphan", "orphan2")];
    const r = validateTopology(nodes, edges);
    expect(r.findings.some((f) => f.code === "UNREACHABLE_NODES")).toBe(true);
    expect(r.stats.unreachableNodeCount).toBeGreaterThan(0);
  });

  it("does not flag Internet-rooted nodes as unreachable", () => {
    const nodes = [N("i", "INTERNET"), N("alb", "ALB"), N("ec2", "EC2")];
    const edges = [E("i", "alb"), E("alb", "ec2")];
    const r = validateTopology(nodes, edges);
    expect(r.findings.some((f) => f.code === "UNREACHABLE_NODES")).toBe(false);
  });
});

describe("topologyValidator — dangling edges", () => {
  it("flags edges that reference missing nodes", () => {
    const nodes = [N("i", "INTERNET"), N("alb", "ALB")];
    const edges = [E("i", "alb"), E("alb", "ghost")];
    const r = validateTopology(nodes, edges);
    expect(r.findings.some((f) => f.code === "DANGLING_EDGE")).toBe(true);
  });
});
