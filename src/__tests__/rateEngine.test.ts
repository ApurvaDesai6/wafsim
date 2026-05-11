// WAFSim v3 — rateEngine flood simulation tests
// Verifies simulateFlood produces correct timeline entries, trigger detection,
// and counters match AWS rate-based rule semantics.

import { describe, expect, it } from "vitest";
import { simulateFlood } from "@/engines/rateEngine";
import type { Rule, WebACL, HttpRequest } from "@/lib/types";
import { makeRule, makeWebACL, baseRequest } from "./_fixtures";

function floodRequest(): HttpRequest {
  return baseRequest({
    uri: "/api/endpoint",
    method: "GET",
    sourceIP: "198.51.100.100",
  });
}

function rateOnlyAcl(limit: number): WebACL {
  return makeWebACL({
    name: "rate-flood-test",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: "RateLimit",
        priority: 0,
        action: "BLOCK",
        statement: {
          type: "RateBasedStatement",
          rateLimit: limit,
          evaluationWindowSec: 300,
          aggregateKeyType: "IP",
        } as Rule["statement"],
      }),
    ],
  });
}

describe("simulateFlood — basic shape", () => {
  it("produces a non-empty timeline with expected totals", () => {
    const acl = rateOnlyAcl(1000);
    const result = simulateFlood(floodRequest(), acl, 600, 1); // 10/sec for 60s = 600 req
    expect(result.timeline.length).toBeGreaterThan(0);
    expect(result.totalRequests).toBe(result.blockedRequests + result.allowedRequests);
    expect(result.totalRequests).toBeGreaterThan(0);
  });
});

describe("simulateFlood — below-threshold traffic", () => {
  it("does not trigger rate limit when rate stays below limit", () => {
    const acl = rateOnlyAcl(10000); // 10k per 5min = ~33/sec → we'll send 1/sec
    const result = simulateFlood(floodRequest(), acl, 60, 1); // 60 rpm → 1 req/sec for 1 min = 60 req
    expect(result.triggersAtSeconds).toBeNull();
    expect(result.blockedRequests).toBe(0);
    expect(result.allowedRequests).toBe(result.totalRequests);
  });
});

describe("simulateFlood — flood triggers rate rule", () => {
  it("trips the rate limit and reports triggersAtSeconds", () => {
    const acl = rateOnlyAcl(100); // Low limit
    // 6000 req/min → 100/sec for 1 min = 6000 total. Will blow past 100 within seconds.
    const result = simulateFlood(floodRequest(), acl, 6000, 1);
    expect(result.triggersAtSeconds).not.toBeNull();
    expect(result.triggersAtSeconds!).toBeGreaterThan(0);
    expect(result.blockedRequests).toBeGreaterThan(0);
    expect(result.triggerRequestCount).toBeGreaterThan(0);
  });
});

describe("simulateFlood — timeline ordering", () => {
  it("timeline entries are in ascending elapsed time order", () => {
    const acl = rateOnlyAcl(100);
    const result = simulateFlood(floodRequest(), acl, 300, 1);
    for (let i = 1; i < result.timeline.length; i++) {
      expect(result.timeline[i].elapsedSeconds).toBeGreaterThanOrEqual(
        result.timeline[i - 1].elapsedSeconds
      );
    }
  });

  it("each timeline entry has a valid action", () => {
    const acl = rateOnlyAcl(100);
    const result = simulateFlood(floodRequest(), acl, 300, 1);
    for (const entry of result.timeline) {
      expect(["ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE"]).toContain(entry.action);
    }
  });
});

describe("simulateFlood — IP variation (distributed attack)", () => {
  it("fewer requests hit the rate limit when source IPs vary per request", () => {
    // With 100 req/min threshold, a single IP floods quickly, but if IPs vary
    // per request each bucket stays under the threshold.
    const acl = rateOnlyAcl(100);
    const sameIP = simulateFlood(floodRequest(), acl, 600, 1); // 10/sec single IP
    const variedIP = simulateFlood(floodRequest(), acl, 600, 1, { varySourceIP: true });
    expect(variedIP.blockedRequests).toBeLessThan(sameIP.blockedRequests);
  });
});
