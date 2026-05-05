// WAFSim v3 — shared test fixtures matching canonical types in src/lib/types.ts
// Centralized so all test files construct valid WAFv2 objects and we only update
// in one place if types evolve.

import type {
  HttpRequest,
  Rule,
  WebACL,
  IPSet,
  RegexPatternSet,
  VisibilityConfig,
} from "@/lib/types";

export function baseRequest(overrides: Partial<HttpRequest> = {}): HttpRequest {
  return {
    protocol: "HTTP/1.1",
    method: "GET",
    uri: "/",
    queryParams: {},
    headers: [
      { name: "Host", value: "example.com" },
      { name: "User-Agent", value: "Mozilla/5.0" },
    ],
    body: "",
    bodyEncoding: "none",
    contentType: "text/plain",
    sourceIP: "203.0.113.10",
    country: "US",
    ...overrides,
  };
}

export const defaultVisibility: VisibilityConfig = {
  sampledRequestsEnabled: true,
  cloudWatchMetricsEnabled: true,
  metricName: "WAFSimTestMetric",
};

export function makeRule(
  partial: Partial<Rule> & Pick<Rule, "name" | "priority" | "statement" | "action">
): Rule {
  return {
    ruleLabels: [],
    visibilityConfig: {
      ...defaultVisibility,
      metricName: partial.name.replace(/[^a-zA-Z0-9]/g, ""),
    },
    ...partial,
  } as Rule;
}

export function makeWebACL(
  partial: Partial<WebACL> & Pick<WebACL, "name" | "defaultAction" | "rules">
): WebACL {
  return {
    id: `test-webacl-${partial.name}`,
    scope: "REGIONAL",
    description: "",
    visibilityConfig: {
      ...defaultVisibility,
      metricName: partial.name.replace(/[^a-zA-Z0-9]/g, ""),
    },
    capacity: 0,
    ...partial,
  } as WebACL;
}

export function makeIPSet(
  partial: Partial<IPSet> & Pick<IPSet, "name" | "addresses">
): IPSet {
  return {
    id: `ipset-${partial.name}`,
    arn: `arn:aws:wafv2:us-east-1:000000000000:regional/ipset/${partial.name}/00000000`,
    description: "",
    scope: "REGIONAL",
    ipAddressVersion: "IPV4",
    ...partial,
  } as IPSet;
}

export function makeRegexPatternSet(
  partial: Partial<RegexPatternSet> & Pick<RegexPatternSet, "name" | "regularExpressionList">
): RegexPatternSet {
  return {
    id: `rps-${partial.name}`,
    arn: `arn:aws:wafv2:us-east-1:000000000000:regional/regexpatternset/${partial.name}/00000000`,
    description: "",
    scope: "REGIONAL",
    ...partial,
  } as RegexPatternSet;
}
