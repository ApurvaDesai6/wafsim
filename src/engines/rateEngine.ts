// WAFSim - Rate-Based Rule Simulation Engine
// Simulates rate-based rule behavior for flood attack testing

import {
  RateBasedStatement,
  HttpRequest,
  FloodSimulationResult,
  FloodTimelineEntry,
  WAFAction,
} from "@/lib/types";
import { evaluateWebACL } from "./wafEngine";
import { WebACL, Rule, EvaluationResult } from "@/lib/types";

/**
 * Simulate a flood attack against a rate-based rule
 */
export function simulateFlood(
  baseRequest: HttpRequest,
  webACL: WebACL,
  requestsPerMinute: number,
  durationMinutes: number,
  options: {
    ipSets?: Array<{ arn: string; name: string; addresses: string[] }>;
    regexPatternSets?: Array<{ arn: string; name: string; regularExpressionList: string[] }>;
    varySourceIP?: boolean; // Simulate distributed attack
  } = {}
): FloodSimulationResult {
  const totalRequests = Math.floor((requestsPerMinute * durationMinutes));
  const intervalMs = 60000 / requestsPerMinute; // Time between requests
  const startTime = Date.now();

  // Find rate-based rules in the WebACL
  const rateRules = webACL.rules.filter(
    (r) => r.statement.type === "RateBasedStatement"
  );

  // Initialize rate tracking
  const rateTracking = {
    requestCounts: new Map<string, number[]>(),
    windowMs: 60000, // 1 minute default
  };

  const timeline: FloodTimelineEntry[] = [];
  let blockedCount = 0;
  let allowedCount = 0;
  let triggerTime: number | null = null;
  let triggerRequestCount = 0;

  for (let i = 0; i < totalRequests; i++) {
    // Create request variant
    const request: HttpRequest = {
      ...baseRequest,
      sourceIP: options.varySourceIP
        ? varyIP(baseRequest.sourceIP, i)
        : baseRequest.sourceIP,
    };

    const requestTimestamp = startTime + i * intervalMs;
    const elapsedSeconds = (requestTimestamp - startTime) / 1000;

    // Update rate tracking for each rate rule
    for (const rule of rateRules) {
      const rateStatement = rule.statement as RateBasedStatement;
      updateRateTracking(rateTracking, rateStatement, request, requestTimestamp);
    }

    // Evaluate the request
    const result = evaluateWebACL(request, webACL, {
      ipSets: options.ipSets as never,
      regexPatternSets: options.regexPatternSets as never,
      requestTimestamp,
      rateTracking,
    });

    // Track results
    if (result.finalAction === "BLOCK") {
      blockedCount++;
      if (triggerTime === null) {
        triggerTime = elapsedSeconds;
        triggerRequestCount = i + 1;
      }
    } else {
      allowedCount++;
    }

    // Record timeline entry every 10 requests or at key moments
    if (i % 10 === 0 || i === totalRequests - 1 || (triggerTime && elapsedSeconds - triggerTime < 1)) {
      // Get current rate for the primary rate rule
      let currentRate = 0;
      if (rateRules.length > 0) {
        const primaryRateRule = rateRules[0].statement as RateBasedStatement;
        const key = getRateKey(primaryRateRule, request);
        const timestamps = rateTracking.requestCounts.get(key || "default") || [];
        currentRate = timestamps.length;
      }

      timeline.push({
        elapsedSeconds,
        requestCount: i + 1,
        currentRate,
        rateLimitHit: triggerTime !== null,
        action: result.finalAction,
      });
    }
  }

  return {
    triggersAtSeconds: triggerTime,
    triggerRequestCount,
    totalRequests,
    blockedRequests: blockedCount,
    allowedRequests: allowedCount,
    timeline,
  };
}

/**
 * Update rate tracking state
 */
function updateRateTracking(
  rateTracking: { requestCounts: Map<string, number[]>; windowMs: number },
  statement: RateBasedStatement,
  request: HttpRequest,
  timestamp: number
): void {
  const key = getRateKey(statement, request);
  if (!key) return;

  const timestamps = rateTracking.requestCounts.get(key) || [];
  timestamps.push(timestamp);

  // Keep only timestamps within the evaluation window
  const windowStart = timestamp - (statement.evaluationWindowSec * 1000);
  const recentTimestamps = timestamps.filter((t) => t > windowStart);
  rateTracking.requestCounts.set(key, recentTimestamps);
}

/**
 * Get the rate tracking key for a request
 */
function getRateKey(statement: RateBasedStatement, request: HttpRequest): string | null {
  switch (statement.aggregateKeyType) {
    case "IP":
      return `ip:${request.sourceIP}`;

    case "FORWARDED_IP":
      const headerName = statement.forwardedIPConfig?.headerName || "X-Forwarded-For";
      const forwardedIP = request.headers?.find(
        (h) => h.name.toLowerCase() === headerName.toLowerCase()
      )?.value;
      return forwardedIP ? `fwdip:${forwardedIP.split(",")[0].trim()}` : null;

    case "CONSTANT":
      return "constant:all";

    case "CUSTOM_KEYS":
      if (!statement.aggregateKeys || statement.aggregateKeys.length === 0) {
        return null;
      }
      const keyParts: string[] = [];
      for (const key of statement.aggregateKeys) {
        if (key.ip) {
          keyParts.push(request.sourceIP);
        } else if (key.header && key.header.name) {
          const headerVal = request.headers?.find(
            (h) => h.name.toLowerCase() === key.header!.name.toLowerCase()
          )?.value || "";
          keyParts.push(headerVal);
        } else if (key.cookie && key.cookie.name) {
          const cookieHeader = request.headers?.find(
            (h) => h.name.toLowerCase() === "cookie"
          )?.value || "";
          const match = cookieHeader.match(new RegExp(`${key.cookie.name}=([^;]+)`));
          keyParts.push(match?.[1] || "");
        } else if (key.queryArgument && key.queryArgument.name) {
          const params = new URLSearchParams(request.uri.split("?")[1] || "");
          keyParts.push(params.get(key.queryArgument.name) || "");
        } else if (key.queryString) {
          keyParts.push(request.uri.split("?")[1] || "");
        } else if (key.httpMethod) {
          keyParts.push(request.method);
        } else if (key.uriPath) {
          keyParts.push(request.uri.split("?")[0]);
        }
      }
      return `custom:${keyParts.join(":")}`;

    default:
      return null;
  }
}

/**
 * Generate a slightly varied IP address
 */
function varyIP(baseIP: string, index: number): string {
  // Parse IPv4
  const parts = baseIP.split(".");
  if (parts.length === 4) {
    // Vary the last octet
    const lastOctet = (parseInt(parts[3]) + index) % 256;
    return `${parts[0]}.${parts[1]}.${parts[2]}.${lastOctet}`;
  }

  // For IPv6 or invalid, return base IP
  return baseIP;
}

/**
 * Calculate when a rate-based rule would trigger
 */
export function calculateRateTrigger(
  rateLimit: number,
  requestsPerMinute: number,
  evaluationWindowSec: number
): {
  triggersAtSeconds: number | null;
  triggerRequestCount: number;
  requestCountAtWindowEnd: number;
} {
  if (requestsPerMinute <= rateLimit) {
    // Rate limit won't be hit
    return {
      triggersAtSeconds: null,
      triggerRequestCount: 0,
      requestCountAtWindowEnd: Math.ceil((requestsPerMinute * evaluationWindowSec) / 60),
    };
  }

  // Calculate when rate limit will be exceeded
  // requests per second
  const requestsPerSecond = requestsPerMinute / 60;

  // Number of requests needed to exceed limit in window
  const triggerRequestCount = rateLimit + 1;

  // Time when the (rateLimit + 1)th request will be sent
  const triggersAtSeconds = (triggerRequestCount - 1) / requestsPerSecond;

  // Maximum requests in a full window
  const requestCountAtWindowEnd = Math.ceil((requestsPerMinute * evaluationWindowSec) / 60);

  return {
    triggersAtSeconds,
    triggerRequestCount,
    requestCountAtWindowEnd,
  };
}

/**
 * Get rate-based rule summary
 */
export function getRateRuleSummary(
  statement: RateBasedStatement
): {
  threshold: number;
  windowSeconds: number;
  aggregateType: string;
  description: string;
} {
  const aggregateDescriptions: Record<string, string> = {
    IP: "Source IP address",
    FORWARDED_IP: "Forwarded IP from X-Forwarded-For header",
    CONSTANT: "All requests combined",
    CUSTOM_KEYS: "Custom aggregation keys",
  };

  return {
    threshold: statement.rateLimit,
    windowSeconds: statement.evaluationWindowSec,
    aggregateType: statement.aggregateKeyType,
    description: `Rate limit: ${statement.rateLimit} requests per ${statement.evaluationWindowSec} seconds, aggregated by ${aggregateDescriptions[statement.aggregateKeyType] || statement.aggregateKeyType}`,
  };
}

/**
 * Simulate rate rule evaluation for a single request
 */
export function evaluateRateRule(
  statement: RateBasedStatement,
  request: HttpRequest,
  requestCount: number,
  timestamps: number[],
  requestTimestamp: number
): {
  matched: boolean;
  currentRate: number;
  reason: string;
} {
  // Count requests in the window
  const windowStart = requestTimestamp - (statement.evaluationWindowSec * 1000);
  const recentTimestamps = timestamps.filter((t) => t > windowStart);
  const currentRate = recentTimestamps.length;

  const matched = currentRate > statement.rateLimit;

  return {
    matched,
    currentRate,
    reason: matched
      ? `Rate exceeded: ${currentRate} > ${statement.rateLimit} limit`
      : `Rate within limit: ${currentRate}/${statement.rateLimit}`,
  };
}
