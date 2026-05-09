// WAFSim v3 — AWS WAF log parser
//
// Parses two input shapes:
//
//   1. Sampled Request (from GetSampledRequests API / WAF console Sample Requests tab)
//      Shape: { Weight, Timestamp, Action, Request: { ClientIP, Country, URI, Method, Headers[], HTTPVersion, HTTPSourceName }, RuleNameWithinRuleGroup, ... }
//
//   2. Full WAF log record (from Kinesis Firehose delivery to S3)
//      Shape: { timestamp, formatVersion, webaclId, terminatingRuleId,
//        terminatingRuleType, action, terminatingRuleMatchDetails[],
//        httpSourceName, httpSourceId, ruleGroupList[], rateBasedRuleList[],
//        nonTerminatingMatchingRules[], requestHeadersInserted[],
//        responseCodeSent, httpRequest: { clientIp, country, headers[],
//        uri, args, httpVersion, httpMethod, requestId, fragment, scheme,
//        host }, labels[] }
//
// Reference:
//   https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
//   https://docs.aws.amazon.com/waf/latest/APIReference/API_SampledHTTPRequest.html

import type { HttpRequest, WAFAction } from "@/lib/types";

export interface ParsedWafLog {
  /** The HTTP request that was evaluated (usable by simulateTrafficFlow / evaluateWebACL). */
  request: HttpRequest;
  /** The final WAF action taken on this request. */
  action: WAFAction;
  /** The rule or rule group that terminated evaluation, if any. */
  terminatingRuleId?: string;
  /** Which managed rule group (if any) the terminating rule came from. */
  terminatingRuleGroupName?: string;
  /** Labels applied during evaluation — critical for label-based exception rules. */
  labels: string[];
  /** The original timestamp (ms since epoch). */
  timestamp?: number;
  /** Free-text description of what matched (for UI display). */
  matchReason?: string;
  /** Raw log JSON, preserved for display. */
  rawLog: Record<string, unknown>;
}

export interface ParseResult {
  ok: boolean;
  log?: ParsedWafLog;
  error?: string;
}

/**
 * Parse a WAF log JSON string. Accepts both sampled-request and full-log
 * shapes and picks whichever one matches.
 */
export function parseWafLog(input: string): ParseResult {
  let raw: unknown;
  try {
    raw = JSON.parse(input);
  } catch (e) {
    return { ok: false, error: `Not valid JSON: ${(e as Error).message}` };
  }
  if (!raw || typeof raw !== "object") {
    return { ok: false, error: "Input is not a JSON object" };
  }
  const rec = raw as Record<string, unknown>;

  // Detect sampled-request format (camelCase of the SampledHTTPRequest type)
  // vs full Kinesis log format (lowercased property names).
  if (isSampledRequest(rec)) {
    return parseSampledRequest(rec);
  }
  if (isFullLog(rec)) {
    return parseFullLog(rec);
  }
  return {
    ok: false,
    error:
      "Unrecognized WAF log shape. Expected Sampled Request (with Request: { ClientIP, URI, Method }) or full Kinesis log (with httpRequest: { clientIp, uri, httpMethod }).",
  };
}

// ---------------------------------------------------------------------------
// Sampled-request format (API: GetSampledRequests)
// ---------------------------------------------------------------------------

function isSampledRequest(rec: Record<string, unknown>): boolean {
  if ("Request" in rec) {
    const r = rec.Request as Record<string, unknown> | undefined;
    return !!(r && ("URI" in r || "Method" in r));
  }
  return false;
}

function parseSampledRequest(rec: Record<string, unknown>): ParseResult {
  const r = (rec.Request ?? {}) as Record<string, unknown>;
  const uri = typeof r.URI === "string" ? r.URI : "/";
  const method = normalizeMethod(typeof r.Method === "string" ? r.Method : "GET");
  const clientIP = typeof r.ClientIP === "string" ? r.ClientIP : "0.0.0.0";
  const country = typeof r.Country === "string" ? r.Country : "";
  const httpVersion = typeof r.HTTPVersion === "string" ? r.HTTPVersion : "HTTP/1.1";
  const sampledHeaders = (Array.isArray(r.Headers) ? r.Headers : []) as Array<{
    Name?: string;
    Value?: string;
  }>;
  const headers = sampledHeaders
    .filter((h) => typeof h.Name === "string" && typeof h.Value === "string")
    .map((h) => ({ name: h.Name!, value: h.Value! }));

  const action = normalizeAction(typeof rec.Action === "string" ? rec.Action : "BLOCK");
  const terminatingRuleId = typeof rec.RuleNameWithinRuleGroup === "string"
    ? rec.RuleNameWithinRuleGroup
    : undefined;
  const labels = extractLabels(rec);

  const { path, queryString, queryParams } = splitUri(uri);

  const request: HttpRequest = {
    protocol: normalizeProtocol(httpVersion),
    method,
    uri: path + (queryString ? `?${queryString}` : ""),
    queryParams,
    headers,
    body: "", // sampled requests don't include body
    bodyEncoding: "none",
    contentType: findHeader(headers, "content-type") ?? "text/plain",
    sourceIP: clientIP,
    country,
  };

  return {
    ok: true,
    log: {
      request,
      action,
      terminatingRuleId,
      labels,
      timestamp: typeof rec.Timestamp === "string" ? Date.parse(rec.Timestamp) : undefined,
      matchReason: terminatingRuleId ? `Matched rule: ${terminatingRuleId}` : undefined,
      rawLog: rec,
    },
  };
}

// ---------------------------------------------------------------------------
// Full Kinesis log format
// ---------------------------------------------------------------------------

function isFullLog(rec: Record<string, unknown>): boolean {
  if ("httpRequest" in rec) {
    const r = rec.httpRequest as Record<string, unknown> | undefined;
    return !!(r && ("uri" in r || "httpMethod" in r));
  }
  return false;
}

function parseFullLog(rec: Record<string, unknown>): ParseResult {
  const r = (rec.httpRequest ?? {}) as Record<string, unknown>;
  const uri = typeof r.uri === "string" ? r.uri : "/";
  const method = normalizeMethod(typeof r.httpMethod === "string" ? r.httpMethod : "GET");
  const clientIP = typeof r.clientIp === "string" ? r.clientIp : "0.0.0.0";
  const country = typeof r.country === "string" ? r.country : "";
  const httpVersion = typeof r.httpVersion === "string" ? r.httpVersion : "HTTP/1.1";
  const args = typeof r.args === "string" ? r.args : "";
  const host = typeof r.host === "string" ? r.host : "";

  const logHeaders = (Array.isArray(r.headers) ? r.headers : []) as Array<{
    name?: string;
    value?: string;
  }>;
  const headers = logHeaders
    .filter((h) => typeof h.name === "string" && typeof h.value === "string")
    .map((h) => ({ name: h.name!, value: h.value! }));
  if (host && !findHeader(headers, "host")) {
    headers.unshift({ name: "Host", value: host });
  }

  const action = normalizeAction(typeof rec.action === "string" ? rec.action : "BLOCK");
  const terminatingRuleId =
    typeof rec.terminatingRuleId === "string" ? rec.terminatingRuleId : undefined;
  // Identify the managed rule group that owned the terminating rule
  const ruleGroupList = (Array.isArray(rec.ruleGroupList) ? rec.ruleGroupList : []) as Array<{
    ruleGroupId?: string;
    terminatingRule?: { ruleId?: string };
  }>;
  const terminatingRuleGroupName = ruleGroupList.find(
    (g) => g.terminatingRule?.ruleId === terminatingRuleId
  )?.ruleGroupId;

  const labels = extractLabels(rec);

  // Match details: terminatingRuleMatchDetails is useful for human-readable reason
  const matchDetails = (Array.isArray(rec.terminatingRuleMatchDetails)
    ? rec.terminatingRuleMatchDetails
    : []) as Array<{
    conditionType?: string;
    location?: string;
    matchedData?: string[];
  }>;
  const matchReason = matchDetails.length
    ? matchDetails
        .map(
          (d) =>
            `${d.conditionType ?? "MATCH"} in ${d.location ?? "?"}: ${
              d.matchedData?.join(", ") ?? ""
            }`
        )
        .join("; ")
    : terminatingRuleId
    ? `Matched rule: ${terminatingRuleId}`
    : undefined;

  const { path, queryString, queryParams } = splitUri(uri + (args ? `?${args}` : ""));

  const request: HttpRequest = {
    protocol: normalizeProtocol(httpVersion),
    method,
    uri: path + (queryString ? `?${queryString}` : ""),
    queryParams,
    headers,
    body: "", // full logs don't include body (intentional — WAF doesn't log bodies)
    bodyEncoding: "none",
    contentType: findHeader(headers, "content-type") ?? "text/plain",
    sourceIP: clientIP,
    country,
  };

  return {
    ok: true,
    log: {
      request,
      action,
      terminatingRuleId,
      terminatingRuleGroupName,
      labels,
      timestamp: typeof rec.timestamp === "number" ? rec.timestamp : undefined,
      matchReason,
      rawLog: rec,
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractLabels(rec: Record<string, unknown>): string[] {
  const labels = rec.labels;
  if (!Array.isArray(labels)) return [];
  return labels
    .map((l) => (l as Record<string, unknown>)?.name)
    .filter((n): n is string => typeof n === "string");
}

function findHeader(
  headers: Array<{ name: string; value: string }>,
  name: string
): string | undefined {
  const lname = name.toLowerCase();
  return headers.find((h) => h.name.toLowerCase() === lname)?.value;
}

function splitUri(uri: string): { path: string; queryString: string; queryParams: Record<string, string> } {
  const qIdx = uri.indexOf("?");
  if (qIdx === -1) return { path: uri, queryString: "", queryParams: {} };
  const path = uri.substring(0, qIdx);
  const queryString = uri.substring(qIdx + 1);
  const params: Record<string, string> = {};
  for (const piece of queryString.split("&")) {
    if (!piece) continue;
    const eq = piece.indexOf("=");
    const key = decodeURIComponent(eq === -1 ? piece : piece.substring(0, eq));
    const value = eq === -1 ? "" : decodeURIComponent(piece.substring(eq + 1));
    params[key] = value;
  }
  return { path, queryString, queryParams: params };
}

function normalizeMethod(m: string): HttpRequest["method"] {
  const M = m.toUpperCase();
  const known: Array<HttpRequest["method"]> = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
  ];
  return (known as string[]).includes(M) ? (M as HttpRequest["method"]) : "GET";
}

function normalizeProtocol(v: string): HttpRequest["protocol"] {
  if (v.includes("2")) return "HTTP/2";
  if (v.includes("3")) return "HTTP/3";
  if (v.includes("1.0")) return "HTTP/1.0";
  return "HTTP/1.1";
}

function normalizeAction(a: string): WAFAction {
  const A = a.toUpperCase();
  const known: WAFAction[] = ["ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE"];
  return (known as string[]).includes(A) ? (A as WAFAction) : "BLOCK";
}
