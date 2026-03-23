// WAFSim - Field Extractor Engine
// Extracts field-to-match components from HTTP requests

import { FieldToMatch, HttpRequest } from "@/lib/types";

/**
 * Extract the URI path from the request
 */
function extractUriPath(request: HttpRequest): string {
  // Extract just the path portion (without query string)
  const uri = request.uri || "/";
  const queryIndex = uri.indexOf("?");
  return queryIndex >= 0 ? uri.substring(0, queryIndex) : uri;
}

/**
 * Extract the query string from the request
 */
function extractQueryString(request: HttpRequest): string {
  // Build query string from queryParams or extract from URI
  if (request.queryParams && Object.keys(request.queryParams).length > 0) {
    return Object.entries(request.queryParams)
      .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
      .join("&");
  }

  // Try to extract from URI
  const queryIndex = request.uri.indexOf("?");
  return queryIndex >= 0 ? request.uri.substring(queryIndex + 1) : "";
}

/**
 * Extract the request body
 */
function extractBody(
  request: HttpRequest,
  oversizeHandling: "CONTINUE" | "MATCH" | "NO_MATCH" = "CONTINUE",
  maxSize: number = 8192
): { content: string; oversize: boolean } {
  let body = request.body || "";

  // Handle base64 encoded body
  if (request.bodyEncoding === "base64" && body) {
    try {
      body = typeof atob !== "undefined" ? atob(body) : Buffer.from(body, "base64").toString("binary");
    } catch {
      // Keep as-is if decode fails
    }
  }

  const oversize = body.length > maxSize;

  if (oversize) {
    switch (oversizeHandling) {
      case "MATCH":
        return { content: body.substring(0, maxSize), oversize: true };
      case "NO_MATCH":
        return { content: "", oversize: true };
      case "CONTINUE":
      default:
        return { content: body, oversize: true };
    }
  }

  return { content: body, oversize: false };
}

/**
 * Extract the HTTP method
 */
function extractMethod(request: HttpRequest): string {
  return request.method || "GET";
}

/**
 * Extract a single header by name (case-insensitive)
 */
function extractSingleHeader(request: HttpRequest, headerName: string): string {
  const header = request.headers?.find(
    (h) => h.name.toLowerCase() === headerName.toLowerCase()
  );
  return header?.value || "";
}

/**
 * Extract all headers
 */
function extractAllHeaders(
  request: HttpRequest,
  matchScope: "KEY" | "VALUE" | "ALL" = "ALL",
  oversizeHandling: string = "CONTINUE"
): string {
  if (!request.headers || request.headers.length === 0) {
    return "";
  }

  switch (matchScope) {
    case "KEY":
      return request.headers.map((h) => h.name).join("\n");
    case "VALUE":
      return request.headers.map((h) => h.value).join("\n");
    case "ALL":
    default:
      return request.headers.map((h) => `${h.name}: ${h.value}`).join("\n");
  }
}

/**
 * Extract a single query argument by name
 */
function extractSingleQueryArgument(request: HttpRequest, argName: string): string {
  // Check queryParams object first
  if (request.queryParams && argName in request.queryParams) {
    return request.queryParams[argName];
  }

  // Try to extract from URI query string
  const queryString = extractQueryString(request);
  const params = new URLSearchParams(queryString);
  return params.get(argName) || "";
}

/**
 * Extract all query arguments
 */
function extractAllQueryArguments(request: HttpRequest): string {
  const queryString = extractQueryString(request);
  if (!queryString) return "";

  const params = new URLSearchParams(queryString);
  return Array.from(params.entries())
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
}

/**
 * Extract cookies from request
 */
function extractCookies(
  request: HttpRequest,
  matchScope: "KEY" | "VALUE" | "ALL" = "ALL"
): string {
  // Try Cookie header first
  const cookieHeader = extractSingleHeader(request, "Cookie");
  if (!cookieHeader) return "";

  // Parse cookies
  const cookies: Array<{ name: string; value: string }> = [];
  cookieHeader.split(";").forEach((cookie) => {
    const trimmed = cookie.trim();
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex >= 0) {
      cookies.push({
        name: trimmed.substring(0, eqIndex).trim(),
        value: trimmed.substring(eqIndex + 1).trim(),
      });
    }
  });

  switch (matchScope) {
    case "KEY":
      return cookies.map((c) => c.name).join("\n");
    case "VALUE":
      return cookies.map((c) => c.value).join("\n");
    case "ALL":
    default:
      return cookies.map((c) => `${c.name}=${c.value}`).join("\n");
  }
}

/**
 * Extract JSON body field
 */
function extractJsonBody(
  request: HttpRequest,
  jsonMatchScope: "VALUE" | "KEY" | "ALL" = "VALUE",
  invalidFallback: "MATCH" | "NO_MATCH" | "EVALUATE_AS_STRING" = "EVALUATE_AS_STRING"
): string {
  const body = extractBody(request).content;

  if (!body) {
    return "";
  }

  try {
    const parsed = JSON.parse(body);

    switch (jsonMatchScope) {
      case "KEY":
        return extractJsonKeys(parsed).join("\n");
      case "VALUE":
        return extractJsonValues(parsed).join("\n");
      case "ALL":
      default:
        return JSON.stringify(parsed, null, 0);
    }
  } catch {
    // Invalid JSON
    switch (invalidFallback) {
      case "MATCH":
        return body;
      case "NO_MATCH":
        return "";
      case "EVALUATE_AS_STRING":
      default:
        return body;
    }
  }
}

/**
 * Recursively extract all keys from JSON object
 */
function extractJsonKeys(obj: unknown, prefix: string = ""): string[] {
  if (typeof obj !== "object" || obj === null) {
    return [];
  }

  const keys: string[] = [];
  const record = obj as Record<string, unknown>;

  for (const key of Object.keys(record)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    keys.push(fullKey);
    keys.push(...extractJsonKeys(record[key], fullKey));
  }

  return keys;
}

/**
 * Recursively extract all values from JSON object
 */
function extractJsonValues(obj: unknown): string[] {
  if (typeof obj !== "object" || obj === null) {
    return [String(obj)];
  }

  const values: string[] = [];
  const record = obj as Record<string, unknown>;

  for (const value of Object.values(record)) {
    values.push(...extractJsonValues(value));
  }

  return values;
}

/**
 * Extract JA3 fingerprint
 */
function extractJa3Fingerprint(
  request: HttpRequest,
  fallback: "MATCH" | "NO_MATCH" = "NO_MATCH"
): string {
  // Return the JA3 fingerprint if provided
  if (request.ja3Fingerprint) {
    return request.ja3Fingerprint;
  }

  // Fallback behavior
  return fallback === "MATCH" ? "" : "";
}

/**
 * Extract HTTP version
 */
function extractHttpVersion(request: HttpRequest): string {
  return request.httpVersion || request.protocol || "HTTP/1.1";
}

/**
 * Extract header order (names in order)
 */
function extractHeaderOrder(request: HttpRequest): string {
  if (!request.headers || request.headers.length === 0) {
    return "";
  }
  return request.headers.map((h) => h.name).join(",");
}

/**
 * Main field extractor function
 * Extracts the specified field from an HTTP request
 */
export function extractField(
  request: HttpRequest,
  fieldToMatch: FieldToMatch
): { content: string; oversize?: boolean } {
  switch (fieldToMatch.type) {
    case "URI_PATH":
      return { content: extractUriPath(request) };

    case "QUERY_STRING":
      return { content: extractQueryString(request) };

    case "BODY":
      return extractBody(request, fieldToMatch.oversizeHandling);

    case "METHOD":
      return { content: extractMethod(request) };

    case "SINGLE_HEADER":
      return { content: extractSingleHeader(request, fieldToMatch.name || "") };

    case "ALL_HEADERS":
      return {
        content: extractAllHeaders(
          request,
          fieldToMatch.matchScope || "ALL",
          fieldToMatch.oversizeHandling || "CONTINUE"
        ),
      };

    case "SINGLE_QUERY_ARGUMENT":
      return { content: extractSingleQueryArgument(request, fieldToMatch.name || "") };

    case "ALL_QUERY_ARGUMENTS":
      return { content: extractAllQueryArguments(request) };

    case "COOKIES":
      return { content: extractCookies(request, fieldToMatch.matchScope || "ALL") };

    case "JSON_BODY":
      return {
        content: extractJsonBody(
          request,
          fieldToMatch.jsonMatchScope || "VALUE",
          fieldToMatch.invalidFallback || "EVALUATE_AS_STRING"
        ),
      };

    case "JA3_FINGERPRINT":
      return {
        content: extractJa3Fingerprint(
          request,
          fieldToMatch.fallbackBehavior || "NO_MATCH"
        ),
      };

    case "HTTP_VERSION":
      return { content: extractHttpVersion(request) };

    case "HEADER_ORDER":
      return { content: extractHeaderOrder(request) };

    default:
      return { content: "" };
  }
}

/**
 * Get all headers as a map (for inspection purposes)
 */
export function getHeadersMap(request: HttpRequest): Map<string, string[]> {
  const headerMap = new Map<string, string[]>();

  if (request.headers) {
    for (const header of request.headers) {
      const key = header.name.toLowerCase();
      const existing = headerMap.get(key) || [];
      existing.push(header.value);
      headerMap.set(key, existing);
    }
  }

  return headerMap;
}

/**
 * Check if a header exists (case-insensitive)
 */
export function hasHeader(request: HttpRequest, headerName: string): boolean {
  return request.headers?.some(
    (h) => h.name.toLowerCase() === headerName.toLowerCase()
  ) || false;
}

/**
 * Get all cookie names from request
 */
export function getCookieNames(request: HttpRequest): string[] {
  const cookieHeader = extractSingleHeader(request, "Cookie");
  if (!cookieHeader) return [];

  return cookieHeader
    .split(";")
    .map((cookie) => {
      const eqIndex = cookie.indexOf("=");
      return eqIndex >= 0 ? cookie.substring(0, eqIndex).trim() : cookie.trim();
    })
    .filter((name) => name.length > 0);
}

/**
 * Get query parameter names from request
 */
export function getQueryParamNames(request: HttpRequest): string[] {
  const names: string[] = [];

  if (request.queryParams) {
    names.push(...Object.keys(request.queryParams));
  }

  // Also check URI
  const queryString = extractQueryString(request);
  if (queryString) {
    const params = new URLSearchParams(queryString);
    params.forEach((_, key) => {
      if (!names.includes(key)) {
        names.push(key);
      }
    });
  }

  return names;
}
