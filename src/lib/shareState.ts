// WAFSim v3 rc.9.3 — Shareable state URLs.
//
// Encodes a subset of workspace state (nodes, edges, wafs, ipSets,
// regexPatternSets) to a URL-safe base64 string. Round-trips through
// gzip compression via the browser's native CompressionStream when
// available — falls back to plain base64 if not.
//
// Design constraints:
//   - Must fit reasonably in a URL (target <8KB encoded, most workspaces
//     fit in 1-2KB compressed).
//   - Must be deterministic — same workspace always produces same URL.
//   - No secrets (IPSets contain IP addresses which might be sensitive;
//     we include them because they're part of the functional state, but
//     docs will warn users to redact before sharing).
//   - Version tagged so future schema changes can be migrated.

import type { AWSResourceNode, TopologyEdge, WebACL, IPSet, RegexPatternSet } from "./types";

const SHARE_VERSION = 1;

export interface ShareableState {
  v: number;
  nodes: AWSResourceNode[];
  edges: TopologyEdge[];
  wafs: WebACL[];
  ipSets: IPSet[];
  regexPatternSets: RegexPatternSet[];
}

// ---------- Encode ----------

export async function encodeShareableState(state: Omit<ShareableState, "v">): Promise<string> {
  const payload: ShareableState = { v: SHARE_VERSION, ...state };
  const json = JSON.stringify(payload);

  // Try gzip via CompressionStream (Chrome/Edge/Safari 16.4+/Firefox 113+).
  // Falls back to plain base64 if unsupported.
  try {
    if (typeof CompressionStream !== "undefined") {
      const stream = new Response(json).body!.pipeThrough(new CompressionStream("gzip"));
      const buf = await new Response(stream).arrayBuffer();
      return "z:" + toBase64Url(new Uint8Array(buf));
    }
  } catch {
    // fall through
  }
  return "p:" + toBase64Url(new TextEncoder().encode(json));
}

export async function decodeShareableState(encoded: string): Promise<ShareableState | null> {
  try {
    const prefix = encoded.slice(0, 2);
    const body = encoded.slice(2);
    const bytes = fromBase64Url(body);

    let json: string;
    if (prefix === "z:" && typeof DecompressionStream !== "undefined") {
      const stream = new Response(bytes).body!.pipeThrough(new DecompressionStream("gzip"));
      json = await new Response(stream).text();
    } else if (prefix === "p:") {
      json = new TextDecoder().decode(bytes);
    } else {
      // Legacy or unknown prefix — try both
      try {
        const stream = new Response(bytes).body!.pipeThrough(new DecompressionStream("gzip"));
        json = await new Response(stream).text();
      } catch {
        json = new TextDecoder().decode(bytes);
      }
    }

    const parsed = JSON.parse(json);
    if (typeof parsed !== "object" || parsed === null || parsed.v !== SHARE_VERSION) {
      return null;
    }
    return parsed as ShareableState;
  } catch {
    return null;
  }
}

// ---------- Base64-URL helpers ----------

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- URL plumbing ----------

export function buildShareUrl(baseUrl: string, encoded: string): string {
  const url = new URL(baseUrl);
  url.searchParams.set("state", encoded);
  return url.toString();
}

export function extractShareState(url: string): string | null {
  try {
    const u = new URL(url);
    return u.searchParams.get("state");
  } catch {
    return null;
  }
}
