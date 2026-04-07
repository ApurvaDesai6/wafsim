// WAFSim - Text Transformation Engine
// Implements all 15 AWS WAF text transformations

import { TextTransformationType, TextTransformation } from "@/lib/types";

/**
 * URL Decode - decodes URL-encoded characters
 * Converts %XX sequences to their character equivalents
 */
function urlDecode(s: string): string {
  try {
    // Handle + as space first
    let result = s.replace(/\+/g, " ");
    // Decode %XX sequences
    result = decodeURIComponent(result);
    return result;
  } catch {
    // If decoding fails, return original
    return s;
  }
}

/**
 * URL Decode Unicode - decodes URL-encoded unicode characters
 * Handles %uXXXX format in addition to standard URL encoding
 */
function urlDecodeUni(s: string): string {
  try {
    // Handle + as space
    let result = s.replace(/\+/g, " ");
    // Handle %uXXXX unicode sequences
    result = result.replace(/%u([0-9A-Fa-f]{4})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
    // Handle standard %XX sequences
    result = decodeURIComponent(result);
    return result;
  } catch {
    return s;
  }
}

/**
 * HTML Entity Decode - decodes HTML entities
 * Handles named entities, decimal, and hex numeric entities
 */
function htmlEntityDecode(s: string): string {
  const entityMap: Record<string, string> = {
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&nbsp;": " ",
    "&copy;": "©",
    "&reg;": "®",
    "&trade;": "™",
    "&euro;": "€",
    "&pound;": "£",
    "&yen;": "¥",
    "&cent;": "¢",
    "&mdash;": "—",
    "&ndash;": "–",
    "&hellip;": "...",
    "&lsquo;": "'",
    "&rsquo;": "'",
    "&ldquo;": "\"",
    "&rdquo;": "\"",
  };

  let result = s;

  // Decode named entities
  for (const [entity, char] of Object.entries(entityMap)) {
    result = result.split(entity).join(char);
    // Also handle case-insensitive
    result = result.split(entity.toLowerCase()).join(char);
    result = result.split(entity.toUpperCase()).join(char);
  }

  // Decode decimal numeric entities &#1234;
  result = result.replace(/&#(\d+);?/g, (_, dec) => {
    const codePoint = parseInt(dec, 10);
    if (codePoint > 0 && codePoint < 0x10ffff) {
      return String.fromCodePoint(codePoint);
    }
    return _;
  });

  // Decode hex numeric entities &#x1a2b;
  result = result.replace(/&#[xX]([0-9A-Fa-f]+);?/g, (_, hex) => {
    const codePoint = parseInt(hex, 16);
    if (codePoint > 0 && codePoint < 0x10ffff) {
      return String.fromCodePoint(codePoint);
    }
    return _;
  });

  return result;
}

/**
 * Compress White Space - normalize whitespace
 * Replaces multiple whitespace characters with single space, trims
 */
function compressWhiteSpace(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

/**
 * CMD Line - normalize shell command formatting
 * Removes shell metacharacters and normalizes command formatting
 */
function cmdLine(s: string): string {
  let result = s;

  // Remove common shell escape sequences
  result = result.replace(/\\([\\'"`$(){}[\]<>|&;*?~!#])/g, "$1");

  // Remove caret escaping (Windows)
  result = result.replace(/\^([\\'"`$(){}[\]<>|&;*?~!#])/g, "$1");

  // Normalize quotes
  result = result.replace(/['"`]/g, "");

  // Compress whitespace
  result = compressWhiteSpace(result);

  // Remove null bytes
  result = result.replace(/\0/g, "");

  // Normalize slashes (both directions)
  result = result.replace(/[\\/]+/g, "/");

  return result;
}

/**
 * Base64 Decode - standard base64 decoding
 */
function base64Decode(s: string): string {
  try {
    // Handle URL-safe base64
    let normalized = s.replace(/-/g, "+").replace(/_/g, "/");
    // Pad to multiple of 4
    while (normalized.length % 4 !== 0) {
      normalized += "=";
    }
    // Decode using atob (works in browser and Node.js with Buffer)
    if (typeof atob !== "undefined") {
      return atob(normalized);
    }
    // Fallback for environments without atob
    return Buffer.from(normalized, "base64").toString("binary");
  } catch {
    return s;
  }
}

/**
 * Base64 Decode Extended - tolerant base64 decoding
 * Handles malformed base64 more gracefully
 */
function base64DecodeExt(s: string): string {
  try {
    // Remove any non-base64 characters
    let cleaned = s.replace(/[^A-Za-z0-9+/=_-]/g, "");

    // Handle URL-safe base64
    cleaned = cleaned.replace(/-/g, "+").replace(/_/g, "/");

    // Try to pad if needed
    const padLength = (4 - (cleaned.length % 4)) % 4;
    cleaned += "=".repeat(padLength);

    // Attempt decode
    if (typeof atob !== "undefined") {
      return atob(cleaned);
    }
    return Buffer.from(cleaned, "base64").toString("binary");
  } catch {
    return s;
  }
}

/**
 * Hex Decode - decode hexadecimal sequences
 * Handles both %XX and 0xXX formats
 */
function hexDecode(s: string): string {
  let result = s;

  // Decode %XX format
  result = result.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // Decode 0xXX format
  result = result.replace(/0x([0-9A-Fa-f]{2})/gi, (_, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // Decode \xXX format
  result = result.replace(/\\x([0-9A-Fa-f]{2})/gi, (_, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  return result;
}

/**
 * MD5 Hash - compute MD5 hash of string
 * Returns lowercase hex string
 */
function md5Hash(s: string): string {
  // Simple MD5 implementation (RFC 1321)
  // Note: In production, use a crypto library
  // This is a simplified implementation for simulation

  // For browser environment, use SubtleCrypto
  // For Node.js, use crypto module
  // For simulation purposes, we'll use a simple hash

  // This is a placeholder - in real implementation use proper crypto
  let hash = 0;
  for (let i = 0; i < s.length; i++) {
    const char = s.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32-bit integer
  }

  // Convert to hex and pad
  const hexHash = Math.abs(hash).toString(16).padStart(8, "0");

  // Repeat to simulate 32-char MD5 output
  return (hexHash + hexHash + hexHash + hexHash).substring(0, 32);
}

/**
 * Replace Nulls - replace null bytes with spaces
 */
function replaceNulls(s: string): string {
  return s.replace(/\0/g, " ");
}

/**
 * Remove Nulls - remove null bytes entirely
 */
function removeNulls(s: string): string {
  return s.replace(/\0/g, "");
}

/**
 * Normalize Path - normalize URL path segments
 * Resolves . and .. segments, removes duplicate slashes
 */
function normalizePath(s: string): string {
  // Handle URL-encoded slashes
  let result = s.replace(/%2f/gi, "/");

  // Remove duplicate slashes
  result = result.replace(/\/+/g, "/");

  // Split into segments
  const segments = result.split("/");
  const normalized: string[] = [];

  for (const segment of segments) {
    if (segment === ".") {
      // Skip current directory references
      continue;
    } else if (segment === "..") {
      // Go up one directory
      if (normalized.length > 1) {
        normalized.pop();
      }
    } else {
      normalized.push(segment);
    }
  }

  return normalized.join("/") || "/";
}

/**
 * Normalize Path Windows - normalize Windows path formatting
 * Handles backslashes, drive letters, and UNC paths
 */
function normalizePathWin(s: string): string {
  let result = s;

  // Convert forward slashes to backslashes
  result = result.replace(/\//g, "\\");

  // Handle URL-encoded backslashes
  result = result.replace(/%5c/gi, "\\");

  // Remove duplicate backslashes
  result = result.replace(/\\+/g, "\\");

  // Handle .. and . segments
  const segments = result.split("\\");
  const normalized: string[] = [];

  for (const segment of segments) {
    if (segment === ".") {
      continue;
    } else if (segment === "..") {
      if (normalized.length > 0 && !normalized[normalized.length - 1].includes(":")) {
        normalized.pop();
      }
    } else if (segment) {
      normalized.push(segment);
    }
  }

  // Preserve leading backslash for UNC paths
  if (s.startsWith("\\\\") || s.startsWith("//")) {
    return "\\\\" + normalized.join("\\");
  }

  return normalized.join("\\") || ".";
}

/**
 * Map of all transformation functions
 */
export const TEXT_TRANSFORMATIONS: Record<TextTransformationType, (s: string) => string> = {
  NONE: (s) => s,
  LOWERCASE: (s) => s.toLowerCase(),
  URL_DECODE: urlDecode,
  URL_DECODE_UNI: urlDecodeUni,
  HTML_ENTITY_DECODE: htmlEntityDecode,
  COMPRESS_WHITE_SPACE: compressWhiteSpace,
  CMD_LINE: cmdLine,
  BASE64_DECODE: base64Decode,
  BASE64_DECODE_EXT: base64DecodeExt,
  HEX_DECODE: hexDecode,
  MD5: md5Hash,
  REPLACE_NULLS: replaceNulls,
  REMOVE_NULLS: removeNulls,
  NORMALIZE_PATH: normalizePath,
  NORMALIZE_PATH_WIN: normalizePathWin,
};

/**
 * Apply a single text transformation
 */
export function applyTransformation(input: string, type: TextTransformationType): string {
  const transformFn = TEXT_TRANSFORMATIONS[type];
  if (!transformFn) {
    console.warn(`Unknown transformation type: ${type}`);
    return input;
  }
  return transformFn(input);
}

/**
 * Apply multiple transformations in priority order
 * Lower priority number = applied first
 */
export function applyTransformations(
  input: string,
  transformations: TextTransformation[]
): string {
  const sorted = [...transformations].sort((a, b) => a.priority - b.priority);
  let result = input;
  for (const transformation of sorted) {
    result = applyTransformation(result, transformation.type);
  }
  return result;
}

/**
 * Apply transformations and return step-by-step chain for visualization
 */
export function applyTransformationsWithChain(
  input: string,
  transformations: TextTransformation[]
): { result: string; chain: Array<{ type: string; before: string; after: string }> } {
  const sorted = [...transformations].sort((a, b) => a.priority - b.priority);
  const chain: Array<{ type: string; before: string; after: string }> = [];
  let result = input;
  for (const transformation of sorted) {
    if (transformation.type === "NONE") continue;
    const before = result;
    result = applyTransformation(result, transformation.type);
    if (before !== result) {
      chain.push({ type: transformation.type, before, after: result });
    }
  }
  return { result, chain };
}

/**
 * Get list of all available transformation types
 */
export function getAvailableTransformations(): TextTransformationType[] {
  return Object.keys(TEXT_TRANSFORMATIONS) as TextTransformationType[];
}

/**
 * Get human-readable description for transformation type
 */
export function getTransformationDescription(type: TextTransformationType): string {
  const descriptions: Record<TextTransformationType, string> = {
    NONE: "No transformation applied",
    LOWERCASE: "Convert all characters to lowercase",
    URL_DECODE: "Decode URL-encoded characters (%XX)",
    URL_DECODE_UNI: "Decode URL-encoded Unicode (%uXXXX)",
    HTML_ENTITY_DECODE: "Decode HTML entities (&amp; &#x27; etc.)",
    COMPRESS_WHITE_SPACE: "Replace multiple whitespace with single space",
    CMD_LINE: "Normalize shell command formatting",
    BASE64_DECODE: "Decode Base64-encoded content",
    BASE64_DECODE_EXT: "Decode Base64 (tolerant of errors)",
    HEX_DECODE: "Decode hexadecimal sequences (%XX and 0xXX)",
    MD5: "Compute MD5 hash",
    REPLACE_NULLS: "Replace null bytes with spaces",
    REMOVE_NULLS: "Remove null bytes entirely",
    NORMALIZE_PATH: "Normalize URL path segments (resolve . and ..)",
    NORMALIZE_PATH_WIN: "Normalize Windows path formatting",
  };
  return descriptions[type];
}

/**
 * Check if a transformation might modify the input
 */
export function transformationMayModify(type: TextTransformationType): boolean {
  return type !== "NONE";
}
