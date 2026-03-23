// WAFSim - XSS Detection Engine
// Heuristic detection matching AWS WAF cross-site scripting patterns

/**
 * Common XSS attack tags
 */
const XSS_TAGS = [
  "script", "iframe", "object", "embed", "applet", "meta", "link", "style",
  "base", "form", "input", "button", "textarea", "select", "svg", "math",
  "frame", "frameset", "layer", "ilayer", "bgsound", "title", "xml",
];

/**
 * Event handler attributes commonly used in XSS
 */
const EVENT_HANDLERS = [
  "onload", "onerror", "onclick", "onmouseover", "onmouseout", "onmouseenter",
  "onmouseleave", "onfocus", "onblur", "onchange", "onsubmit", "onreset",
  "onkeydown", "onkeyup", "onkeypress", "ondblclick", "oncontextmenu",
  "onwheel", "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover",
  "ondragstart", "ondrop", "onscroll", "oncopy", "oncut", "onpaste",
  "onbeforeunload", "onunload", "onresize", "oninput", "oninvalid",
  "onsearch", "ontouchstart", "ontouchmove", "ontouchend", "ontouchcancel",
  "onanimationstart", "onanimationend", "onanimationiteration",
  "ontransitionend", "onabort", "oncanplay", "oncanplaythrough",
  "ondurationchange", "onemptied", "onended", "onloadeddata",
  "onloadedmetadata", "onloadstart", "onpause", "onplay", "onplaying",
  "onprogress", "onratechange", "onseeked", "onseeking", "onstalled",
  "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting", "ontoggle",
  "onpointerdown", "onpointerup", "onpointermove", "onpointerenter",
  "onpointerleave", "onpointerover", "onpointerout", "onpointercancel",
  "ongotpointercapture", "onlostpointercapture", "onbeforeprint",
  "onafterprint", "onhashchange", "onmessage", "onoffline", "ononline",
  "onpagehide", "onpageshow", "onpopstate", "onstorage", "onshow",
];

/**
 * Dangerous URL schemes
 */
const DANGEROUS_SCHEMES = [
  "javascript:", "vbscript:", "data:text/html", "data:application",
  "data:text/javascript", "livescript:", "mocha:", "ecmascript:",
];

/**
 * XSS attack patterns
 */
const XSS_PATTERNS = [
  // Script tags
  /<script[^>]*>[\s\S]*?<\/script>/gi,
  /<script[^>]*>/gi,
  /<\/script>/gi,

  // Event handlers
  /\bon\w+\s*=/gi,
  new RegExp(`\\b(${EVENT_HANDLERS.join("|")})\\s*=`, "gi"),

  // JavaScript URL scheme
  /javascript\s*:/gi,
  /javascript\s*&#/gi,
  /javascript\s*&#/gi,

  // Data URL with script content
  /data\s*:\s*text\/html/gi,
  /data\s*:\s*application\/javascript/gi,
  /data\s*:\s*[a-z]+;base64/gi,

  // VBScript
  /vbscript\s*:/gi,

  // SVG/Math vectors
  /<svg[^>]*onload/gi,
  /<svg[^>]*>/gi,
  /<math[^>]*>/gi,

  // Object/Embed/IFrame
  /<iframe[^>]*>/gi,
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
  /<applet[^>]*>/gi,

  // Meta refresh
  /<meta[^>]*http-equiv[^>]*refresh/gi,
  /<meta[^>]*content[^>]*url/gi,

  // Style-based XSS
  /<style[^>]*>[\s\S]*?<\/style>/gi,
  /expression\s*\(/gi,
  /behavior\s*:/gi,
  /-moz-binding\s*:/gi,

  // Form injection
  /<form[^>]*>/gi,
  /<input[^>]*type\s*=\s*['"]?hidden/gi,

  // Base tag hijacking
  /<base[^>]*href/gi,

  // Link tag injection
  /<link[^>]*rel\s*=\s*['"]?import/gi,
  /<link[^>]*rel\s*=\s*['"]?stylesheet/gi,

  // Attribute injection
  /\s+src\s*=\s*['"]?javascript/gi,
  /\s+href\s*=\s*['"]?javascript/gi,
  /\s+action\s*=\s*['"]?javascript/gi,
  /\s+formaction\s*=\s*['"]?javascript/gi,
  /\s+poster\s*=\s*['"]?javascript/gi,
  /\s+data\s*=\s*['"]?javascript/gi,

  // HTML entity encoded
  /&#x?[0-9a-f]+;?/gi,
  /&#[0-9]+;?/gi,

  // Unicode escape
  /\\u[0-9a-f]{4}/gi,
  /\\x[0-9a-f]{2}/gi,

  // Template literals injection
  /`[^`]*\$\{/gi,

  // Document/domain manipulation
  /document\s*\.\s*(cookie|domain|write|writeln)/gi,
  /window\s*\.\s*(location|open|eval)/gi,
  /eval\s*\(/gi,
  /setTimeout\s*\(/gi,
  /setInterval\s*\(/gi,
  /Function\s*\(/gi,
  /new\s+Function\s*\(/gi,

  // DOM clobbering
  /<img[^>]*name\s*=/gi,
  /<a[^>]*name\s*=/gi,
  /<form[^>]*name\s*=/gi,

  // Mutation XSS patterns
  /<noscript[^>]*>[\s\S]*?<\/noscript>/gi,
  /<noembed[^>]*>[\s\S]*?<\/noembed>/gi,
  /<noframes[^>]*>[\s\S]*?<\/noframes>/gi,

  // XML-based
  /<!\[CDATA\[/gi,
  /<!ENTITY/gi,

  // Expression injection
  /\{\{[^}]*\}\}/g, // Template engines
  /<%[^%]*%>/g, // ERB-style
];

/**
 * High sensitivity patterns (more aggressive detection)
 */
const HIGH_SENSITIVITY_PATTERNS = [
  ...XSS_PATTERNS,

  // Additional aggressive patterns
  /<[a-z]+[^>]*>/gi, // Any HTML tag
  /%3c[^%]*%3e/gi, // URL encoded angle brackets
  /&lt;[^&]*&gt;/gi, // HTML encoded angle brackets
  /\\[ux][0-9a-f]+/gi, // Escaped unicode
  /\sstyle\s*=/gi, // Style attribute
  /\sclass\s*=/gi, // Class attribute (for CSS attacks)
  /@import/gi, // CSS import
  /url\s*\(/gi, // CSS url
];

/**
 * Low sensitivity patterns (only obvious attacks)
 */
const LOW_SENSITIVITY_PATTERNS = [
  // Most obvious XSS patterns only
  /<script[^>]*>/gi,
  /javascript\s*:/gi,
  /on(load|error|click|mouseover|focus|blur)\s*=/gi,
  /<iframe[^>]*>/gi,
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
  /data\s*:\s*text\/html/gi,
  /eval\s*\(/gi,
  /document\s*\.\s*write/gi,
  /expression\s*\(/gi,
];

/**
 * Evasion patterns to detect and normalize
 */
const EVASION_PATTERNS = [
  // Null byte injection
  /\0/g,
  // Tab/newline between characters
  /[\t\n\r]/g,
  // Case mixing
  // Mixed case already handled by case-insensitive regex
];

/**
 * Check if content matches XSS patterns
 * @param content - The content to check
 * @param sensitivity - Detection sensitivity level
 * @returns true if XSS detected
 */
export function detectXSS(
  content: string,
  sensitivity: "LOW" | "HIGH" = "HIGH"
): boolean {
  if (!content) return false;

  const patterns = sensitivity === "LOW"
    ? LOW_SENSITIVITY_PATTERNS
    : HIGH_SENSITIVITY_PATTERNS;

  // Check against patterns
  for (const pattern of patterns) {
    if (pattern.test(content)) {
      return true;
    }
  }

  // Check for dangerous schemes
  for (const scheme of DANGEROUS_SCHEMES) {
    if (content.toLowerCase().includes(scheme)) {
      return true;
    }
  }

  // Check for encoded dangerous schemes
  const decodedContent = decodeContent(content);
  for (const scheme of DANGEROUS_SCHEMES) {
    if (decodedContent.toLowerCase().includes(scheme)) {
      return true;
    }
  }

  return false;
}

/**
 * Decode various encodings in content
 */
function decodeContent(content: string): string {
  let decoded = content;

  // URL decode
  try {
    decoded = decodeURIComponent(decoded);
  } catch {
    // Keep original if decode fails
  }

  // HTML entity decode
  decoded = decoded
    .replace(/&#x([0-9A-Fa-f]+);?/gi, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    )
    .replace(/&#(\d+);?/g, (_, dec) =>
      String.fromCharCode(parseInt(dec, 10))
    )
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&amp;/gi, "&");

  // Unicode decode
  decoded = decoded.replace(/\\u([0-9A-Fa-f]{4})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );

  // Remove null bytes
  decoded = decoded.replace(/\0/g, "");

  return decoded;
}

/**
 * Get detailed match information for XSS
 * @param content - The content to analyze
 * @param sensitivity - Detection sensitivity level
 * @returns Object with match details
 */
export function getXSSMatch(
  content: string,
  sensitivity: "LOW" | "HIGH" = "HIGH"
): {
  detected: boolean;
  matchedPatterns: string[];
  matchedTags: string[];
  matchedEvents: string[];
  matchedSchemes: string[];
} {
  const result = {
    detected: false,
    matchedPatterns: [] as string[],
    matchedTags: [] as string[],
    matchedEvents: [] as string[],
    matchedSchemes: [] as string[],
  };

  if (!content) return result;

  const patterns = sensitivity === "LOW"
    ? LOW_SENSITIVITY_PATTERNS
    : HIGH_SENSITIVITY_PATTERNS;

  // Check patterns
  for (const pattern of patterns) {
    const matches = content.match(pattern);
    if (matches) {
      result.detected = true;
      result.matchedPatterns.push(...matches);
    }
  }

  // Check for XSS tags
  for (const tag of XSS_TAGS) {
    const tagRegex = new RegExp(`<${tag}[^>]*>`, "gi");
    if (tagRegex.test(content)) {
      result.matchedTags.push(tag);
    }
  }

  // Check for event handlers
  for (const event of EVENT_HANDLERS) {
    const eventRegex = new RegExp(`\\b${event}\\s*=`, "gi");
    if (eventRegex.test(content)) {
      result.matchedEvents.push(event);
    }
  }

  // Check for dangerous schemes
  const contentLower = content.toLowerCase();
  for (const scheme of DANGEROUS_SCHEMES) {
    if (contentLower.includes(scheme)) {
      result.matchedSchemes.push(scheme);
    }
  }

  // Also check decoded content
  const decodedContent = decodeContent(content);
  const decodedLower = decodedContent.toLowerCase();
  for (const scheme of DANGEROUS_SCHEMES) {
    if (decodedLower.includes(scheme) && !result.matchedSchemes.includes(scheme)) {
      result.matchedSchemes.push(scheme + " (encoded)");
    }
  }

  // Remove duplicates
  result.matchedPatterns = [...new Set(result.matchedPatterns)];
  result.matchedTags = [...new Set(result.matchedTags)];
  result.matchedEvents = [...new Set(result.matchedEvents)];
  result.matchedSchemes = [...new Set(result.matchedSchemes)];

  // Set detected if we have any matches
  if (
    result.matchedPatterns.length > 0 ||
    result.matchedTags.length > 0 ||
    result.matchedEvents.length > 0 ||
    result.matchedSchemes.length > 0
  ) {
    result.detected = true;
  }

  return result;
}

/**
 * Normalize content for XSS detection
 * Handles common evasion techniques
 */
export function normalizeForXSSDetection(content: string): string {
  let normalized = content;

  // URL decode multiple times (handles double encoding)
  for (let i = 0; i < 3; i++) {
    try {
      const decoded = decodeURIComponent(normalized);
      if (decoded === normalized) break;
      normalized = decoded;
    } catch {
      break;
    }
  }

  // HTML entity decode
  normalized = decodeContent(normalized);

  // Remove null bytes
  normalized = normalized.replace(/\0/g, "");

  // Normalize whitespace
  normalized = normalized.replace(/[\t\n\r]+/g, " ");

  // Remove HTML comments
  normalized = normalized.replace(/<!--[\s\S]*?-->/g, "");

  // Remove CDATA
  normalized = normalized.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");

  return normalized;
}

/**
 * Check if a request looks like it might contain XSS
 */
export function checkRequestForXSS(
  body: string,
  uri: string,
  headers: Array<{ name: string; value: string }>,
  sensitivity: "LOW" | "HIGH" = "HIGH"
): {
  detected: boolean;
  locations: string[];
  details: ReturnType<typeof getXSSMatch>;
} {
  const locations: string[] = [];
  let allMatches: ReturnType<typeof getXSSMatch> = {
    detected: false,
    matchedPatterns: [],
    matchedTags: [],
    matchedEvents: [],
    matchedSchemes: [],
  };

  // Check body
  if (body) {
    const bodyMatches = getXSSMatch(body, sensitivity);
    if (bodyMatches.detected) {
      locations.push("BODY");
      allMatches = mergeXSSMatchResults(allMatches, bodyMatches);
    }
  }

  // Check URI
  if (uri) {
    const uriMatches = getXSSMatch(uri, sensitivity);
    if (uriMatches.detected) {
      locations.push("URI");
      allMatches = mergeXSSMatchResults(allMatches, uriMatches);
    }
  }

  // Check query parameters in URI
  const queryIndex = uri.indexOf("?");
  if (queryIndex >= 0) {
    const queryString = uri.substring(queryIndex + 1);
    try {
      const params = new URLSearchParams(queryString);
      params.forEach((value, key) => {
        const paramMatches = getXSSMatch(value, sensitivity);
        if (paramMatches.detected) {
          locations.push(`QUERY:${key}`);
          allMatches = mergeXSSMatchResults(allMatches, paramMatches);
        }
      });
    } catch {
      // Ignore parse errors
    }
  }

  // Check headers
  for (const header of headers) {
    const headerMatches = getXSSMatch(
      `${header.name}: ${header.value}`,
      sensitivity
    );
    if (headerMatches.detected) {
      locations.push(`HEADER:${header.name}`);
      allMatches = mergeXSSMatchResults(allMatches, headerMatches);
    }
  }

  return {
    detected: locations.length > 0,
    locations,
    details: allMatches,
  };
}

/**
 * Merge two XSS match result objects
 */
function mergeXSSMatchResults(
  a: ReturnType<typeof getXSSMatch>,
  b: ReturnType<typeof getXSSMatch>
): ReturnType<typeof getXSSMatch> {
  return {
    detected: a.detected || b.detected,
    matchedPatterns: [...new Set([...a.matchedPatterns, ...b.matchedPatterns])],
    matchedTags: [...new Set([...a.matchedTags, ...b.matchedTags])],
    matchedEvents: [...new Set([...a.matchedEvents, ...b.matchedEvents])],
    matchedSchemes: [...new Set([...a.matchedSchemes, ...b.matchedSchemes])],
  };
}

/**
 * Get severity level of XSS match
 */
export function getXSSSeverity(
  details: ReturnType<typeof getXSSMatch>
): "HIGH" | "MEDIUM" | "LOW" {
  // High severity: script tags, javascript: scheme, event handlers with code
  if (
    details.matchedTags.includes("script") ||
    details.matchedSchemes.some((s) => s.includes("javascript"))
  ) {
    return "HIGH";
  }

  // Medium severity: other dangerous tags, event handlers
  if (
    details.matchedTags.length > 0 ||
    details.matchedEvents.length > 0 ||
    details.matchedSchemes.some((s) => s.includes("data:"))
  ) {
    return "MEDIUM";
  }

  // Low severity: potential indicators
  return "LOW";
}
