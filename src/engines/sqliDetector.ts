// WAFSim - SQL Injection Detection Engine
// Heuristic detection matching AWS WAF SQL injection patterns

/**
 * SQL keywords that are commonly used in injection attacks
 */
const SQL_KEYWORDS = [
  "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE",
  "UNION", "JOIN", "WHERE", "FROM", "INTO", "VALUES", "SET", "AND", "OR", "NOT",
  "NULL", "LIKE", "BETWEEN", "IN", "EXISTS", "CASE", "WHEN", "THEN", "ELSE", "END",
  "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET", "TOP", "DISTINCT",
  "EXEC", "EXECUTE", "EXECSP", "SP_EXECUTESQL", "XP_CMDSHELL",
  "INFORMATION_SCHEMA", "SYSOBJECTS", "SYSCOLUMNS", "SYS.TABLES", "SYS.COLUMNS",
  "CONCAT", "CHAR", "NCHAR", "VARCHAR", "NVARCHAR", "CONVERT", "CAST",
  "BENCHMARK", "SLEEP", "WAITFOR", "DELAY", "PG_SLEEP",
];

/**
 * SQL comment patterns
 */
const SQL_COMMENTS = [
  "--",      // Standard SQL comment
  "/*",      // Block comment start
  "*/",      // Block comment end
  "#",       // MySQL comment
  ";--",     // Statement terminator + comment
  "%00",     // Null byte
];

/**
 * SQL injection patterns - common attack signatures
 */
const SQL_INJECTION_PATTERNS = [
  // Boolean-based injection patterns
  /['"]\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  /['"]\s*(OR|AND)\s+['"]?[a-z]+['"]?\s*=\s*['"]?[a-z]+/i,
  /['"]\s*(OR|AND)\s+\d+\s*=\s*\d+/i,
  /\d+\s*=\s*\d+\s*--/i,
  /['"]\s*OR\s+1\s*=\s*1/i,
  /['"]\s*OR\s+'1'\s*=\s*'1/i,
  /['"]\s*OR\s+'[^']*'\s*=\s*'[^']*'/i,
  /['"]\s*OR\s+true\s*--/i,
  /['"]\s*OR\s+'a'\s*=\s*'a/i,

  // UNION-based injection
  /UNION\s+(ALL\s+)?SELECT/i,
  /UNION\s+\/\*.*?\*\/\s*SELECT/i,
  /UNION\s+%[0-9A-Fa-f]{2}SELECT/i,

  // Time-based injection
  /SLEEP\s*\(\s*\d+\s*\)/i,
  /BENCHMARK\s*\(\s*\d+/i,
  /WAITFOR\s+DELAY\s+['"][^'"]+['"]/i,
  /PG_SLEEP\s*\(\s*\d+\s*\)/i,

  // Stacked queries
  /;\s*SELECT\s+/i,
  /;\s*INSERT\s+/i,
  /;\s*UPDATE\s+/i,
  /;\s*DELETE\s+/i,
  /;\s*DROP\s+/i,
  /;\s*EXEC(UTE)?\s+/i,
  /;\s*XP_/i,

  // Error-based injection
  /CONVERT\s*\(\s*INT/i,
  /CAST\s*\(\s*.*\s+AS\s+INT/i,
  /EXTRACTVALUE\s*\(/i,
  /UPDATEXML\s*\(/i,
  /XMLTYPE\s*\(/i,

  // Command execution
  /XP_CMDSHELL/i,
  /SP_OACREATE/i,
  /SP_OAMETHOD/i,
  /SP_EXECUTESQL/i,

  // Data exfiltration
  /INTO\s+OUTFILE/i,
  /INTO\s+DUMPFILE/i,
  /LOAD_FILE\s*\(/i,
  /INFORMATION_SCHEMA\./i,
  /SYSOBJECTS/i,
  /SYS\.TABLES/i,
  /SYS\.COLUMNS/i,

  // String concatenation tricks
  /CHAR\s*\(\s*\d+\s*\)/i,
  /CONCAT\s*\(\s*['"]/i,
  /['"]\s*\|\|\s*['"]/i,
  /['"]\s*\+\s*['"]/i,

  // Comment-based evasion
  /['"]\s*--/,
  /['"]\s*#/,
  /['"]\s*\/\*/,
  /\*\/\s*['"]/,
  /['"]\s*%00/,

  // Hex encoding
  /0x[0-9A-Fa-f]+\s*\|\|/i,
  /UNHEX\s*\(/i,
  /HEX\s*\(/i,

  // Quote escaping attempts
  /\\\'/,
  /''/,
  /\\\\/,

  // Tautologies
  /'[^']*'\s*=\s*'[^']*'/,
  /1\s*=\s*1\s*--/,
  /1\s*OR\s+1\s*=\s*1/,
  /'\s*OR\s+'\w+'\s*=\s*'\w+'/,

  // Numeric injection
  /-?\d+\s*(OR|AND)\s+-?\d+\s*=\s*-?\d+/i,
  /-?\d+\s+UNION/i,

  // Procedure injection
  /EXEC\s+\(/i,
  /EXECUTE\s+\(/i,
  /sp_/i,

  // Privilege escalation
  /GRANT\s+/i,
  /REVOKE\s+/i,
  /PRIVILEGES/i,
];

/**
 * Patterns that are stronger indicators of SQL injection (high sensitivity)
 */
const HIGH_SENSITIVITY_PATTERNS = [
  ...SQL_INJECTION_PATTERNS,
  // Additional aggressive patterns for high sensitivity
  /['"]\s*(\|\||\+|OR|AND)/i,
  /(\|\||\+|OR|AND)\s*['"]/i,
  /['"]\s*;\s*['"]/i,
  /'\s*--/,
  /"\s*--/,
  /'\s*#/,
  /--\s*$/m,
  /;\s*$/,
  /ORDER\s+BY\s+\d+--/i,
  /GROUP\s+BY\s+\d+--/i,
];

/**
 * Patterns for low sensitivity (only obvious attacks)
 */
const LOW_SENSITIVITY_PATTERNS = [
  // Most obvious SQL injection patterns only
  /UNION\s+(ALL\s+)?SELECT/i,
  /OR\s+1\s*=\s*1/i,
  /OR\s+'1'\s*=\s*'1/i,
  /;\s*DROP\s+/i,
  /;\s*DELETE\s+/i,
  /XP_CMDSHELL/i,
  /SLEEP\s*\(\s*\d+\s*\)/i,
  /WAITFOR\s+DELAY/i,
  /BENCHMARK\s*\(/i,
  /INFORMATION_SCHEMA/i,
  /INTO\s+OUTFILE/i,
];

/**
 * Context markers that indicate SQL might be expected (not injection)
 */
const SAFE_CONTEXTS = [
  /content-type:\s*application\/json/i,
  /content-type:\s*text\/plain/i,
];

/**
 * Check if content matches SQL injection patterns
 * @param content - The content to check
 * @param sensitivity - Detection sensitivity level
 * @returns true if SQL injection detected
 */
export function detectSQLInjection(
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

  // Check for SQL keywords with suspicious context
  if (sensitivity === "HIGH" && hasSuspiciousSQLContext(content)) {
    return true;
  }

  return false;
}

/**
 * Check for SQL keywords in suspicious context
 */
function hasSuspiciousSQLContext(content: string): boolean {
  const upperContent = content.toUpperCase();

  // Check for quote followed by SQL keyword
  for (const keyword of SQL_KEYWORDS) {
    // Pattern: 'KEYWORD or "KEYWORD
    const quotePattern = new RegExp(`['"]\\s*${keyword}\\b`, "i");
    if (quotePattern.test(content)) {
      return true;
    }

    // Pattern: KEYWORD followed by quote and content
    const trailingPattern = new RegExp(`\\b${keyword}\\s+['"]`, "i");
    if (trailingPattern.test(content)) {
      // Check if it looks like injection
      if (/[='"]/i.test(content)) {
        return true;
      }
    }
  }

  // Check for multiple SQL keywords in sequence
  const keywordCount = SQL_KEYWORDS.filter((kw) =>
    new RegExp(`\\b${kw}\\b`, "i").test(upperContent)
  ).length;

  // Many SQL keywords + quotes = suspicious
  if (keywordCount >= 3 && /['"]/.test(content)) {
    return true;
  }

  // Check for comment + keyword combination
  for (const comment of SQL_COMMENTS) {
    if (content.includes(comment)) {
      for (const keyword of SQL_KEYWORDS.slice(0, 15)) { // Check common keywords
        if (new RegExp(`\\b${keyword}\\b`, "i").test(upperContent)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Get detailed match information for SQL injection
 * @param content - The content to analyze
 * @param sensitivity - Detection sensitivity level
 * @returns Object with match details
 */
export function getSQLInjectionMatch(
  content: string,
  sensitivity: "LOW" | "HIGH" = "HIGH"
): {
  detected: boolean;
  matchedPatterns: string[];
  matchedKeywords: string[];
  matchedComments: string[];
} {
  const result = {
    detected: false,
    matchedPatterns: [] as string[],
    matchedKeywords: [] as string[],
    matchedComments: [] as string[],
  };

  if (!content) return result;

  const patterns = sensitivity === "LOW"
    ? LOW_SENSITIVITY_PATTERNS
    : HIGH_SENSITIVITY_PATTERNS;

  // Check patterns
  for (const pattern of patterns) {
    const match = content.match(pattern);
    if (match) {
      result.detected = true;
      result.matchedPatterns.push(match[0]);
    }
  }

  // Check keywords
  for (const keyword of SQL_KEYWORDS) {
    const regex = new RegExp(`\\b${keyword}\\b`, "gi");
    const matches = content.match(regex);
    if (matches) {
      result.matchedKeywords.push(...matches.map((m) => m.toUpperCase()));
    }
  }

  // Remove duplicates
  result.matchedKeywords = [...new Set(result.matchedKeywords)];

  // Check comments
  for (const comment of SQL_COMMENTS) {
    if (content.includes(comment)) {
      result.matchedComments.push(comment);
    }
  }

  // Set detected if we have matches
  if (result.matchedPatterns.length > 0) {
    result.detected = true;
  }

  return result;
}

/**
 * Normalize content for SQL injection detection
 * Handles common evasion techniques
 */
export function normalizeForSQLDetection(content: string): string {
  let normalized = content;

  // URL decode
  try {
    normalized = decodeURIComponent(normalized);
  } catch {
    // Keep original if decode fails
  }

  // Remove null bytes
  normalized = normalized.replace(/\0/g, "");

  // Normalize whitespace
  normalized = normalized.replace(/[\s\xa0]+/g, " ");

  // Handle hex encoding
  normalized = normalized.replace(/0x([0-9A-Fa-f]{2})/gi, (_, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // Handle char() functions
  normalized = normalized.replace(/CHAR\s*\(\s*(\d+)\s*\)/gi, (_, code) => {
    return String.fromCharCode(parseInt(code, 10));
  });

  // Remove inline comments that could be evasion
  normalized = normalized.replace(/\/\*[^*]*\*\//g, "");

  return normalized;
}

/**
 * Check if a request body looks like it might contain SQL injection
 */
export function checkRequestForSQL(
  body: string,
  uri: string,
  headers: Array<{ name: string; value: string }>,
  sensitivity: "LOW" | "HIGH" = "HIGH"
): {
  detected: boolean;
  locations: string[];
  details: ReturnType<typeof getSQLInjectionMatch>;
} {
  const locations: string[] = [];
  let allMatches: ReturnType<typeof getSQLInjectionMatch> = {
    detected: false,
    matchedPatterns: [],
    matchedKeywords: [],
    matchedComments: [],
  };

  // Check body
  if (body) {
    const bodyMatches = getSQLInjectionMatch(body, sensitivity);
    if (bodyMatches.detected) {
      locations.push("BODY");
      allMatches = mergeMatchResults(allMatches, bodyMatches);
    }
  }

  // Check URI
  if (uri) {
    const uriMatches = getSQLInjectionMatch(uri, sensitivity);
    if (uriMatches.detected) {
      locations.push("URI");
      allMatches = mergeMatchResults(allMatches, uriMatches);
    }
  }

  // Check headers
  for (const header of headers) {
    const headerMatches = getSQLInjectionMatch(
      `${header.name}: ${header.value}`,
      sensitivity
    );
    if (headerMatches.detected) {
      locations.push(`HEADER:${header.name}`);
      allMatches = mergeMatchResults(allMatches, headerMatches);
    }
  }

  return {
    detected: locations.length > 0,
    locations,
    details: allMatches,
  };
}

/**
 * Merge two match result objects
 */
function mergeMatchResults(
  a: ReturnType<typeof getSQLInjectionMatch>,
  b: ReturnType<typeof getSQLInjectionMatch>
): ReturnType<typeof getSQLInjectionMatch> {
  return {
    detected: a.detected || b.detected,
    matchedPatterns: [...new Set([...a.matchedPatterns, ...b.matchedPatterns])],
    matchedKeywords: [...new Set([...a.matchedKeywords, ...b.matchedKeywords])],
    matchedComments: [...new Set([...a.matchedComments, ...b.matchedComments])],
  };
}
