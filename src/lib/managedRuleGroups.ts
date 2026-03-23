// WAFSim - AWS Managed Rule Groups Static Data
// Comprehensive data for all documented AWS Managed Rule Groups

import { ManagedRuleGroup } from "@/lib/types";

/**
 * AWS Managed Rule Groups
 * Based on AWS WAF documentation:
 * https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
 */
export const MANAGED_RULE_GROUPS: Record<string, ManagedRuleGroup> = {
  // =============================================================================
  // Core Rule Set
  // =============================================================================
  AWSManagedRulesCommonRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesCommonRuleSet",
    description:
      "Core rule set that provides protection against exploitation of a wide range of vulnerabilities, including those described in OWASP Top 10. This rule set is a good starting point for most websites.",
    wcu: 700,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:core-rule-set:",
    rules: [
      {
        name: "NoUserAgent_HEADER",
        description: "Checks for the absence of User-Agent header, which can indicate automated tools",
        defaultAction: "Block",
        addedLabels: ["NoUserAgent_HEADER"],
        simulationCriteria: {
          type: "header_absent",
          field: "User-Agent",
        },
      },
      {
        name: "UserAgent_BadBots_HEADER",
        description: "Checks for known malicious bot user agents",
        defaultAction: "Block",
        addedLabels: ["UserAgent_BadBots_HEADER"],
        simulationCriteria: {
          type: "header_match",
          field: "User-Agent",
          patterns: ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirbuster", "wpscan", "burp", "owasp"],
        },
      },
      {
        name: "SizeRestrictions_QUERYSTRING",
        description: "Checks for query strings larger than 2048 characters",
        defaultAction: "Block",
        addedLabels: ["SizeRestrictions_QUERYSTRING"],
        simulationCriteria: {
          type: "size_check",
          field: "query",
          operator: "exceeds",
          value: 2048,
        },
      },
      {
        name: "SizeRestrictions_BODY",
        description: "Checks for request bodies larger than 8192 bytes",
        defaultAction: "Block",
        addedLabels: ["SizeRestrictions_BODY"],
        simulationCriteria: {
          type: "size_check",
          field: "body",
          operator: "exceeds",
          value: 8192,
        },
      },
      {
        name: "SizeRestrictions_URIPATH",
        description: "Checks for URI paths longer than 512 characters",
        defaultAction: "Block",
        addedLabels: ["SizeRestrictions_URIPATH"],
        simulationCriteria: {
          type: "size_check",
          field: "uri",
          operator: "exceeds",
          value: 512,
        },
      },
      {
        name: "CrossSiteScripting_QUERYSTRING",
        description: "Detects XSS patterns in query string",
        defaultAction: "Block",
        addedLabels: ["CrossSiteScripting_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "<script|javascript:|onerror|onload",
        },
      },
      {
        name: "CrossSiteScripting_BODY",
        description: "Detects XSS patterns in request body",
        defaultAction: "Block",
        addedLabels: ["CrossSiteScripting_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "<script|javascript:|onerror|onload",
        },
      },
      {
        name: "CrossSiteScripting_COOKIE",
        description: "Detects XSS patterns in cookies",
        defaultAction: "Block",
        addedLabels: ["CrossSiteScripting_COOKIE"],
        simulationCriteria: {
          type: "header_match",
          field: "Cookie",
          pattern: "<script|javascript:|onerror",
        },
      },
      {
        name: "GenericLFI_QUERYSTRING",
        description: "Detects Local File Inclusion attempts in query string",
        defaultAction: "Block",
        addedLabels: ["GenericLFI_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "../|..\\|/etc/passwd|/proc/self",
        },
      },
      {
        name: "GenericLFI_BODY",
        description: "Detects Local File Inclusion attempts in body",
        defaultAction: "Block",
        addedLabels: ["GenericLFI_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "../|..\\|/etc/passwd|/proc/self",
        },
      },
      {
        name: "GenericRFI_QUERYSTRING",
        description: "Detects Remote File Inclusion attempts in query string",
        defaultAction: "Block",
        addedLabels: ["GenericRFI_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "php://|data://|expect://|http://|https://|ftp://",
        },
      },
      {
        name: "GenericRFI_BODY",
        description: "Detects Remote File Inclusion attempts in body",
        defaultAction: "Block",
        addedLabels: ["GenericRFI_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "php://|data://|expect://",
        },
      },
      {
        name: "GenericRFI_COOKIE",
        description: "Detects Remote File Inclusion attempts in cookies",
        defaultAction: "Block",
        addedLabels: ["GenericRFI_COOKIE"],
        simulationCriteria: {
          type: "header_match",
          field: "Cookie",
          pattern: "php://|data://",
        },
      },
      {
        name: "RestrictedExtensions_QUERYSTRING",
        description: "Blocks requests for restricted file extensions",
        defaultAction: "Block",
        addedLabels: ["RestrictedExtensions_QUERYSTRING"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "\\.(bak|config|sql|ini|log|sh|bash|exe|dll|bat)$",
        },
      },
      {
        name: "RestrictedExtensions_BODY",
        description: "Blocks POST requests containing restricted file extensions",
        defaultAction: "Block",
        addedLabels: ["RestrictedExtensions_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "\\.(bak|config|sql|ini|log|sh|bash|exe|dll|bat)",
        },
      },
      {
        name: "CrossSiteScripting_URIPATH",
        description: "Detects XSS patterns in URI path",
        defaultAction: "Block",
        addedLabels: ["CrossSiteScripting_URIPATH"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "<script|javascript:|onerror|onload",
        },
      },
      {
        name: "GenericLFI_URIPATH",
        description: "Detects Local File Inclusion in URI path",
        defaultAction: "Block",
        addedLabels: ["GenericLFI_URIPATH"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "\\.\\./|\\.\\.\\\\|/etc/|/proc/",
        },
      },
    ],
  },

  // =============================================================================
  // Known Bad Inputs Rule Set
  // =============================================================================
  AWSManagedRulesKnownBadInputsRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesKnownBadInputsRuleSet",
    description:
      "Rules to block request patterns that are known to be invalid and are associated with exploitation or discovery of vulnerabilities. This can help reduce false positives and false negatives.",
    wcu: 200,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:known-bad-inputs:",
    rules: [
      {
        name: "Log4JRCE",
        description: "Detects Log4Shell (CVE-2021-44228) exploitation attempts",
        defaultAction: "Block",
        addedLabels: ["Log4JRCE"],
        simulationCriteria: {
          type: "custom",
          operator: "contains",
          value: "${jndi:",
        },
      },
      {
        name: "Log4JRCE_URIPATH",
        description: "Detects Log4Shell in URI path",
        defaultAction: "Block",
        addedLabels: ["Log4JRCE_URIPATH"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "${jndi:|jndi:ldap|jndi:dns|jndi:rmi",
        },
      },
      {
        name: "Log4JRCE_QUERYSTRING",
        description: "Detects Log4Shell in query string",
        defaultAction: "Block",
        addedLabels: ["Log4JRCE_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "${jndi:|jndi:ldap|jndi:dns|jndi:rmi",
        },
      },
      {
        name: "Log4JRCE_HEADER",
        description: "Detects Log4Shell in headers",
        defaultAction: "Block",
        addedLabels: ["Log4JRCE_HEADER"],
        simulationCriteria: {
          type: "header_match",
          field: "any",
          pattern: "${jndi:|jndi:ldap|jndi:dns|jndi:rmi",
        },
      },
      {
        name: "Log4JRCE_BODY",
        description: "Detects Log4Shell in request body",
        defaultAction: "Block",
        addedLabels: ["Log4JRCE_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "${jndi:|jndi:ldap|jndi:dns|jndi:rmi",
        },
      },
      {
        name: "PROPFIND_METHOD",
        description: "Blocks PROPFIND method often used in WebDAV exploits",
        defaultAction: "Block",
        addedLabels: ["PROPFIND_METHOD"],
        simulationCriteria: {
          type: "method_check",
          value: "PROPFIND",
        },
      },
      {
        name: "ExploitablePaths_URIPATH",
        description: "Detects requests to known vulnerable paths",
        defaultAction: "Block",
        addedLabels: ["ExploitablePaths_URIPATH"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "/wp-admin/setup-config|/phpmyadmin|/manager/html|/solr/admin",
        },
      },
    ],
  },

  // =============================================================================
  // SQLi Rule Set
  // =============================================================================
  AWSManagedRulesSQLiRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesSQLiRuleSet",
    description:
      "Rules to block SQL injection attacks. Use this rule group if you want to protect against SQL injection attacks. The rules in this group inspect multiple parts of the request for SQL injection patterns.",
    wcu: 200,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:sql-rule-set:",
    rules: [
      {
        name: "SQLi_QUERYSTRING",
        description: "Detects SQL injection in query string",
        defaultAction: "Block",
        addedLabels: ["SQLi_QUERYSTRING"],
        sensitivityLevel: "HIGH",
        simulationCriteria: {
          type: "query_pattern",
          pattern: "UNION|SELECT|OR 1=1|OR '1'='1|DROP TABLE|'--|\"--",
        },
      },
      {
        name: "SQLi_BODY",
        description: "Detects SQL injection in request body",
        defaultAction: "Block",
        addedLabels: ["SQLi_BODY"],
        sensitivityLevel: "HIGH",
        simulationCriteria: {
          type: "body_pattern",
          pattern: "UNION|SELECT|OR 1=1|OR '1'='1|DROP TABLE|'--",
        },
      },
      {
        name: "SQLi_COOKIE",
        description: "Detects SQL injection in cookies",
        defaultAction: "Block",
        addedLabels: ["SQLi_COOKIE"],
        sensitivityLevel: "HIGH",
        simulationCriteria: {
          type: "header_match",
          field: "Cookie",
          pattern: "UNION|SELECT|OR 1=1",
        },
      },
      {
        name: "SQLi_URIPATH",
        description: "Detects SQL injection in URI path",
        defaultAction: "Block",
        addedLabels: ["SQLi_URIPATH"],
        sensitivityLevel: "HIGH",
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "UNION|SELECT|OR 1=1",
        },
      },
      {
        name: "SQLi_HEADER",
        description: "Detects SQL injection in request headers",
        defaultAction: "Block",
        addedLabels: ["SQLi_HEADER"],
        sensitivityLevel: "HIGH",
        simulationCriteria: {
          type: "header_match",
          field: "any",
          pattern: "UNION|SELECT|OR 1=1|'--",
        },
      },
    ],
  },

  // =============================================================================
  // Linux Rule Set
  // =============================================================================
  AWSManagedRulesLinuxRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesLinuxRuleSet",
    description:
      "Rules to block exploitation of vulnerabilities that are specific to Linux operating systems. Use this rule group if your application is running on Linux.",
    wcu: 200,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:linux-rule-set:",
    rules: [
      {
        name: "LFI_URIPATH",
        description: "Detects Linux Local File Inclusion in URI",
        defaultAction: "Block",
        addedLabels: ["LFI_URIPATH"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "/etc/passwd|/etc/shadow|/proc/self|/var/log",
        },
      },
      {
        name: "LFI_QUERYSTRING",
        description: "Detects Linux LFI in query string",
        defaultAction: "Block",
        addedLabels: ["LFI_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "/etc/passwd|/etc/shadow|/proc/self",
        },
      },
      {
        name: "LFI_BODY",
        description: "Detects Linux LFI in body",
        defaultAction: "Block",
        addedLabels: ["LFI_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "/etc/passwd|/etc/shadow|/proc/self",
        },
      },
      {
        name: "CommandInjection_QUERYSTRING",
        description: "Detects Linux command injection in query string",
        defaultAction: "Block",
        addedLabels: ["CommandInjection_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: ";\\s*cat|;\\s*ls|;\\s*wget|;\\s*curl|`cat|`ls|\\$\\(",
        },
      },
      {
        name: "CommandInjection_BODY",
        description: "Detects Linux command injection in body",
        defaultAction: "Block",
        addedLabels: ["CommandInjection_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: ";\\s*cat|;\\s*ls|;\\s*wget|`cat|`ls",
        },
      },
    ],
  },

  // =============================================================================
  // Unix Rule Set
  // =============================================================================
  AWSManagedRulesUnixRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesUnixRuleSet",
    description:
      "Rules to block exploitation of vulnerabilities that are specific to Unix operating systems.",
    wcu: 100,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:unix-rule-set:",
    rules: [
      {
        name: "UnixShell_QUERYSTRING",
        description: "Detects Unix shell metacharacters in query string",
        defaultAction: "Block",
        addedLabels: ["UnixShell_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: ";|\\||`|\\$\\(|&&|\\|\\|",
        },
      },
      {
        name: "UnixShell_BODY",
        description: "Detects Unix shell metacharacters in body",
        defaultAction: "Block",
        addedLabels: ["UnixShell_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: ";|\\||`|\\$\\(|&&|\\|\\|",
        },
      },
    ],
  },

  // =============================================================================
  // Windows Rule Set
  // =============================================================================
  AWSManagedRulesWindowsRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesWindowsRuleSet",
    description:
      "Rules to block exploitation of vulnerabilities that are specific to Windows operating systems. Use this rule group if your application is running on Windows.",
    wcu: 200,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:windows-rule-set:",
    rules: [
      {
        name: "WindowsPathTraversal_URIPATH",
        description: "Detects Windows path traversal in URI",
        defaultAction: "Block",
        addedLabels: ["WindowsPathTraversal_URIPATH"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "\\.\\.\\\\|C:\\\\|\\\\Windows\\\\|\\\\System32",
        },
      },
      {
        name: "WindowsCommandInjection_QUERYSTRING",
        description: "Detects Windows command injection in query string",
        defaultAction: "Block",
        addedLabels: ["WindowsCommandInjection_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "cmd\\.exe|powershell|net\\.exe|whoami|dir\\s|type\\s",
        },
      },
      {
        name: "WindowsCommandInjection_BODY",
        description: "Detects Windows command injection in body",
        defaultAction: "Block",
        addedLabels: ["WindowsCommandInjection_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "cmd\\.exe|powershell|net\\.exe|whoami",
        },
      },
    ],
  },

  // =============================================================================
  // PHP Rule Set
  // =============================================================================
  AWSManagedRulesPHPRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesPHPRuleSet",
    description:
      "Rules to block exploitation of vulnerabilities that are specific to PHP applications. Use this rule group if your application is running on PHP.",
    wcu: 100,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:php-rule-set:",
    rules: [
      {
        name: "PHPHighRiskVars_QUERYSTRING",
        description: "Detects PHP high-risk variables in query string",
        defaultAction: "Block",
        addedLabels: ["PHPHighRiskVars_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "_SERVER\\[|_ENV\\[|auto_prepend_file|auto_append_file",
        },
      },
      {
        name: "PHPInjection_QUERYSTRING",
        description: "Detects PHP code injection in query string",
        defaultAction: "Block",
        addedLabels: ["PHPInjection_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "php://|expect://|zip://|phar://",
        },
      },
      {
        name: "PHPInjection_BODY",
        description: "Detects PHP code injection in body",
        defaultAction: "Block",
        addedLabels: ["PHPInjection_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "php://|expect://|zip://|phar://",
        },
      },
    ],
  },

  // =============================================================================
  // WordPress Rule Set
  // =============================================================================
  AWSManagedRulesWordPressRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesWordPressRuleSet",
    description:
      "Rules to block exploitation of vulnerabilities that are specific to WordPress. Use this rule group if your application is running on WordPress.",
    wcu: 100,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:wordpress-rule-set:",
    rules: [
      {
        name: "WordPressExploitableCommands_QUERYSTRING",
        description: "Detects WordPress exploitable commands",
        defaultAction: "Block",
        addedLabels: ["WordPressExploitableCommands_QUERYSTRING"],
        simulationCriteria: {
          type: "query_pattern",
          pattern: "wp-config\\.php|xmlrpc\\.php|wp-login\\.php\\?action=register",
        },
      },
      {
        name: "WordPressExploitablePaths_URIPATH",
        description: "Detects requests to WordPress exploitable paths",
        defaultAction: "Block",
        addedLabels: ["WordPressExploitablePaths_URIPATH"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "/wp-admin/setup-config|/wp-admin/install|/wp-content/debug\\.log",
        },
      },
      {
        name: "WordPressAdminProtection",
        description: "Protects WordPress admin area",
        defaultAction: "Count",
        addedLabels: ["WordPressAdminProtection"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "/wp-admin/|/wp-login\\.php",
        },
      },
    ],
  },

  // =============================================================================
  // Admin Protection Rule Set
  // =============================================================================
  AWSManagedRulesAdminProtectionRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesAdminProtectionRuleSet",
    description:
      "Rules that allow you to block external access to exposed admin pages. This can be useful if you run admin applications that you don't want to be accessible from the internet.",
    wcu: 100,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:admin-protection-rule-set:",
    rules: [
      {
        name: "AdminProtection_URIPATH",
        description: "Detects requests to admin pages",
        defaultAction: "Block",
        addedLabels: ["AdminProtection_URIPATH"],
        simulationCriteria: {
          type: "uri_pattern",
          pattern: "/admin|/administrator|/wp-admin|/phpmyadmin|/manager/html",
        },
      },
      {
        name: "AdminProtection_BODY",
        description: "Detects admin-related content in body",
        defaultAction: "Count",
        addedLabels: ["AdminProtection_BODY"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "admin|administrator|password",
        },
      },
    ],
  },

  // =============================================================================
  // Amazon IP Reputation List
  // =============================================================================
  AWSManagedRulesAmazonIpReputationList: {
    vendorName: "AWS",
    name: "AWSManagedRulesAmazonIpReputationList",
    description:
      "Rules that are based on Amazon internal threat intelligence. Blocks IP addresses that are typically associated with bots or other threats. Useful as a starting point or for additional protection.",
    wcu: 25,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:amazon-ip-reputation-list:",
    rules: [
      {
        name: "AWSManagedIPReputationList",
        description: "Blocks IP addresses with bad reputation",
        defaultAction: "Block",
        addedLabels: ["AWSManagedIPReputationList"],
        simulationCriteria: {
          type: "ip_in_list",
          patterns: ["1.2.3.4"], // Placeholder - actual list is dynamic
        },
      },
    ],
  },

  // =============================================================================
  // Anonymous IP List
  // =============================================================================
  AWSManagedRulesAnonymousIpList: {
    vendorName: "AWS",
    name: "AWSManagedRulesAnonymousIpList",
    description:
      "Rules to block requests from IP addresses that are associated with anonymity services like VPNs, proxies, and Tor nodes. Use this to block requests from sources that might hide the identity of the requester.",
    wcu: 50,
    scope: "BOTH",
    additionalFee: false,
    labelNamespace: "awswaf:managed:aws:anonymous-ip-list:",
    rules: [
      {
        name: "AnonymousIPList",
        description: "Blocks requests from anonymous IP addresses",
        defaultAction: "Block",
        addedLabels: ["AnonymousIPList"],
        simulationCriteria: {
          type: "ip_in_list",
          patterns: [], // Dynamic list
        },
      },
      {
        name: "TorExitNode",
        description: "Blocks Tor exit nodes",
        defaultAction: "Block",
        addedLabels: ["TorExitNode"],
        simulationCriteria: {
          type: "ip_in_list",
          patterns: [], // Dynamic list
        },
      },
      {
        name: "HostingProviderIP",
        description: "Blocks hosting provider IPs (often used for bots)",
        defaultAction: "Count",
        addedLabels: ["HostingProviderIP"],
        simulationCriteria: {
          type: "ip_in_list",
          patterns: [], // Dynamic list
        },
      },
    ],
  },

  // =============================================================================
  // Bot Control Rule Set
  // =============================================================================
  AWSManagedRulesBotControlRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesBotControlRuleSet",
    description:
      "Rules to identify and block bot traffic. Provides granular control over which bots to allow, block, or count. Includes TGT (Targeted) inspection level for advanced bot detection.",
    wcu: 50,
    scope: "BOTH",
    additionalFee: true,
    labelNamespace: "awswaf:managed:aws:bot-control:",
    rules: [
      {
        name: "CategoryBot",
        description: "Identifies known bot categories",
        defaultAction: "Count",
        addedLabels: ["CategoryBot"],
        simulationCriteria: {
          type: "header_match",
          field: "User-Agent",
          pattern: "bot|crawler|spider|scraper",
        },
      },
      {
        name: "CategorySearchEngine",
        description: "Identifies search engine bots",
        defaultAction: "Count",
        addedLabels: ["CategorySearchEngine"],
        simulationCriteria: {
          type: "header_match",
          field: "User-Agent",
          pattern: "Googlebot|Bingbot|Slurp|DuckDuckBot",
        },
      },
      {
        name: "CategoryMonitoring",
        description: "Identifies monitoring service bots",
        defaultAction: "Count",
        addedLabels: ["CategoryMonitoring"],
        simulationCriteria: {
          type: "header_match",
          field: "User-Agent",
          pattern: "Pingdom|NewRelic|StatusCake|UptimeRobot",
        },
      },
      {
        name: "CategoryEmailClient",
        description: "Identifies email client requests",
        defaultAction: "Count",
        addedLabels: ["CategoryEmailClient"],
        simulationCriteria: {
          type: "header_match",
          field: "User-Agent",
          pattern: "Outlook|Thunderbird|AppleMail",
        },
      },
      {
        name: "SignalNonBrowserUserAgent",
        description: "Identifies non-browser user agents",
        defaultAction: "Count",
        addedLabels: ["SignalNonBrowserUserAgent"],
        simulationCriteria: {
          type: "header_match",
          field: "User-Agent",
          pattern: "curl|wget|python-requests|java|okhttp|httpclient",
        },
      },
      {
        name: "Tgt_BadBot",
        description: "Targeted detection of bad bots",
        defaultAction: "Block",
        addedLabels: ["Tgt_BadBot"],
        simulationCriteria: {
          type: "header_match",
          field: "User-Agent",
          pattern: "sqlmap|nikto|masscan|zgrab",
        },
      },
      {
        name: "Tgt_MaliciousBot",
        description: "Targeted detection of malicious bot behavior",
        defaultAction: "Block",
        addedLabels: ["Tgt_MaliciousBot"],
        simulationCriteria: {
          type: "custom",
          operator: "equals",
          value: "detected",
        },
      },
    ],
  },

  // =============================================================================
  // Account Takeover Prevention (ATP)
  // =============================================================================
  AWSManagedRulesATPRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesATPRuleSet",
    description:
      "Rules to detect and block account takeover attempts such as credential stuffing, brute force login, and fake account creation. Requires configuration of login path and credential fields.",
    wcu: 50,
    scope: "BOTH",
    additionalFee: true,
    labelNamespace: "awswaf:managed:aws:atp:",
    rules: [
      {
        name: "ATP_CredentialTheft",
        description: "Detects credential theft patterns",
        defaultAction: "Block",
        addedLabels: ["ATP_CredentialTheft"],
        simulationCriteria: {
          type: "body_pattern",
          pattern: "password|passwd|pwd|secret|token",
        },
      },
      {
        name: "ATP_BruteForce",
        description: "Detects brute force login attempts",
        defaultAction: "Block",
        addedLabels: ["ATP_BruteForce"],
        simulationCriteria: {
          type: "custom",
          operator: "equals",
          value: "detected",
        },
      },
      {
        name: "ATP_CredentialStuffing",
        description: "Detects credential stuffing attacks",
        defaultAction: "Block",
        addedLabels: ["ATP_CredentialStuffing"],
        simulationCriteria: {
          type: "custom",
          operator: "equals",
          value: "detected",
        },
      },
      {
        name: "ATP_SuspiciousLogin",
        description: "Detects suspicious login activity",
        defaultAction: "Count",
        addedLabels: ["ATP_SuspiciousLogin"],
        simulationCriteria: {
          type: "custom",
          operator: "equals",
          value: "detected",
        },
      },
    ],
  },

  // =============================================================================
  // Account Creation Fraud Prevention (ACFP)
  // =============================================================================
  AWSManagedRulesACFPRuleSet: {
    vendorName: "AWS",
    name: "AWSManagedRulesACFPRuleSet",
    description:
      "Rules to detect and block fake account creation attempts. Requires configuration of registration path and form fields.",
    wcu: 50,
    scope: "BOTH",
    additionalFee: true,
    labelNamespace: "awswaf:managed:aws:acfp:",
    rules: [
      {
        name: "ACFP_FakeAccountCreation",
        description: "Detects fake account creation patterns",
        defaultAction: "Block",
        addedLabels: ["ACFP_FakeAccountCreation"],
        simulationCriteria: {
          type: "custom",
          operator: "equals",
          value: "detected",
        },
      },
      {
        name: "ACFP_SuspiciousRegistration",
        description: "Detects suspicious registration activity",
        defaultAction: "Count",
        addedLabels: ["ACFP_SuspiciousRegistration"],
        simulationCriteria: {
          type: "custom",
          operator: "equals",
          value: "detected",
        },
      },
    ],
  },
};

/**
 * Get a list of all managed rule group names
 */
export function getManagedRuleGroupNames(): string[] {
  return Object.keys(MANAGED_RULE_GROUPS);
}

/**
 * Get a managed rule group by name
 */
export function getManagedRuleGroup(name: string): ManagedRuleGroup | undefined {
  return MANAGED_RULE_GROUPS[name];
}

/**
 * Check if a managed rule group exists
 */
export function hasManagedRuleGroup(name: string): boolean {
  return name in MANAGED_RULE_GROUPS;
}

/**
 * Get the total WCU for a managed rule group
 */
export function getManagedRuleGroupWCU(name: string): number {
  const group = MANAGED_RULE_GROUPS[name];
  return group?.wcu || 0;
}

/**
 * Check if a managed rule group has additional fees
 */
export function hasAdditionalFee(name: string): boolean {
  const group = MANAGED_RULE_GROUPS[name];
  return group?.additionalFee || false;
}

/**
 * Get managed rule groups by scope
 */
export function getManagedRuleGroupsByScope(scope: "CLOUDFRONT" | "REGIONAL"): ManagedRuleGroup[] {
  return Object.values(MANAGED_RULE_GROUPS).filter((group) => {
    return group.scope === "BOTH" || group.scope === scope.toUpperCase();
  });
}

/**
 * Get all labels that can be emitted by a managed rule group
 */
export function getManagedRuleGroupLabels(name: string): string[] {
  const group = MANAGED_RULE_GROUPS[name];
  if (!group) return [];

  const labels: string[] = [];
  for (const rule of group.rules) {
    for (const label of rule.addedLabels) {
      labels.push(group.labelNamespace + label);
    }
  }
  return labels;
}
