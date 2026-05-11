// WAFSim v3 — End-to-end demo harness
// Programmatic full-stack flow: build a WebACL, define IP sets + regex pattern sets,
// simulate a batch of realistic requests (benign + attacks), verify evaluation
// matches documented expectations, and round-trip the config through the export
// engine so we know the generated AWS JSON survives import.
//
// This is intentionally written as a Vitest scenario so a single `vitest run` in
// CI validates every major subsystem end to end.

import { describe, expect, it } from "vitest";
import {
  evaluateWebACL,
  evaluateBatch,
  summarizeResults,
  validateWebACL,
} from "@/engines/wafEngine";
import {
  exportAsWebACLJson,
  exportAsTerraformHCL,
  generateCLICommands,
} from "@/engines/exportEngine";
import { importWebACLJson } from "@/engines/importEngine";
import type { HttpRequest, WebACL } from "@/lib/types";
import {
  baseRequest,
  makeRule,
  makeWebACL,
  makeIPSet,
  makeRegexPatternSet,
} from "./_fixtures";

const corpIPs = makeIPSet({
  name: "CorporateOfficeIPs",
  description: "Known corporate egress IPs",
  addresses: ["203.0.113.0/24"],
});

const adminPaths = makeRegexPatternSet({
  name: "AdminPaths",
  description: "Sensitive admin endpoints",
  regularExpressionList: ["^/admin", "^/wp-admin", "^/phpmyadmin"],
});

const webACL: WebACL = makeWebACL({
  name: "wafsim-demo-webacl",
  description: "WAFSim v3 end-to-end demo",
  defaultAction: "ALLOW",
  rules: [
    // Priority 0 — allow corp IPs to admin paths
    makeRule({
      name: "AllowCorpToAdmin",
      priority: 0,
      action: "ALLOW",
      statement: {
        type: "AndStatement",
        statements: [
          {
            type: "IPSetReferenceStatement",
            arn: corpIPs.arn,
            ipSetReference: { arn: corpIPs.arn },
          },
          {
            type: "RegexPatternSetReferenceStatement",
            arn: adminPaths.arn,
            fieldToMatch: { type: "URI_PATH" },
            textTransformations: [{ type: "NONE", priority: 0 }],
          },
        ],
      } as WebACL["rules"][0]["statement"],
    }),
    // Priority 1 — block non-corp access to admin
    makeRule({
      name: "BlockAdminAccess",
      priority: 1,
      action: "BLOCK",
      ruleLabels: ["demo:blocked:admin-access"],
      statement: {
        type: "RegexPatternSetReferenceStatement",
        arn: adminPaths.arn,
        fieldToMatch: { type: "URI_PATH" },
        textTransformations: [{ type: "NONE", priority: 0 }],
      } as WebACL["rules"][0]["statement"],
    }),
    // Priority 2 — block China
    makeRule({
      name: "BlockGeoCN",
      priority: 2,
      action: "BLOCK",
      ruleLabels: ["demo:blocked:geo"],
      statement: {
        type: "GeoMatchStatement",
        countryCodes: ["CN"],
      } as WebACL["rules"][0]["statement"],
    }),
    // Priority 3 — SQLi on query string
    makeRule({
      name: "BlockSQLi",
      priority: 3,
      action: "BLOCK",
      statement: {
        type: "SqliMatchStatement",
        fieldToMatch: { type: "QUERY_STRING" },
        textTransformations: [{ type: "URL_DECODE", priority: 0 }],
        sensitivityLevel: "LOW",
      } as WebACL["rules"][0]["statement"],
    }),
    // Priority 4 — COUNT suspicious user-agents (does not terminate)
    makeRule({
      name: "CountBadUA",
      priority: 4,
      action: "COUNT",
      ruleLabels: ["demo:ua:suspicious"],
      statement: {
        type: "ByteMatchStatement",
        searchString: "sqlmap",
        fieldToMatch: { type: "SINGLE_HEADER", name: "user-agent" },
        textTransformations: [{ type: "LOWERCASE", priority: 0 }],
        positionalConstraint: "CONTAINS",
      } as WebACL["rules"][0]["statement"],
    }),
    // Priority 5 — block on suspicious UA label applied by earlier COUNT rule
    makeRule({
      name: "BlockSuspiciousUALabel",
      priority: 5,
      action: "BLOCK",
      statement: {
        type: "LabelMatchStatement",
        scope: "LABEL",
        key: "demo:ua:suspicious",
      } as WebACL["rules"][0]["statement"],
    }),
  ],
});

describe("WAFSim v3 E2E demo — full user flow", () => {
  const options = { ipSets: [corpIPs], regexPatternSets: [adminPaths] };

  it("WebACL validates and has expected non-zero WCU", () => {
    const v = validateWebACL(webACL);
    expect(v.valid).toBe(true);
    expect(v.errors).toEqual([]);
    expect(v.wcu).toBeGreaterThan(0);
  });

  describe("per-request evaluation", () => {
    it("allows corp IP to /admin", () => {
      const r = evaluateWebACL(
        baseRequest({ uri: "/admin/setup", sourceIP: "203.0.113.42" }),
        webACL,
        options
      );
      expect(r.finalAction).toBe("ALLOW");
      expect(r.terminatingRule?.rule.name).toBe("AllowCorpToAdmin");
    });

    it("blocks non-corp IP on /admin", () => {
      const r = evaluateWebACL(
        baseRequest({ uri: "/wp-admin/install.php", sourceIP: "198.51.100.99" }),
        webACL,
        options
      );
      expect(r.finalAction).toBe("BLOCK");
      expect(r.terminatingRule?.rule.name).toBe("BlockAdminAccess");
      expect(r.labelsApplied).toContain("demo:blocked:admin-access");
    });

    it("blocks CN country", () => {
      const r = evaluateWebACL(
        baseRequest({ uri: "/public/index", country: "CN" }),
        webACL,
        options
      );
      expect(r.finalAction).toBe("BLOCK");
      expect(r.terminatingRule?.rule.name).toBe("BlockGeoCN");
    });

    it("blocks SQLi on query string", () => {
      const r = evaluateWebACL(
        baseRequest({
          uri: "/api/users?id=1%27%20OR%201%3D1--",
          queryParams: { id: "1' OR 1=1--" },
        }),
        webACL,
        options
      );
      expect(r.finalAction).toBe("BLOCK");
      expect(r.terminatingRule?.rule.name).toBe("BlockSQLi");
    });

    it("COUNT → label → BLOCK chain (label propagation)", () => {
      const r = evaluateWebACL(
        baseRequest({ headers: [{ name: "User-Agent", value: "sqlmap/1.6.7" }] }),
        webACL,
        options
      );
      expect(r.labelsApplied).toContain("demo:ua:suspicious");
      expect(r.finalAction).toBe("BLOCK");
      expect(r.terminatingRule?.rule.name).toBe("BlockSuspiciousUALabel");
      expect(r.allMatchedRules.map((m) => m.rule.name)).toContain("CountBadUA");
    });

    it("allows benign request that matches nothing", () => {
      const r = evaluateWebACL(
        baseRequest({ uri: "/public/home", queryParams: {} }),
        webACL,
        options
      );
      expect(r.finalAction).toBe("ALLOW");
      expect(r.terminatingRule).toBeNull();
    });
  });

  describe("batch evaluation + summary", () => {
    it("tallies a mixed traffic batch correctly", () => {
      const batch: HttpRequest[] = [
        baseRequest({ uri: "/public/home" }),
        baseRequest({ uri: "/admin", sourceIP: "203.0.113.5" }),
        baseRequest({ uri: "/admin", sourceIP: "198.51.100.5" }),
        baseRequest({
          uri: "/api/users?id=1%27%20OR%201%3D1--",
          queryParams: { id: "1' OR 1=1--" },
        }),
        baseRequest({ country: "CN" }),
        baseRequest({ headers: [{ name: "User-Agent", value: "sqlmap/1.0" }] }),
      ];
      const results = evaluateBatch(batch, webACL, options);
      const summary = summarizeResults(results);
      expect(summary.total).toBe(6);
      // At least the admin + SQLi + geo + UA-label rules should block
      expect(summary.blocked).toBeGreaterThanOrEqual(4);
    });
  });

  describe("export engine round-trip", () => {
    it("exports valid AWS WAFv2 WebACL JSON", () => {
      const json = exportAsWebACLJson(webACL);
      expect(json.Name).toBe(webACL.name);
      expect(json.Scope).toBe(webACL.scope);
      expect(json.DefaultAction).toHaveProperty("Allow");
      expect(json.Rules).toHaveLength(webACL.rules.length);
      for (const r of json.Rules) {
        expect(r.VisibilityConfig).toBeDefined();
        expect(r.VisibilityConfig.MetricName).toBeTypeOf("string");
      }
    });

    it("produces terraform HCL that references aws_wafv2_web_acl", () => {
      const tf = exportAsTerraformHCL(webACL, [corpIPs], [adminPaths]);
      expect(tf).toMatch(/aws_wafv2_web_acl/);
      expect(tf).toContain(webACL.name);
    });

    it("produces a CLI command sequence that mentions create-web-acl", () => {
      const cli = generateCLICommands(webACL, [corpIPs], [adminPaths]);
      const joined = cli.join("\n");
      expect(joined).toMatch(/aws wafv2/);
      expect(joined).toMatch(/create-web-acl/);
      expect(joined).toMatch(/create-ip-set/);
      expect(joined).toMatch(/create-regex-pattern-set/);
    });

    it("round-trips through JSON import", () => {
      const json = exportAsWebACLJson(webACL);
      const imported = importWebACLJson(JSON.stringify(json));
      expect(imported.webACL).toBeDefined();
      if (!imported.webACL) return;
      expect(imported.webACL.name).toBe(webACL.name);
      expect(imported.webACL.rules.length).toBe(webACL.rules.length);
    });
  });
});
