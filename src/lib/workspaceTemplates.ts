// WAFSim v3 rc.9.3 — Starting templates for common scenarios.
//
// Addresses the "dropped in an editor with no guidance" UX gap.
// Each template scaffolds a realistic starting topology so the user can
// immediately simulate, modify, or learn from it.
//
// Templates are consumed by the store's importState(JSON.stringify(template))
// path so they share the import pipeline used by shareable URLs and
// user-saved workspaces.

import type { AWSResourceNode, TopologyEdge, WebACL, IPSet, RegexPatternSet } from "./types";

export interface WorkspaceTemplate {
  id: string;
  name: string;
  tagline: string;
  description: string;
  icon: string;
  difficulty: "Starter" | "Intermediate" | "Advanced";
  nodes: AWSResourceNode[];
  edges: TopologyEdge[];
  wafs: WebACL[];
  ipSets: IPSet[];
  regexPatternSets: RegexPatternSet[];
}

// Helper to build the standard visibilityConfig every WAF rule needs
function viz(name: string) {
  return {
    sampledRequestsEnabled: true,
    cloudWatchMetricsEnabled: true,
    metricName: name,
  };
}

// ---------- Templates ----------

const TEMPLATE_CLOUDFRONT_S3: WorkspaceTemplate = {
  id: "cf-s3",
  name: "CloudFront + S3",
  tagline: "Static site behind CloudFront with WAF",
  description:
    "Content delivery pattern. WAF at the CF edge terminates unwanted traffic before it reaches origin. Best for marketing sites, SPA fronts, static assets.",
  icon: "🌐",
  difficulty: "Starter",
  nodes: [
    { id: "internet", type: "INTERNET", label: "Internet", icon: "🌐", wafAttachable: false, position: { x: 80, y: 220 } },
    { id: "cf", type: "CLOUDFRONT", label: "CloudFront", icon: "☁️", wafAttachable: true, scope: "CLOUDFRONT", position: { x: 320, y: 220 } },
    { id: "waf-cf-node", type: "WAF", label: "WAF (CF)", icon: "🛡️", wafAttachable: false, wafId: "waf-cf", position: { x: 320, y: 80 } },
    { id: "s3", type: "S3", label: "S3 Bucket", icon: "🗄️", wafAttachable: false, position: { x: 600, y: 220 } },
  ],
  edges: [
    { id: "e1", source: "internet", target: "cf" },
    { id: "e2", source: "cf", target: "s3" },
    { id: "p1", source: "waf-cf-node", target: "cf", wafId: "waf-cf" },
  ],
  wafs: [
    {
      id: "waf-cf",
      name: "Edge-WAF",
      scope: "CLOUDFRONT",
      defaultAction: "ALLOW",
      visibilityConfig: viz("EdgeWAF"),
      rules: [
        {
          name: "CommonRuleSet",
          priority: 10,
          overrideAction: "NONE",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
            excludedRules: [],
          } as never,
          action: "NONE",
          visibilityConfig: viz("CRS"),
        },
      ],
    },
  ],
  ipSets: [],
  regexPatternSets: [],
};

const TEMPLATE_ALB_EC2: WorkspaceTemplate = {
  id: "alb-ec2",
  name: "ALB + EC2 (regional)",
  tagline: "Classic web app with regional WAF",
  description:
    "Most common production setup: ALB fronting EC2/ASG, regional WAF on the ALB. Ships with geo protection + SQLi/XSS managed rules.",
  icon: "⚖️",
  difficulty: "Starter",
  nodes: [
    { id: "internet", type: "INTERNET", label: "Internet", icon: "🌐", wafAttachable: false, position: { x: 80, y: 220 } },
    { id: "alb", type: "ALB", label: "ALB", icon: "⚖️", wafAttachable: true, scope: "REGIONAL", position: { x: 320, y: 220 } },
    { id: "waf-alb-node", type: "WAF", label: "WAF (ALB)", icon: "🛡️", wafAttachable: false, wafId: "waf-alb", position: { x: 320, y: 80 } },
    { id: "ec2", type: "EC2", label: "EC2 Instance", icon: "🖥️", wafAttachable: false, position: { x: 600, y: 220 } },
  ],
  edges: [
    { id: "e1", source: "internet", target: "alb" },
    { id: "e2", source: "alb", target: "ec2" },
    { id: "p1", source: "waf-alb-node", target: "alb", wafId: "waf-alb" },
  ],
  wafs: [
    {
      id: "waf-alb",
      name: "ALB-WAF",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      visibilityConfig: viz("ALBWAF"),
      rules: [
        {
          name: "CommonRuleSet",
          priority: 10,
          overrideAction: "NONE",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
            excludedRules: [],
          } as never,
          action: "NONE",
          visibilityConfig: viz("CRS"),
        },
        {
          name: "KnownBadInputs",
          priority: 20,
          overrideAction: "NONE",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesKnownBadInputsRuleSet",
            excludedRules: [],
          } as never,
          action: "NONE",
          visibilityConfig: viz("KBI"),
        },
      ],
    },
  ],
  ipSets: [],
  regexPatternSets: [],
};

const TEMPLATE_APIGW_LAMBDA: WorkspaceTemplate = {
  id: "apigw-lambda",
  name: "API Gateway + Lambda",
  tagline: "Serverless API with rate limits",
  description:
    "Serverless REST API behind API Gateway. Regional WAF with rate-based rule + CommonRuleSet. Ships with a rate limit of 100/5min per IP.",
  icon: "⚡",
  difficulty: "Intermediate",
  nodes: [
    { id: "internet", type: "INTERNET", label: "Internet", icon: "🌐", wafAttachable: false, position: { x: 80, y: 220 } },
    { id: "apigw", type: "API_GATEWAY", label: "API Gateway", icon: "🔌", wafAttachable: true, scope: "REGIONAL", position: { x: 320, y: 220 } },
    { id: "waf-apigw-node", type: "WAF", label: "WAF (APIGW)", icon: "🛡️", wafAttachable: false, wafId: "waf-apigw", position: { x: 320, y: 80 } },
    { id: "lambda", type: "LAMBDA", label: "Lambda Function", icon: "⚡", wafAttachable: false, position: { x: 600, y: 220 } },
  ],
  edges: [
    { id: "e1", source: "internet", target: "apigw" },
    { id: "e2", source: "apigw", target: "lambda" },
    { id: "p1", source: "waf-apigw-node", target: "apigw", wafId: "waf-apigw" },
  ],
  wafs: [
    {
      id: "waf-apigw",
      name: "APIGW-WAF",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      visibilityConfig: viz("APIGWWAF"),
      rules: [
        {
          name: "RateLimit",
          priority: 10,
          action: "BLOCK",
          statement: {
            type: "RateBasedStatement",
            rateLimit: 100,
            evaluationWindowSec: 300,
            aggregateKeyType: "IP",
          } as never,
          visibilityConfig: viz("RateLimit"),
        },
        {
          name: "CommonRuleSet",
          priority: 20,
          overrideAction: "NONE",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
            excludedRules: [],
          } as never,
          action: "NONE",
          visibilityConfig: viz("CRS"),
        },
      ],
    },
  ],
  ipSets: [],
  regexPatternSets: [],
};

const TEMPLATE_MULTI_TIER: WorkspaceTemplate = {
  id: "multi-tier",
  name: "Full stack (CF + ALB + APIGW)",
  tagline: "Multi-WAF defense in depth",
  description:
    "Realistic production fleet: CloudFront at the edge, ALB + EC2 for web app, API Gateway + Lambda for APIs. Separate WAFs per tier with appropriate scope and managed groups.",
  icon: "🏗️",
  difficulty: "Advanced",
  nodes: [
    { id: "internet", type: "INTERNET", label: "Internet", icon: "🌐", wafAttachable: false, position: { x: 80, y: 280 } },
    { id: "cf", type: "CLOUDFRONT", label: "CloudFront", icon: "☁️", wafAttachable: true, scope: "CLOUDFRONT", position: { x: 280, y: 280 } },
    { id: "waf-cf-node", type: "WAF", label: "Edge WAF", icon: "🛡️", wafAttachable: false, wafId: "waf-cf", position: { x: 280, y: 120 } },
    { id: "alb", type: "ALB", label: "ALB", icon: "⚖️", wafAttachable: true, scope: "REGIONAL", position: { x: 540, y: 180 } },
    { id: "waf-alb-node", type: "WAF", label: "ALB WAF", icon: "🛡️", wafAttachable: false, wafId: "waf-alb", position: { x: 540, y: 40 } },
    { id: "ec2", type: "EC2", label: "Web App EC2", icon: "🖥️", wafAttachable: false, position: { x: 820, y: 180 } },
    { id: "apigw", type: "API_GATEWAY", label: "API Gateway", icon: "🔌", wafAttachable: true, scope: "REGIONAL", position: { x: 540, y: 420 } },
    { id: "waf-apigw-node", type: "WAF", label: "APIGW WAF", icon: "🛡️", wafAttachable: false, wafId: "waf-apigw", position: { x: 540, y: 560 } },
    { id: "lambda", type: "LAMBDA", label: "API Lambda", icon: "⚡", wafAttachable: false, position: { x: 820, y: 420 } },
  ],
  edges: [
    { id: "e1", source: "internet", target: "cf" },
    { id: "e2", source: "cf", target: "alb" },
    { id: "e3", source: "alb", target: "ec2" },
    { id: "e4", source: "cf", target: "apigw" },
    { id: "e5", source: "apigw", target: "lambda" },
    { id: "p1", source: "waf-cf-node", target: "cf", wafId: "waf-cf" },
    { id: "p2", source: "waf-alb-node", target: "alb", wafId: "waf-alb" },
    { id: "p3", source: "waf-apigw-node", target: "apigw", wafId: "waf-apigw" },
  ],
  wafs: [
    {
      id: "waf-cf",
      name: "EdgeWAF",
      scope: "CLOUDFRONT",
      defaultAction: "ALLOW",
      visibilityConfig: viz("EdgeWAF"),
      rules: [
        {
          name: "RateLimitGlobal",
          priority: 5,
          action: "BLOCK",
          statement: {
            type: "RateBasedStatement",
            rateLimit: 2000,
            evaluationWindowSec: 300,
            aggregateKeyType: "IP",
          } as never,
          visibilityConfig: viz("RateLimitGlobal"),
        },
        {
          name: "IPReputation",
          priority: 10,
          overrideAction: "NONE",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesAmazonIpReputationList",
            excludedRules: [],
          } as never,
          action: "NONE",
          visibilityConfig: viz("IPRep"),
        },
      ],
    },
    {
      id: "waf-alb",
      name: "ALB-WAF",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      visibilityConfig: viz("ALBWAF"),
      rules: [
        {
          name: "CommonRuleSet",
          priority: 10,
          overrideAction: "NONE",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
            excludedRules: [],
          } as never,
          action: "NONE",
          visibilityConfig: viz("CRS"),
        },
      ],
    },
    {
      id: "waf-apigw",
      name: "APIGW-WAF",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      visibilityConfig: viz("APIGWWAF"),
      rules: [
        {
          name: "RateLimitAPI",
          priority: 10,
          action: "BLOCK",
          statement: {
            type: "RateBasedStatement",
            rateLimit: 100,
            evaluationWindowSec: 300,
            aggregateKeyType: "IP",
          } as never,
          visibilityConfig: viz("RateLimitAPI"),
        },
      ],
    },
  ],
  ipSets: [],
  regexPatternSets: [],
};

const TEMPLATE_BLANK: WorkspaceTemplate = {
  id: "blank",
  name: "Blank canvas",
  tagline: "Start from scratch",
  description:
    "Empty workspace. Drag resources from the left palette to build your own topology. Best when you're modeling something unusual.",
  icon: "📄",
  difficulty: "Starter",
  nodes: [
    { id: "internet", type: "INTERNET", label: "Internet", icon: "🌐", wafAttachable: false, position: { x: 80, y: 220 } },
  ],
  edges: [],
  wafs: [],
  ipSets: [],
  regexPatternSets: [],
};

export const WORKSPACE_TEMPLATES: WorkspaceTemplate[] = [
  TEMPLATE_ALB_EC2,
  TEMPLATE_CLOUDFRONT_S3,
  TEMPLATE_APIGW_LAMBDA,
  TEMPLATE_MULTI_TIER,
  TEMPLATE_BLANK,
];

export function getTemplate(id: string): WorkspaceTemplate | undefined {
  return WORKSPACE_TEMPLATES.find((t) => t.id === id);
}

export function templateToImportJson(t: WorkspaceTemplate): string {
  return JSON.stringify({
    nodes: t.nodes,
    edges: t.edges,
    wafs: t.wafs,
    ipSets: t.ipSets,
    regexPatternSets: t.regexPatternSets,
  });
}
