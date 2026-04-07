# WAFSim — Project Context

> Use this file to restore full context if chat history is lost.
> Tell the assistant: "Read /Users/apdesai/Downloads/deploy/wafsim-v1/CONTEXT.md and resume from where we left off."

---

## What Is WAFSim

AWS WAFSim is a browser-based interactive simulator that lets users configure WebACL rules, attach them to a visual AWS architecture (CloudFront → ALB → ECS/Lambda/etc.), and test rule behavior against simulated HTTP traffic — no live AWS resources needed. It evaluates requests using the same priority-based rule evaluation logic as the real WAF service.

**Live URL**: https://wafsim.apurvad.xyz (hosted on Vercel, DNS via Route 53 CNAME)
**Source**: https://github.com/ApurvaDesai6/wafsim
**Developer**: Apurva Desai (apdesai)

---

## Tech Stack

- **Framework**: Next.js 16 + React 19 + TypeScript
- **UI**: Tailwind CSS + shadcn/ui components
- **Canvas**: React Flow (node-based topology visualization)
- **State**: Zustand store (`wafsimStore.ts`)
- **Hosting**: Vercel (free tier, auto-deploys from `main` branch)
- **DNS**: Route 53 — `wafsim.apurvad.xyz` CNAME → `10d17c0c5725dbf0.vercel-dns-017.com.`
- **Previous hosting**: EC2 t3.medium (i-09f3d4fcaed6d4ecf) in us-east-1, now locked down by Epoxy Mitigations sev2 security group. Instance still running but inaccessible.

---

## Git Structure

- **Branches**: `main` (production), `v2-improvements` (active dev branch)
- **Workflow**: Develop on `v2-improvements`, merge to `main`, push. Vercel auto-deploys from `main`.
- **Current version**: v2.18 (as of April 6, 2026)

---

## Project Structure (~10,274 LOC in core files)

```
src/
├── app/
│   ├── page.tsx (459 LOC)           — Main page: orchestrates topology, WAF config, traffic sim, evaluation
│   ├── layout.tsx                    — Root layout
│   └── api/
│       ├── explain-rule/route.ts     — AI-powered rule explanation (uses ZAI_API_KEY env var)
│       ├── generate-test-request/route.ts — AI-powered test request generation
│       └── tests/route.ts            — Test runner endpoint
├── engines/
│   ├── wafEngine.ts (496 LOC)        — Core: evaluateWebACL, evaluateRule, getEffectiveAction, rate tracking
│   ├── statementEvaluator.ts (1053 LOC) — All 14 statement types: byteMatch, geoMatch, sqliMatch, xssMatch, regexMatch, sizeConstraint, IPSet, labelMatch, rateBasedStatement, managedRuleGroup, ruleGroupReference, AND/OR/NOT
│   ├── exportEngine.ts (772 LOC)     — Export as WebACL JSON, Terraform HCL, CLI commands
│   ├── fieldExtractor.ts (417 LOC)   — Extract fields from HTTP requests (URI, headers, body, query, cookies)
│   ├── textTransformations.ts (413 LOC) — All WAF text transformations (URL decode, base64, HTML entity, etc.)
│   ├── sqliDetector.ts (425 LOC)     — SQL injection detection engine
│   ├── xssDetector.ts (520 LOC)      — XSS detection engine
│   ├── rateEngine.ts (304 LOC)       — Rate-based rule evaluation and flood simulation
│   └── wcuCalculator.ts (326 LOC)    — WCU (Web ACL Capacity Units) calculation
├── components/
│   ├── TopologyCanvas.tsx (782 LOC)  — React Flow canvas: nodes (CloudFront, ALB, API GW, ECS, Lambda, WAF), edges, traffic flow coloring
│   ├── RuleBuilder.tsx (906 LOC)     — Rule creation UI: all statement types, text transforms, actions, labels
│   ├── ResourceManager.tsx (515 LOC) — Add/remove/configure architecture resources
│   ├── WAFConfigPanel.tsx (503 LOC)  — WebACL configuration: rules list, priority ordering, default action, managed rule groups
│   ├── TrafficSimulator.tsx (307 LOC) — Configure and send test HTTP requests
│   ├── TrafficAnimation.tsx (294 LOC) — Animated traffic flow on canvas edges
│   ├── EvaluationTrace.tsx (261 LOC) — Visual trace of rule evaluation: which rules matched, actions taken, labels
│   ├── QuickLoadPresets.tsx (131 LOC) — Pre-built topology + rule configurations
│   └── WCUBudgetMeter.tsx (120 LOC)  — Visual WCU usage meter
├── lib/
│   ├── types.ts (725 LOC)           — All TypeScript types (HttpRequest, WAFAction, Statement types, WebACL, etc.)
│   ├── managedRuleGroups.ts (967 LOC) — All 14 AWS Managed Rule Group definitions with simulated sub-rules
│   ├── utils.ts                      — Utility functions
│   └── db.ts                         — Prisma client (minimal, for future use)
└── store/
    └── wafsimStore.ts (545 LOC)      — Zustand store: nodes, edges, WAF configs, rules, evaluation results, UI state
```

---

## Key Features (Working)

- Visual topology canvas with drag-and-drop AWS resources
- WAF node attachment to resources (CloudFront, ALB, API Gateway)
- All 14 WAF statement types supported in rule builder
- All 14 AWS Managed Rule Groups (simulated — see Known Limitations)
- Priority-based rule evaluation matching real WAF behavior
- COUNT rules don't terminate evaluation (matches real WAF)
- Label propagation between rules
- Text transformations (all WAF transforms supported)
- Traffic flow visualization with color-coded edges (green=passed, red=blocked)
- Block cascade: if WAF blocks at CloudFront, ALL downstream edges show red (v2.18)
- Rate-based rule evaluation
- WCU budget calculation and display
- Export as WebACL JSON, Terraform HCL, CLI commands
- Quick-load presets for common architectures
- Sampled request logs

---

## Known Limitations

1. **AWS Managed Rule Groups use simulated approximations** — the actual regex/match logic isn't public. If the tool were developed internally by AWS, real rule logic could be integrated for 1:1 accuracy. The tool is strongest for custom rule validation.
2. **Rate-based flood simulation** has an "In Development" badge (v2.17) — basic rate tracking works but full flood sim needs refinement.
3. **No import** — can't yet import an existing WebACL JSON to populate the canvas.
4. **Export accuracy** — needs audit against real AWS `CreateWebACL` API schema, especially for nested statements in Terraform HCL.

---

## SPARK Submission & Stakeholders

Submitted to SPARK tool intake (https://w.amazon.com/bin/view/AWSSupportPortal/CST/TAA/SPARK) on April 6, 2026.

**Stakeholders**:
- Apurva Desai (apdesai) — Developer
- Andrew Stiller (astiller) — Manager
- Yang Liu (yangliuz) — WAF SXO
- Avi Rmani (avirmani)
- Prasanj T (prasanjt)

**Timeline**: MVP/POC complete (current). Core functionality validation and feature improvement throughout April, targeting internal beta with WAF SME review by May 2026. Assess customer-facing recommendation after SME review.

**Slack channel created** for SXO visibility and feedback.

---

## Hosting & Infrastructure

| Component | Current State |
|---|---|
| EC2 (i-09f3d4fcaed6d4ecf) | Running but locked down by Epoxy Mitigations SG. t3.medium, us-east-1a. ~$30/mo cost while idle. |
| ALB | apurvad-xyz-alb-1394578021.us-east-1.elb.amazonaws.com — still exists but EC2 behind it is isolated |
| Route 53 | Zone Z099153621G9JWKOVT92M for apurvad.xyz. wafsim subdomain CNAME'd to Vercel. |
| Vercel | Free tier. Auto-deploys from main branch. Custom domain wafsim.apurvad.xyz connected. |
| S3 | s3://apurvad-xyz-failover/deploy/ — used for EC2 deployment artifacts (legacy) |

---

## Env Variables

- `ZAI_API_KEY` — Used by `/api/explain-rule` and `/api/generate-test-request`. Optional; app works without it, AI features just won't function.

---

## Development Improvement Schedule (April 7–18, 2 items/day)

| Date | AM | PM |
|---|---|---|
| Apr 7 | v2.19 — Export audit: WebACL JSON vs real CreateWebACL schema | v2.20 — Terraform HCL fix for nested statements |
| Apr 8 | v2.21 — AMR sub-rule listing in config panel | v2.22 — AMR rule override UI (COUNT/BLOCK/ALLOW per sub-rule) |
| Apr 9 | v2.23 — Import WebACL JSON → populate canvas | v2.24 — Import validation & error handling |
| Apr 10 | v2.25 — Label propagation visualization in trace | v2.26 — Scope-down statement UI |
| Apr 11 | v2.27 — Text transformation chain visualization | v2.28 — Regex pattern set management UI |
| Apr 12 | v2.29 — IP set management UI | v2.30 — Batch test mode (multiple requests) |
| Apr 13 | v2.31 — Request template library (SQLi, XSS, SSRF, Log4j) | v2.32 — WCU calculator audit vs AWS docs |
| Apr 14 | v2.33 — Dark mode / theme toggle | v2.34 — Shareable configs via URL encoding |
| Apr 15 | v2.35 — Keyboard shortcuts | v2.36 — Accessibility pass (ARIA, keyboard nav) |
| Apr 16 | v2.37 — Performance (virtualize lists, lazy load, optimize renders) | v2.38 — Custom response body support |
| Apr 17 | v2.39 — Multi-WebACL comparison view | v2.40 — In-app documentation & help tooltips |
| Apr 18 | v2.41 — Edge case sweep (all 14 statement types) | v2.42 — Polish (loading states, error boundaries, spacing) |

**Apr 19–30**: Buffer for SME feedback, bug fixes, stretch features.

---

## Deploy Workflow (Vercel — Current)

```bash
cd /Users/apdesai/Downloads/deploy/wafsim-v1
git checkout v2-improvements
# make changes
git add -A && git commit -m "v2.XX: description"
git checkout main && git merge v2-improvements --no-edit
git push origin main   # triggers Vercel auto-deploy
git checkout v2-improvements
```

## Deploy Workflow (EC2 — Legacy, currently non-functional)

```bash
# Build locally, tar, upload to S3, SSH in, docker build, docker-compose up
# EC2 is locked down — this workflow no longer works until SG is restored
```

---

## Last Session Summary

> Update this section at the end of each working session.

**Date**: April 6, 2026
**Version**: v2.18
**What was done**:
- Fixed traffic flow cascade: BFS traversal propagates block status to ALL downstream nodes
- Deployed to Vercel (free tier) after EC2 was locked down by sev2 Epoxy Mitigations
- Updated Route 53 DNS: wafsim.apurvad.xyz CNAME → Vercel
- Submitted SPARK tool intake form
- Created Slack channel for SXO team visibility
- Established 2-items/day improvement schedule through April 18

**Next up**: v2.19 (export JSON audit) and v2.20 (Terraform HCL nested statement fix)
