# WAFSim v3 — Product Vision & Improvement Plan (2026-05-08)

Triple-perspective analysis after Apurva's feedback: "think in turns from product manager and customer side and senior engineer and really improve and develop that feature since massive cx gap there and take look at rest of platform hard and make substantive improvements everywhere."

---

## Who is the customer?

Four clearly distinct personas:

1. **AWS support engineer** (Apurva's own role) — debugging customer WAF issues, needs to reproduce FP scenarios quickly, paste real logs, generate proposed exceptions, share with the customer via case comms.
2. **SRE / DevOps at a company using WAF** — has an existing WAF config in Terraform/CFN, needs to test changes before deployment, wants IaC export.
3. **Security engineer writing WAF policy** — needs defense-in-depth analysis, posture scoring, compliance-friendly audit trails.
4. **Developer inheriting a WAF setup** — doesn't understand what's there, needs visualization + explanation + "what breaks if I change this".

The tool as-shipped only works well for persona (1) and only for ad-hoc single-log troubleshooting. Personas (2)–(4) are underserved.

---

## What's missing (PM perspective)

### The FP Exception feature in particular

- **No history.** Every time you use the tool, you start from a blank log textarea. In reality, an SE troubleshoots 5–10 FPs per week, many from the same customer. There should be a history of past exceptions generated, searchable by URI/rule/tag.
- **Output is just JSON.** Real customers deploy via CloudFormation, Terraform, or CDK — JSON is a dev-hostile format. Need multi-format export.
- **No audit/justification trail.** Compliance-heavy customers need to document WHY each exception exists, WHO approved it, WHAT log triggered it. Without this, WAFSim is not deployable in regulated environments.
- **No bulk mode.** A migration (e.g. tightening managed-group overrides) produces dozens of FPs. Can't process them one-by-one through a wizard.
- **No integration hooks.** Real customers paste logs from CloudWatch Insights / Athena / S3. The tool should accept a URL/query template, not just copy-paste.
- **No pattern library.** Common FPs (rich text editor on a CMS, file upload endpoints, legacy IP ranges) are the same across most customers. WAFSim should ship a built-in library of known safe-to-allow patterns.

### The rest of the platform

- **No IaC import.** Can't bring an existing WebACL from Terraform/CloudFormation/CDK into WAFSim to simulate against. Every session starts from scratch. **This is the single biggest gap** — without it, WAFSim is a toy, not a tool.
- **No IaC export.** The inverse — can't export WAFSim-designed WebACLs as deployable CFN/Terraform.
- **No shareable URLs.** Can't send a teammate a link that says "check this out". This is table-stakes for a web-first tool in 2026.
- **No templates.** Empty-canvas first-run experience is hostile. "What do I even drag?"
- **No landing/hero.** User lands on the canvas with no explanation of what the tool is.
- **No tour/onboarding.** Feature discovery is zero.
- **No collaboration.** Can't comment on a rule, tag a teammate, assign someone.
- **No persistence beyond localStorage.** Refresh in a different browser = start over. Real tools have cloud sync OR cleanly-communicated local-first.
- **No diff view** on Compare tab (which exists but is weak).

### YC-ready signals that are missing

- No clear value prop on landing. Wafsim.apurvad.xyz just dumps you into the editor.
- No pricing consideration / paid tier hint.
- No case studies / before-after examples.
- No "used by" social proof.
- Pitch deck artifacts absent (what screenshots would you put in a YC application?).
- No dogfooding narrative — Apurva uses it at AWS support, but that's invisible to a visitor.

---

## Customer needs (empathy pass)

### Scenario: AWS SE troubleshoots a customer FP

- Customer opens a case: "WAF is blocking legit requests to /api/import from my SaaS integration".
- SE needs: a) confirm the FP, b) identify the blocking rule, c) design an exception, d) validate the exception doesn't break their actual attack protection, e) send the customer a deliverable (CloudFormation? rule JSON? step-by-step console instructions?).
- Today WAFSim covers b, c, a bit of d. Gaps: (a) requires customer log, (d) only tests canned variants, (e) only JSON output.

### Scenario: SRE migrating from unmanaged to managed rules

- SRE has Terraform for an existing WebACL with 15 hand-written rules. Wants to move to `AWSManagedRulesCommonRuleSet` + exceptions.
- Needs: import current Terraform, see how it maps in WAFSim, run traffic through it, add managed group, identify FPs via simulation, generate exceptions, export updated Terraform.
- Today WAFSim covers… none of this end-to-end. All pieces exist separately; nothing connects.

### Scenario: Security engineer auditing a fleet

- Has 20 WebACLs across 8 accounts. Wants to score them all, find the weakest, prioritize fixes.
- Today: AggregatePostureBadge (new in rc.9) does single-workspace fleet scoring. No cross-workspace, no WebACL import at scale, no report export.

---

## Senior engineer gaps

- **TypeScript strict errors pre-existing.** Saw `src/engines/statementEvaluator.ts` and `wafEngine.ts` with `TS2536` and `TS2345` errors when running `tsc --noEmit`. Build passes (Next.js less strict) but this is accumulating debt.
- **Lots of `as unknown as` casts** where proper discriminated unions would be cleaner.
- **Zustand store is one 600-LOC file** — could be split into slices (wafs, topology, simulation, settings).
- **No error boundaries** — any component crash nukes the whole app.
- **No bundle-size budget.** App is probably getting chunky.
- **No Playwright / e2e tests.** Everything is component-level or engine-level. Integration tests added in rc.9 were a first step but still don't test the UI.
- **No accessibility audit** — keyboard nav broken, screen reader probably unusable.
- **No observability.** If something breaks in prod, no one knows.
- **No CI test gate.** Vercel auto-deploys on push; no "tests must pass" enforcement.
- **No feature flags** — can't ship to a subset of users.

---

## Prioritized improvements (rc.9.3 scope)

What delivers most perceived value per hour of work, ordered by (impact × reach) / effort:

### SHIPPING THIS RC

1. **Shareable state URLs** — encode the workspace into a URL param, paste to share. Base64 gzip of relevant zustand slices. ~100 LOC. Addresses the "can't send a teammate a link" gap.

2. **Templates picker on empty canvas** — 4 built-in starting scenarios (ALB + EC2, CloudFront + S3, APIGW + Lambda, Full stack with WAF). One click scaffolds the topology. ~200 LOC. Addresses the "what do I even drag" gap.

3. **FP Exception: history tab.** All generated exceptions get logged to zustand state (timestamp, log summary, strategy, scope, result, WAF). History tab in the wizard lets you see past ones, re-apply, delete. ~150 LOC. Addresses the "no bulk / no audit" gap.

4. **FP Exception: multi-format export.** Beyond raw JSON, offer CloudFormation, Terraform, and AWS CLI one-liner. Tabs in the Advanced section. ~200 LOC. Addresses the "dev-hostile output" gap.

5. **Better empty-canvas landing.** If no nodes exist, show a hero explaining what WAFSim does, with template CTAs. ~100 LOC. Addresses the "no landing" gap.

### QUEUED FOR rc.9.4

6. Import existing WAF from JSON/CloudFormation/Terraform.
7. Diff view on Compare tab.
8. TypeScript strict fixes in statementEvaluator + wafEngine.
9. Tooltip-style help layer across the UI.
10. Split zustand store into slices.

### QUEUED FOR rc.10+

11. Playwright e2e tests.
12. Accessibility audit + fixes.
13. Error boundaries + observability.
14. Bundle size budget.

---

## Design principles going forward

- **Empty state is a first-class state** — every screen should explain itself to a first-time user.
- **Ruthlessly compact copy** — no paragraph where a sentence works; no sentence where a label works.
- **Output format matches deployment reality** — if a user exports anything, offer it in the format they'll actually deploy with.
- **Verify before apply** — every destructive action shows before/after.
- **Local-first, cloud-optional** — workspace always persists locally; sharing is an explicit action.

---

## Open product questions (flagged for Apurva)

- Is there appetite for cloud sync? (Requires backend + auth.)
- Is there appetite for a free/paid tier split? (What would paid unlock?)
- Target launch milestones: YC Winter 2027 batch? If so, MVP needs feature freeze by Sep 2026.
- Is the internal AWS FalsePositiveAutomation integration (Yang Liu) still viable, or should we fully commit to the external product?
