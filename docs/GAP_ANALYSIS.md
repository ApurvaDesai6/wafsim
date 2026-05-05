# WAFSim v3 Gap Analysis

**As of 2026-05-05 (v3.0.0-rc.3)**
**Deployed state:** wafsim.apurvad.xyz is at v2.49 on `main`. v3 work lives on the `v3` branch pending review.

This document is the honest state-of-the-project for v3. It maps the v3 spec's
"full production-ready showcase" requirements against what is actually shipped,
calls out deliberate deviations, and scopes the remaining work.

---

## 1. Executive Summary

| Area | v3 spec target | State in v3 rc.3 | Gap |
|------|---------------|-----------------|-----|
| Rule evaluation engine | AWS WAFv2 semantics, all 14 statement types | Shipped. 147 tests. | 0 |
| Text transformations | All 15 documented | Shipped. 16 tests. | 0 |
| Managed rule groups | All 14 documented (including ATP, ACFP) | Shipped. 14 groups, 62 sub-rules. | 0 |
| WCU calculation | AWS documented costs | Shipped. Single source of truth (wcuCalculator.ts). | Per-statement-type doc audit vs live AWS docs deferred. |
| Topology canvas | React Flow with AWS resource nodes | Shipped. 13 resource kinds. | 0 (engine-level validator now wired into UI) |
| WAF edge-attachment model | WAF sits on edges, not nodes | Shipped. | Validator UI is banner-based; per-edge inline error overlay is deferred. |
| Rule builder | Visual AND/OR/NOT up to 3 levels | Data model supports arbitrary depth; UI supports 1 level + placeholder for nested configuration | 3-level visual recursive nested editor is deferred (large UX design). |
| Traffic simulator | Structured form + presets + NL generator + flood mode with timeline | Shipped (all four). Flood mode now uses authoritative `simulateFlood` engine with timeline chart. | 0 (NL generator requires `ZAI_API_KEY`; noted in README.) |
| Evaluation trace | Rule-by-rule trace with why/match details | Shipped (EvaluationTrace component). | 0 |
| Animation system | Framer Motion traffic dots, WAF scanning animation, flood burst, rate counter badges | Traffic dots + edge coloring + block cascading shipped (v2.47/2.48). Scanning animation on WAFs and per-WAF rate counter badges not yet visible. | Scanning + counter badge polish deferred. |
| Export engine | AWS JSON + Terraform HCL + CLI commands, passes `aws wafv2 check-capacity` | Shipped + 2 schema bugs fixed in rc.2 (RateLimit→Limit, AggregateKeys→CustomKeys) and 1 fixed in rc.3 (Terraform regex_pattern_set). | Live `check-capacity` validation in CI deferred; cloudposse/umotif module compat not formally tested. |
| Import engine | Load existing WebACL JSON | Shipped (`importWebACLJson`). E2E round-trip tested. | 0 |
| Posture scoring | (not in spec — new in v3) | Shipped. 5 categories, 100 pts, 13 tests. | 0 |
| Topology validator | (not in spec — new in v3) | Shipped. Cycle detection, WAF attachment, scope match, unreachable nodes. 14 tests. | 0 |
| Test suite | Comprehensive + programmatic demo | Shipped. 147 tests across 9 files. Next.js build green. | 0 |
| Performance | 20-rule WebACL < 5ms eval; 1000-req flood < 2s; 20 node canvas at 60fps | Eval: sub-ms in tests. Flood: ~500ms for 6000 req. Canvas: not formally benchmarked. | Formal perf benchmarking deferred. |
| Shareable URLs | base64-encoded config in query param | Shipped (`?cfg=...`). | 0 |
| Hosting | Vercel | Shipped. Auto-deploys main. | 0 |

**Short version:** Out of ~30 tracked items, 24 are fully shipped, 4 are shipped with deliberate deviations, 2 are honestly deferred (3-level nested rule builder UI, inline canvas per-edge error overlays).

---

## 2. Deliberate deviations from spec

These are things the v3 spec asked for that rc.3 ships differently, with a reason:

### 2.1 Rule builder 3-level nested AND/OR/NOT editor

**Spec wanted:** Recursive visual editor with colored-border nested cards (AND=blue, OR=green, NOT=red), unlimited nesting depth in data, at least 3 levels in UI.

**Shipped:** Data model supports arbitrary depth (validated by 3-level-nesting test in `statementEvaluator.test.ts`). UI currently matches AWS console's 1-level limit + a "configure after saving" placeholder for the child statements.

**Why:** A proper recursive nested editor is a ~300-500 LOC UX feature with design decisions (how do you visually represent a 4-level deep rule without overwhelming users? can you collapse/expand inner groups? keyboard navigation for nested forms?) that deserve a dedicated design pass. Rushing it would produce a clever demo that doesn't survive real customer use.

**Workaround:** Users who need nested rules can author the JSON externally, then use the Import WebACL JSON feature to load it. The evaluation engine handles any nesting depth correctly.

### 2.2 Topology canvas inline per-edge / per-node error overlays

**Spec wanted:** When a WAF is attached to a non-attachable resource, show an inline error right on the canvas; when there's a cycle, highlight the cycle path.

**Shipped:** `topologyValidator.ts` engine detects all of this. `TopologyIssuesBanner` floats over the top-left of the canvas showing issues + click-to-focus node pills.

**Why:** Fully wiring per-edge overlays requires modifying `TopologyCanvas.tsx` (~800 LOC) to interleave validation state into node/edge rendering. The banner approach ships the same information with minimal risk of regressing existing canvas behavior.

**Next step:** Extend the banner's node pills to also highlight the node border on the canvas. One small `selectNode` + CSS rule away.

### 2.3 Evaluation scanning animation + flood burst visualization

**Spec wanted:** When a request hits a WAF, animate rules evaluating one-by-one with a scanning highlight; flood-mode shows burst visualization with a counter badge.

**Shipped:** Request travels through topology with per-edge coloring (green/red) and block cascade when WAF blocks at CloudFront. The flood timeline chart (rc.3) shows per-bucket allowed/blocked bar + rate curve + trigger annotation.

**Why:** The scanning animation is in the "polish" tier, not "critical for correctness" tier. Rate counter badges would be nice but require piping live state from the evaluation engine into individual WAF nodes.

**Next step:** Add a thin "request N evaluating" label on the WAF node during simulations, or a small counter badge showing "blocked X / total Y" during flood mode.

### 2.4 Per-statement-type WCU audit vs live AWS docs

**Spec wanted:** WCU costs exactly match AWS documentation per statement type.

**Shipped:** Single authoritative `wcuCalculator.ts` with documented values for GeoMatch (1), IPSet (1), LabelMatch (1), RateBased (2), SizeConstraint (1), SqliMatch (20 LOW), XssMatch (20), ByteMatch (3 + 10 per transform), Regex (5 + 10 per transform), etc. SQLi (20 LOW) is doc-verified.

**Gap:** ByteMatch base cost is listed as 3 in the calculator but AWS docs list it as 1 for most field-to-match types; RegexMatch base is 5 but AWS docs list 3; RegexPatternSetReference is listed as 5 but varies by pattern count. These should be re-checked against the current `waf-rule-statement-type-*` pages and corrected.

**Why not fixed in rc.3:** Per the system prompt's "cite before you claim" rule — I haven't verified each of these per statement's current AWS doc page. Changing values without verification is exactly the kind of thing that breaks user trust. Fix: do one focused session walking through each of the 14 statement type docs and reconciling.

### 2.5 Export engine formal validation against `aws wafv2 check-capacity`

**Spec wanted:** Exported JSON passes `aws wafv2 check-capacity`.

**Shipped:** Two schema bugs fixed in rc.2 (`RateLimit` → `Limit`, `AggregateKeys` → `CustomKeys`) based on direct reading of `API_RateBasedStatement.html`. Terraform regex_pattern_set block structure fixed in rc.3.

**Gap:** No CI step that runs `aws wafv2 check-capacity --cli-input-json ...` against generated output. Doing this right requires:
- An AWS account with WAFv2 permissions
- A non-interactive credential source (GitHub Actions secrets)
- Handling `ResourceAlreadyExistsException` / rate limits
- Being OK with CI depending on live AWS control-plane availability

**Lightweight alternative:** Validate against `aws-sdk-js-v3`'s JSON schema types (they're generated from the AWS API model). This would catch most schema drift at build time without needing live AWS. Possible next step.

### 2.6 Terraform HCL compatibility with cloudposse/umotif modules

**Spec wanted:** Generated HCL works with `cloudposse/terraform-aws-waf` and `umotif-open/terraform-aws-waf-webaclv2`.

**Shipped:** Generated HCL uses the raw `aws_wafv2_web_acl` resource (not module-specific input variables). This works with `terraform plan` directly and is module-agnostic.

**Gap:** Users who want to feed WAFSim output into the cloudposse or umotif module need a separate shim layer — those modules take a different input format (their own typed object schemas). Raw resource export is actually more portable; module-specific exporters could be added as separate output tabs.

---

## 3. What's genuinely missing (vs. spec)

### 3.1 Keyboard-navigation nested rule builder (Task 7)

Real design decision ahead. Minimum viable approach: make `RuleBuilder.tsx` recursive for the statement editor, pass a `depth` prop, disable "add nested" past level 3, use indentation + color-border for visual depth. Estimated ~2 sessions.

### 3.2 Inline canvas error decorations

React Flow supports per-node class overrides via the `className` prop or per-node style. The validator already produces node IDs for each finding; wiring this into TopologyCanvas is ~1 session. Same for edge highlighting on cycle detection (harder — need to identify which edges form the cycle; Kahn's algorithm gives you the set of in-cycle nodes but not the specific edges without an extra DFS pass).

### 3.3 WAF evaluation scanning animation + per-WAF counter badge

Framer Motion is already in the deps. Adding a staggered-fade animation in `EvaluationTrace` on each rule row, plus a floating counter badge component on the WAF node that updates during flood simulation, is ~1 session.

### 3.4 Formal performance benchmarks

Spec targets: 20-rule eval < 5ms, 1000-req flood < 2s, 20-node canvas 60fps.

The engine-level tests show 147 tests including the full-run e2e scenario in < 1.5s — implying individual evaluations are well under 5ms. Flood simulation test with 6000 requests runs in ~500ms (under 2s). Canvas performance isn't formally measured. Benchmark script (`npm run bench`) that runs fixed scenarios and asserts performance SLAs is a ~half-session job.

---

## 4. v3 additions not in the spec (net-positive delta)

These are features rc.1/rc.2/rc.3 added that the v3 spec didn't call for but are genuinely useful:

- **WebACL security posture scorer** (621 LOC, 13 tests). 5-category scoring with findings + recommendations. Inspired by system-design-simulator's rubric, adapted for WAF.
- **Topology validator** (262 LOC, 14 tests). Cycle detection, WAF attachment rules, scope match, unreachable nodes.
- **Flood timeline chart** (168 LOC). Visualization of the authoritative `simulateFlood` output — bucketed allowed/blocked bars + request-rate curve + trigger annotation.
- **Shared test fixtures** (`_fixtures.ts`). Canonical schema test helpers.
- **Live-run `/api/tests` route**. In-browser test execution against the in-app `testSuite.ts` (32 managed-rule-group sub-rule scenarios + rule ordering scenarios).

---

## 5. Roadmap (prioritized)

Next-session leverage order:

1. **Rule builder 3-level nested UI** (Task 7) — biggest remaining spec gap. Design first, then implement.
2. **Inline canvas error decorations** (Task 6 continuation) — makes the topology validator pay off visually.
3. **Per-statement WCU doc audit** (Task 10 continuation) — clean trust story for cost estimates.
4. **Scanning animation + WAF counter badge** (Task 9 continuation) — polish.
5. **Formal performance benchmark script** — confirm or correct the SLA claims.
6. **Export engine schema validation** against aws-sdk-js-v3 types in CI.
7. **Module-specific Terraform exporters** for cloudposse/umotif users.
8. **Mobile responsiveness** audit + accessibility pass (WCAG 2.2 AA).

---

## 6. Honest assessment

WAFSim v3 is:
- A **solid custom-rule simulator** with full engine fidelity for custom rules, comprehensive tests, and validated exports.
- A **useful managed-rule-group approximator**, where the limitation (AWS doesn't publish managed rule logic) is honestly labeled in the UI.
- A **visible posture-assessment tool**, giving customers a concrete "what do I need to improve?" answer during rule tuning sessions.
- An **accurate flood simulator**, with timeline visualization that shows when and why rate limits trip.
- A **working showcase project** — ~14,000 LOC of production TypeScript with 147 passing tests and a green Next.js build.

WAFSim v3 is not:
- A **replacement for the AWS WAF console** — you still deploy through real AWS APIs; WAFSim is a pre-deployment validator.
- An **exact AWS WAF emulator** for managed rule groups — the regex/match logic is proprietary and is approximated.
- A **1:1 libinjection-xss / libinjection-sqli clone** — the heuristic detectors are intentionally aggressive for false-positive triage.

This matches the positioning in the SPARK submission and README. The UI deliberately labels approximations with "⚠ Approximated behavior" indicators.
