# Changelog

All notable changes to WAFSim are captured here.

## [3.0.0] — 2026-05-11

**v3 promotion to main.** Summary of what shipped across the v3 development cycle (rc.1 through rc.9.5) before promotion.

### Architecture & engine
- Extracted traffic-flow simulation into `src/engines/trafficFlowEngine.ts` with proper multi-attach handling (same WebACL protecting multiple resources was previously under-coloring downstream edges).
- Rate-based rule flood simulation with a timeline chart + override hook that feeds results into topology coloring.
- 14 statement types with COUNT vs terminating semantics, label propagation across rules.
- All 14 AWS Managed Rule Groups with per-sub-rule simulation criteria + accurate label namespaces.
- Posture scoring engine (5 dimensions × 20 points = 100) with per-dimension actionable findings.

### False-positive exception generator
- 5-step wizard (Paste → Review → Configure → Preview → Verify & Apply).
- 4 strategies: label-match (default, emits BLOCK+NOT for default-ALLOW WebACLs per AWS WAF Developer Guide canonical pattern), managed-group-exclusion, custom-allow-bypass, scope-down-statement.
- One-click prerequisite fixer (flips managed groups to COUNT mode when required).
- Rule context in Review shows what the terminating rule does by looking it up in the managed rule groups catalog.
- Automatic verification before apply: runs original blocked request + canned attack variant through the WAF before and after insertion, reports side-by-side. Insert button disabled unless both verify correctly.
- Multi-format export: AWS JSON, CloudFormation YAML, Terraform HCL, AWS CLI sequence.
- Persistent history tab with audit trail.

### Workspace UX
- Starting templates on empty canvas: ALB+EC2, CF+S3, APIGW+Lambda, multi-tier full stack, blank.
- Shareable state URLs (gzip + base64, ~2KB per typical workspace).
- Welcome overlay with template picker on fresh workspaces.
- Right-panel posture score when a WAF is selected; minimal "click a WAF" hint otherwise.

### Quality
- 210 tests across unit + integration + E2E layers.
- Workflow-level integration tests that exercise the full topology → simulate → export → verify path (these catch bugs that unit tests cannot).
- TypeScript strict mode mostly clean; 51 pre-existing errors in `statementEvaluator`, `NestedStatementEditor`, `importEngine`, `TopologyCanvas` flagged as tech debt in the handoff note.

### Removed from earlier drafts
- Always-on `TopologyIssuesBanner` — was net-negative noise, removed from UI. Engine kept for future opt-in integration.
- Aggregate fleet posture badge — showed non-actionable metrics, removed. Engine function stays for future re-integration.

### Correctness
- Label-match exception generator emits BLOCK+NOT for default-ALLOW WebACLs (self-contained, no downstream rule required to catch attacks) and ALLOW+AND for default-BLOCK WebACLs. Earlier versions emitted ALLOW+AND unconditionally which was unsafe for default-ALLOW because attacks fell through to default ALLOW.

### Deferred to post-v3
- Import existing WebACL from CloudFormation / Terraform (JSON import works today).
- Interactive multi-request verification in the Verify step.
- Before/after rule diff in the Preview step.
- AMR label namespace casing lookup table for derivation fallback.
- Visual identity pass distinct from the generic Tailwind/shadcn aesthetic.

---

## [3.0.0-rc.9] — 2026-05-08

**Three serious issues reported during Vercel testing of rc.8, all fixed, plus
the first integration-test layer that would have caught them, plus the
aggregate fleet posture score as a consumer-grade landing-view feature.**

### Fixed (the three bugs Apurva found on Vercel)

1. **Rate-based rule never fired because Run Flood targeted `wafs[0]`.**
   TrafficSimulator hardcoded `const activeWAF = wafs[0]` for the Flood tab.
   In a multi-WAF topology where the rate-rule WAF wasn't index 0, the
   flood silently ran against the wrong WAF. Floods of 600 req/300s
   against a 100/5min rate rule would report "threshold not hit" because
   they weren't actually hitting that rule.
   **Fix**: explicit Target WAF dropdown in the Flood tab, defaulting to
   whatever is selected in the right panel. Each WAF's attached rate-rule
   count is shown inline so users see what they're about to test. When a
   WAF has no rate rules, a yellow inline warning says "flood will only
   show regular rule behavior; nothing will rate-limit".

2. **Run Simulation (single-shot) silently can't trigger rate rules.**
   Topology `Run Simulation` evaluates each WAF once with ONE request.
   Rate-based rules require N requests in a time window — impossible
   to trigger in single-shot. Previously the UI showed ALLOW with no
   indication this was structurally impossible, leading users to think
   their WAF wasn't working.
   **Fix**: when the evaluated WAF contains any `RateBasedStatement`
   rules, the EvaluationTrace panel shows a blue banner: "N rate-based
   rules on this WAF. Single-request simulation can't trigger rate
   limits — switch to the Flood tab to test."

3. **Flood outcome didn't update the topology canvas.** Run Flood updated
   only the bottom-panel timeline chart. The canvas kept whatever edge
   coloring it had from a previous single-shot sim, producing the
   infamous "RED Allow with green connecting path" state — where the
   edge colors contradicted the displayed evaluation result.
   **Fix**: `simulateTrafficFlow` now accepts an optional
   `wafOutcomeOverrides: Map<wafId, {action, reason}>`. `handleFloodComplete`
   in page.tsx runs topology flow with the flood's final outcome as an
   override (tripped → BLOCK, not tripped → ALLOW) and updates
   `trafficEdges`/`wafResults` accordingly. Both `handleSimulate` and
   `handleFloodComplete` now clear stale topology state BEFORE running,
   so no previous coloring can linger into a new simulation.

### Added

- **`src/__tests__/integration/multiWafRateFlood.test.ts` (6 tests).**
  The integration tests that would have caught all three bugs above.
  Builds Apurva's exact scenario: 3 WAFs (ALB regional, APIGW regional,
  CloudFront with RBR 100/5min), CF WAF NOT in index 0. Verifies:
  - single-shot leaves CF green (expected — can't trip rate rules)
  - flood against CF trips at the correct load
  - override-based topology update colors CF downstream as blocked
  - flood against WAF_ALB (no RBR) does NOT trip
  - regional WAFs still block independently
  - state-consistency invariant: WAF with BLOCK action ⇒ outgoing
    protection edge is colored blocked (no "red WAF green edge" state)
  - override precedence: ALLOW override wins over default evaluation

- **`scoreWebACLFleet()` + `AggregatePostureBadge` component.** When the
  right panel has no specific WAF selected, it now shows an overall
  Fleet Security Posture score computed across all WebACLs in the
  topology. Per Apurva's feedback: "the smart security score should
  take everything into account if they have multiple webACLs and
  assess overall sec posture — a useful consumer value add feature."
  Includes:
  - Overall score (average of per-WebACL scores) + verdict
  - Four fleet-level findings that the per-WebACL scorer can't surface:
    1. **Unprotected resources** (ERROR) — WAF-attachable resources in
       the topology with no WebACL attached
    2. **Inconsistent IP reputation protection** (WARNING) — some
       WebACLs have the IP reputation managed group, others don't
    3. **Mixed default actions** (INFO) — WebACLs with different
       `defaultAction` (ALLOW vs BLOCK) across similar-facing resources
    4. **Mixed override modes for managed rule groups** (INFO) — same
       managed group in different override modes (COUNT vs NONE) across
       WebACLs, usually indicates incomplete A/B test rollout
  - Per-WebACL mini-cards showing each WAF's individual score + attached
    resources. Click any card to drill into that WAF.
  - Consolidated findings from all WebACLs, deduped by title, keeping
    the highest severity.
  - Tests in `src/__tests__/postureScorerFleet.test.ts` (8 tests) for
    aggregate math, dedup, and each fleet-level finding type.

### Changed

- **Topology validator: two finding types fixed + banner removed.**
  `WAF_DANGLING` previously fired when a WAF had no upstream OR no
  downstream. In WAFSim's side-attached-WAF model, WAFs never have
  upstream — they're attached to resources via a "protects" edge. The
  old rule fired on every well-formed WAF. **Fix**: WAF_DANGLING now
  only fires when a WAF has no downstream (not protecting anything).
  `UNREACHABLE_NODES` similarly flagged WAF nodes as unreachable since
  they're off the main traffic path; **fix**: excluded WAF nodes from
  the unreachable check. Per Apurva's feedback "the topology issues
  banner flags are all shit, remove it entirely unless massively
  improved", the always-on `TopologyIssuesBanner` component is no
  longer rendered in page.tsx. The engine + its 14 unit tests remain
  in place so a future release can gate findings behind an explicit
  "Validate Topology" button.

### Meta

The meta lesson from rc.8 → rc.9: **169 unit tests passing meant nothing
about whether user workflows worked**. All 169 tests validated pure
function correctness; zero tested the integration between flood sim,
topology sim, and UI state updates. Going forward, any claim of "N
tests passing" in a commit message should be paired with "including
integration test covering [specific user workflow]" or it's not a
credibility signal.

Test count: 183 (up from 169). Build green.

---

## [3.0.0-rc.7] — 2026-05-08

Critical bug fix + architectural refactor for traffic-flow simulation.

### Fixed
- **Multi-attach WAF traffic-flow bug**: when one regional WebACL protected
  multiple resources (e.g. the same WAF attached to both an ALB and an
  API Gateway), a SQLi attack against the topology would only color
  downstream-of-API-Gateway edges red; downstream-of-ALB stayed green even
  though the WAF should have blocked both paths. Root cause: inline
  `handleSimulate` in `page.tsx` used `Map<wafId, resourceId>` which
  overwrites on each iteration, so only the last-iterated protected
  resource saw the WAF evaluation.

### Changed — architectural refactor
- Extracted traffic-flow logic into `src/engines/trafficFlowEngine.ts`
  (233 LOC). Clean 4-step algorithm:
  1. Index topology (`normalChildren`, `wafExpansion` per WAF node).
  2. Evaluate every WAF for each of its protected resources
     independently (fixes the reported bug).
  3. BFS reachability treating directly-blocked resources as sinks
     (reachable themselves, don't propagate).
  4. Derive `edgeFlow` + `blockedNodes` from reachability + direct-blocked
     sets. Fan-in handled correctly — a node reachable via an alternate
     unblocked path is not over-blocked by a cascading parent.
- `page.tsx handleSimulate` reduced from ~130 lines of inline BFS to a
  delegating call to the new engine.

### Added tests
- `src/__tests__/trafficFlowEngine.test.ts` (6 tests):
  - Reported bug reproduction: one WAF protecting ALB + APIGW — both
    paths block on SQLi.
  - Benign request inverse (both paths pass).
  - Single-WAF-single-resource baseline.
  - Fan-out (ALB with 3 downstream backends).
  - Fan-in (S3 reachable via unblocked path AND blocked path — must
    not be over-blocked).
  - Entry-node detection.

Test count: **159** (up from 153 in rc.6). Build green.

### Remaining enterprise-grade work for future rc
Called out explicitly so expectations are clear:
- ALB target groups as first-class topology element.
- CloudFormation / CDK / Terraform plan IaC import — biggest feature.
- Dagre auto-layout for large imported topologies.
- AWS official icons + VPC/Subnet container grouping.
- Enterprise-scale fixture tests.

See `docs/GAP_ANALYSIS.md` for the full picture.

## [3.0.0-rc.6] — 2026-05-05

CHANGELOG entry omitted in rc.6 commit by accident — captured retroactively.

### Fixed
- Posture scorer was reading `statement.limit` but the canonical type is
  `rateLimit`. The +5 "reasonable rate limit" award was silently never
  firing on real WebACLs.
- FloodTimelineChart `bars` array was implicitly typed as `never[]`,
  causing cascading "Property X does not exist on never" errors in
  strict tsc. Fixed with explicit `Bar` type.

### Changed
- tsc strict errors down to 51 (from 57 on main at v2.49) — v3 is
  strictly better than main on type safety.

## [3.0.0-rc.5] — 2026-05-05

Animation polish — rule trace cards now fade in with a staggered scanning
effect, visualizing rule evaluation order as described in the v3 spec.

### Added
- **Staggered rule-scanning animation in EvaluationTrace**. Each rule
  trace card fades in with a small leftward offset and a per-index delay
  (capped at 600ms). Creates the "rules evaluating one-by-one" visual
  the v3 spec described, without needing separate animation state
  machinery. Uses Framer Motion which was already in the deps.

### Notes
- Remaining Task 9 polish items (per-WAF counter badge, WAF scanning
  highlight on the topology canvas) require deeper canvas integration
  and are documented as deferred in `docs/GAP_ANALYSIS.md`.

## [3.0.0-rc.4] — 2026-05-05

Nested rule builder UI + 3-level round-trip tests. This closes the last
significant UX gap from the v3 spec — visual AND/OR/NOT nested rule
authoring up to 3 levels deep.

### Added
- **NestedStatementEditor** (`src/components/NestedStatementEditor.tsx`,
  506 LOC). Recursive statement editor that handles simple statement types
  inline (ByteMatch, GeoMatch, IPSet, LabelMatch, SizeConstraint, RegexMatch)
  and recurses for compound AND/OR/NOT up to 3 levels deep. Visual depth
  is conveyed via colored left border per compound type (AND=blue,
  OR=emerald, NOT=red) and cycling depth tint. Add/remove controls per
  child. Type-switch dropdown preserves tree structure.
- **RuleBuilder integration**: the AND/OR/NOT cases now render
  NestedStatementEditor instead of the previous "configure after saving"
  placeholder. Users can author the full nested rule tree inline.
- **Nested statement round-trip tests** (`nestedStatements.test.ts`,
  6 tests): 3-level `(NOT geo) AND ((geo AND method) OR uri-contains)`
  rule is evaluated against 4 representative requests, exported to AWS
  WAFv2 JSON, imported back, and re-evaluated with identical results.
  The structural nesting depth is asserted in the exported JSON.

### Changed
- Test count grew to **153** (from 147 in rc.3).

### Notes
- Max nesting depth capped at 3 per the v3 spec UX recommendation. The
  underlying engine handles arbitrary depth (verified by
  `statementEvaluator.test.ts` which tests 3+ level nesting against the
  evaluator).
- Type-switching within the editor creates a fresh default statement of
  the new type — existing child configuration is intentionally lost on
  switch to avoid leaving orphaned invalid state.

## [3.0.0-rc.3] — 2026-05-05

Schema conformance fixes, flood simulator upgrade, topology validator UI
wire-in, and an honest v3 gap analysis doc.

### Fixed (export engine schema bugs)
- **`RateBasedStatement` field name**: was `RateLimit`, AWS API expects `Limit`.
  Verified against [API_RateBasedStatement.html](https://docs.aws.amazon.com/waf/latest/APIReference/API_RateBasedStatement.html).
  Any WebACL JSON exported from rc.1/rc.2 with a rate-based rule would have
  been rejected by `aws wafv2 create-web-acl`. Fixed now.
- **`RateBasedStatement` custom keys field**: was `AggregateKeys`, AWS API
  expects `CustomKeys`. Same source. Same impact. Fixed now.
- **Terraform `aws_wafv2_regex_pattern_set`**: was emitting a single
  `regular_expression` block containing multiple `regex_string` assignments
  (invalid HCL schema). Fixed to emit one block per pattern, per the
  Hashicorp provider schema.

### Added
- **TopologyIssuesBanner** (`src/components/TopologyIssuesBanner.tsx`).
  Floats over the canvas top-left, reads store state, runs `validateTopology`
  in memo, and shows findings with click-to-focus-node pills. Silent when
  the topology is clean, error/warning colored when issues exist.
- **FloodTimelineChart** (`src/components/FloodTimelineChart.tsx`, 168 LOC).
  Visualizes flood simulation output with stacked allowed/blocked bars,
  request-rate overlay line, trigger annotation, and per-bucket counters.
- **Real `simulateFlood` engine wired into TrafficSimulator's flood tab**
  (it previously used a hand-rolled `evaluateBatch` loop). Rate limiting now
  reflects the authoritative rate tracking semantics that match
  `wafEngine.ts`. Removed the "In Development" badge.
- **Export engine schema conformance test suite** (`exportEngine.test.ts`,
  14 tests). Covers all three schema bugs above plus CLI command sequence
  dependency ordering, IP set / regex pattern set JSON shape, and core
  WebACL JSON structure.
- **Rate engine tests** (`rateEngine.test.ts`, 6 tests). Verify
  `simulateFlood` produces an ordered timeline, detects trigger time,
  respects above/below-threshold traffic patterns, and reacts correctly to
  IP variation (distributed attack simulation).
- **`docs/GAP_ANALYSIS.md`**. Honest state-of-the-project assessment: what
  the v3 spec asked for, what shipped, deliberate deviations with
  justifications, and prioritized remaining roadmap.

### Changed
- Test count grew to **147** (from 127 in rc.2).
- `/api/tests` route and in-app help text now mention the posture score
  and topology validator features.

### Notes
- `main` still untouched at v2.49 (deployed at wafsim.apurvad.xyz). All
  rc.1/rc.2/rc.3 work is on the `v3` branch.
- See `docs/GAP_ANALYSIS.md` for explicitly-deferred work: 3-level nested
  rule builder UI, inline canvas error decorations, per-statement-type WCU
  doc audit, scanning animation polish, live `aws wafv2 check-capacity`
  CI validation.

## [3.0.0-rc.2] — 2026-05-05

Substantive engine + UX upgrade on top of rc.1. Inspired by patterns from
[system-design-simulator](https://github.com/vijaygupta18/system-design-simulator)
(5-category scoring, Kahn's topological sort, cycle detection) and
[bytedance/ns-x](https://github.com/bytedance/ns-x) (event-driven
packet/node/edge model).

### Added
- **WebACL security posture scorer** (`src/engines/postureScorer.ts`, 621 LOC,
  13 tests). Scores a WebACL across 5 dimensions (Coverage, Defense, Rate
  Limiting, Visibility, Hygiene — 20 points each, 100 total) and returns
  findings with severity + recommendation. Verdicts: *No Protection*,
  *Minimal*, *Basic*, *Solid*, *Strong*, *Defense in Depth*. Each category
  awards points for documented best practices and surfaces what's missing.
- **Topology validator** (`src/engines/topologyValidator.ts`, 262 LOC, 14
  tests). Pre-simulation static analysis that finds:
  - Cycles in the topology graph (Kahn's topological sort).
  - Invalid WAF attachment points (only CloudFront, ALB, API Gateway,
    AppSync, Cognito User Pool, App Runner, Verified Access — per AWS docs).
  - Scope mismatches (CLOUDFRONT-scope WAF on REGIONAL resource, or vice versa).
  - Dangling WAF nodes and dangling edges.
  - Unreachable nodes (no path from any Internet entry).
- **PostureScoreBadge component** (`src/components/PostureScoreBadge.tsx`).
  Compact 5-category breakdown badge, expands to show top findings with
  severity icons + recommendations. Wired into the right-panel WAF config
  view — selecting a WAF now shows its live posture score.
- **Extended vitest suite to 127 tests** (up from 68):
  - +13 posture scorer tests
  - +14 topology validator tests
  - +32 in-app testSuite scenarios (AMR sub-rule coverage + rule ordering)
    now run under vitest CI via `inAppSuite.test.ts`.

### Changed
- Help toast now lists all shortcuts accurately (`Ctrl/⌘+R` simulate,
  `Ctrl+E` export, `Ctrl+S` share) and mentions the new posture score feature.
- `/api/tests` route updated to use correct field names from `runAllTests`
  and to return structured sub-rule + ordering results.

### Notes
- Scorer deliberately opinionated and lenient: score < 20 means no WAF,
  60+ means basic protection, 80+ means production-appropriate, 95+ means
  defense-in-depth. Findings include explicit recommendations, not just
  a number.
- Topology validator runs in under 1 ms for graphs of up to 100 nodes —
  safe to run on every state change.
- Wider UI integration of the topology validator (inline errors on the
  canvas, badge on the top bar) is the next session's work; the engine is
  ready to wire in.

## [3.0.0-rc.1] — 2026-05-05

The v3 release is a stability + credibility pass on the v2.x foundation. Rather
than rebuilding already-working subsystems (topology canvas, rule builder,
traffic simulator, evaluation trace, export engine, animation, managed rule
group catalog — all shipped in v2.x), this release focuses on the gaps that
actually block production confidence: a real test suite, canonical-schema
fixtures, engine consistency, and honest documentation.

### Added
- **Real Vitest test suite** (`src/__tests__/`). 68 tests covering:
  - `wafEngine.ts` — default action, priority ordering, COUNT non-termination,
    ALLOW/BLOCK/CAPTCHA/CHALLENGE termination, label propagation across rules,
    duplicate priority/name validation, WCU reporting, batch evaluation, summary
    aggregation.
  - `statementEvaluator.ts` — ByteMatch (EXACTLY/STARTS_WITH/CONTAINS +
    LOWERCASE transformation), GeoMatch, IPSetReference (CIDR match + miss),
    LabelMatch, And/Or/Not including 3-level nesting (beyond what the AWS
    console allows), SizeConstraint GT/LT, SqliMatch classic `OR 1=1`,
    XssMatch `<script>` + `onerror`, RegexMatch, RegexPatternSetReference.
  - `textTransformations.ts` — NONE, LOWERCASE, URL_DECODE, HTML_ENTITY_DECODE
    (named/numeric/hex), COMPRESS_WHITE_SPACE, REMOVE_NULLS, REPLACE_NULLS,
    BASE64_DECODE, transformation priority ordering, compound pipeline.
  - `e2e-demo.test.ts` — full end-to-end scenario: WebACL with 6 mixed rules
    (AllowCorpToAdmin, BlockAdminAccess, BlockGeoCN, BlockSQLi, CountBadUA,
    BlockSuspiciousUALabel), IP sets + regex pattern sets, batch traffic,
    export-to-JSON + Terraform + CLI, JSON import round-trip.
- **Shared test fixtures** (`src/__tests__/_fixtures.ts`) matching canonical
  types in `src/lib/types.ts` so future test authors don't have to reverse
  engineer the schema.
- **`vitest.config.ts`** with `@/` path alias matching tsconfig, v8 coverage
  provider, html/json-summary reports.
- **`test`, `test:watch`, `test:ui`, `test:coverage`** npm/bun scripts.

### Changed
- **`wafEngine.ts`** no longer duplicates WCU calculation. `validateWebACL()`
  now delegates to the authoritative `wcuCalculator.ts`. Previously the
  engine's local `calculateRuleWCU` used simpler (and in some cases incorrect)
  base costs that diverged from the UI's WCU meter. Single source of truth now.
- **`MAX_WCU` / `BASE_TIER_WCU`** imported from `wcuCalculator.ts` into
  `wafEngine.ts` instead of being hardcoded.
- **`/api/tests` route** rewired to run `runAllTests()` from the existing
  in-app `testSuite.ts` (covers managed-rule-group sub-rules + rule ordering
  scenarios) instead of importing legacy stub files that returned empty
  results.
- **README** refreshed with v3 details, honest scope statements, and a new
  Testing section.
- **package.json** bumped to `3.0.0-rc.1`.

### Removed
- **`src/__tests__/engineTests.ts`** and **`src/__tests__/e2eTests.ts`** —
  legacy 86-byte stub files that returned hardcoded `{ passed: 0, failed: 0 }`.
  Replaced by real tests under the same directory.
- **Duplicate `calculateRuleWCU` function** in `wafEngine.ts` (~100 LOC). The
  authoritative implementation lives in `wcuCalculator.ts`.

### Known limitations (unchanged from v2.x, documented for v3)
- **AWS Managed Rule Group matching is approximated.** AWS does not publish the
  regex/match logic for managed rule groups. WAFSim models documented
  behavior (e.g., `NoUserAgent_HEADER` checks for absent User-Agent) and
  applies the documented label namespaces. Results for custom rules are exact.
  For managed rules, the UI surfaces an "Approximated behavior" indicator.
- **WCU base costs per statement type** in `wcuCalculator.ts` follow AWS docs
  for SQLi (20 LOW / 30 HIGH), GeoMatch (1), IPSetReference (1), LabelMatch
  (1), RateBased (2), SizeConstraint (1). Other values may drift from AWS
  docs as the service evolves — a per-statement-type doc audit is a
  follow-up item.
- **The XSS heuristic is intentionally aggressive** and will flag some benign
  HTML tags in request bodies. AWS's actual libinjection-xss implementation
  has its own false-positive characteristics; WAFSim's detector is a best
  effort and not a 1:1 clone. False-positive triage is the primary WAF
  support engineering use case — WAFSim helps customers see matches in
  context, not replace libinjection.

### Roadmap (not yet in v3)
These are documented for transparency and are not in-scope for 3.0.0-rc.1:
- Flood-simulation visual timeline (v2.x already does rate tracking under the
  hood; the spec's "scrolling timeline" UI view is still pending).
- 3-level visual nesting in the rule builder UI (data model already supports
  arbitrary depth; UI currently matches console's 1-level limit).
- `aws wafv2 check-capacity` online validation on export.
- Shareable-URL round-trip for full WebACL + IP sets + pattern sets (current
  implementation covers the core WebACL).
- Accessibility audit (WCAG 2.2 AA).

## [2.49] — 2026-04-07

Last v2.x release. See git log for incremental v2.x history.
