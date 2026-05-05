# Changelog

All notable changes to WAFSim are captured here.

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
