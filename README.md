# AWS WAFSim

Interactive AWS WAF rule simulator. Build, test, and validate WebACL configurations against real attack patterns before deploying to production — all in the browser, no AWS account required.

**Live demo:** [wafsim.apurvad.xyz](https://wafsim.apurvad.xyz)
**Source:** [github.com/ApurvaDesai6/wafsim](https://github.com/ApurvaDesai6/wafsim)

---

## What it does

WAFSim lets you configure AWS WAF rules in a visual environment and test them against simulated HTTP traffic without needing a live AWS environment. It evaluates rules using the same priority-based logic as the real WAF service, including:

- All 14 WAF statement types (ByteMatch, GeoMatch, SQLi, XSS, RateBased, IPSet, Regex, Size, Label, And/Or/Not, ManagedRuleGroup, RuleGroupReference)
- All 14 AWS Managed Rule Groups with per-rule simulation criteria
- 15 WAF text transformations (URL_DECODE, LOWERCASE, HTML_ENTITY_DECODE, BASE64_DECODE, COMPRESS_WHITE_SPACE, REMOVE_NULLS, and more)
- Rate-based rule evaluation with configurable windows (1 / 2 / 5 / 10 min) and timeline-based flood simulation
- WCU calculation per rule and WebACL total, against the 1,500 / 5,000 WCU AWS tier thresholds
- Label propagation across rules — rules later in priority order can match labels applied by earlier rules
- COUNT vs terminating action semantics (COUNT does not terminate; ALLOW / BLOCK / CAPTCHA / CHALLENGE all terminate)

Beyond core rule evaluation, v3 adds:

- **Starting templates** — 5 scaffolded scenarios (ALB+EC2, CF+S3, APIGW+Lambda, full multi-tier stack, blank)
- **Shareable state URLs** — encode your workspace into a URL for sharing with teammates
- **False-positive exception generator** — 5-step wizard: paste a blocked-request log, pick strategy + scope, preview the generated rule, verify against attack variants, apply to the WebACL
  - 4 strategies: label-match (default), managed-group-exclusion, custom-allow-bypass, scope-down-statement
  - One-click prerequisite fixer: sets the managed group to COUNT mode when required
  - Multi-format export: AWS JSON, CloudFormation YAML, Terraform HCL, AWS CLI one-liner template
  - Persistent history with audit trail (timestamp, strategy, scope, trigger URI, verification result)
- **Posture scoring** — per-WebACL security score across 5 dimensions (Coverage, Defense, Rate Limiting, Visibility, Hygiene) with actionable findings
- **Export to deployable IaC** — AWS JSON (`aws wafv2 create-web-acl`), Terraform HCL (`aws_wafv2_web_acl` resource), full CLI command sequence
- **Import** — paste an existing WebACL JSON to populate the visual builder

---

## Who it's for

- **AWS support engineers and solutions architects** troubleshooting false-positive and false-negative cases — WAFSim gives a shared, interactive artifact to walk customers through rule evaluation order instead of asynchronous log analysis.
- **AWS customers without a dedicated WAF test environment** — validate rule changes against known attack patterns before pushing to production.
- **Anyone learning how AWS WAF rules actually evaluate** — the evaluation trace shows rule-by-rule what matched, what didn't, and why.

---

## Tech stack

- **Next.js 16** (App Router) + **React 19** + **TypeScript** (strict)
- **Tailwind CSS 4** + **shadcn/ui** components
- **React Flow** (`@xyflow/react`) for the topology canvas
- **Framer Motion** for traffic animations
- **Zustand** for state + localStorage persistence
- **Vitest** for unit + E2E tests
- **Bun** for install / dev / build (Node 20+ also supported)
- Deploys to **Vercel**

All rule evaluation runs client-side — no backend compute, no AWS API calls during simulation.

---

## Local setup

```bash
git clone https://github.com/ApurvaDesai6/wafsim.git
cd wafsim

bun install
bun run dev        # http://localhost:3000
bun run build      # production build
bun run test       # run test suite
```

Requires [Bun](https://bun.sh) v1.0+. Node.js 20+ also works with `npm install && npm run dev`.

### Docker

```bash
docker build -f Dockerfile.generic -t wafsim .
docker run -p 3000:3000 wafsim
```

---

## Testing

WAFSim v3 ships with a full Vitest suite under `src/__tests__/`:

```bash
bun run test           # one-shot: run all tests
bun run test:watch     # watch mode
bun run test:ui        # Vitest UI
bun run test:coverage  # with v8 coverage report
```

The suite covers:

- **`wafEngine.test.ts`** — WebACL evaluation loop: default action, priority ordering, COUNT semantics, ALLOW/BLOCK/CAPTCHA/CHALLENGE termination, label propagation, duplicate priority/name validation, batch evaluation.
- **`statementEvaluator.test.ts`** — every statement type with documented matching semantics. Verifies 3-level AND/OR/NOT nesting works (beyond console's 1-level UI limit).
- **`textTransformations.test.ts`** — all 15 text transformations + transformation ordering by priority + compound pipelines (URL_DECODE → LOWERCASE → COMPRESS_WHITE_SPACE).
- **`e2e-demo.test.ts`** — end-to-end scenario: 6-rule WebACL with IP sets + regex pattern sets, mixed traffic batch, full export → Terraform + CLI + JSON → import round-trip.

Shared fixtures in `src/__tests__/_fixtures.ts` match canonical types so future test authors don't need to reverse-engineer the schema.

Additionally, the app exposes a live `/api/tests` endpoint that runs the in-app `testSuite.ts` (managed-rule-group sub-rule coverage + rule-ordering scenarios) for quick browser validation.

---

## Project structure

```
src/
├── app/
│   ├── page.tsx              Main topology + config workspace
│   ├── layout.tsx
│   └── api/
│       ├── generate-test-request/  NL → HttpRequest (Claude)
│       ├── explain-rule/           Rule match explanation (Claude)
│       └── tests/                  Live in-browser test runner
├── engines/                  All WAF evaluation logic
│   ├── wafEngine.ts          Core WebACL evaluation loop
│   ├── statementEvaluator.ts All 14 statement types
│   ├── textTransformations.ts All 15 transformations
│   ├── fieldExtractor.ts     HTTP request field extraction
│   ├── sqliDetector.ts       SQL injection detection heuristic
│   ├── xssDetector.ts        XSS detection heuristic
│   ├── rateEngine.ts         Rate-based rule evaluation
│   ├── wcuCalculator.ts      WCU calculation (authoritative)
│   ├── exportEngine.ts       JSON / Terraform / CLI export
│   ├── importEngine.ts       WebACL JSON import
│   └── testSuite.ts          In-app managed-rule-group tests
├── components/
│   ├── TopologyCanvas.tsx    React Flow canvas with AWS nodes
│   ├── WAFConfigPanel.tsx    WebACL + rules + priorities
│   ├── RuleBuilder.tsx       Visual AND/OR/NOT statement editor
│   ├── ResourceManager.tsx   IP sets + regex pattern sets
│   ├── TrafficSimulator.tsx  Request builder + presets + NL
│   ├── TrafficAnimation.tsx  Framer Motion traffic dots
│   ├── EvaluationTrace.tsx   Rule-by-rule evaluation trace
│   ├── QuickLoadPresets.tsx  Pre-built topology templates
│   └── WCUBudgetMeter.tsx    Live WCU usage bar
├── lib/
│   ├── types.ts              Full WAFv2 type definitions
│   └── managedRuleGroups.ts  All 14 AWS Managed Rule Group models
├── store/
│   └── wafsimStore.ts        Zustand store
└── __tests__/                Vitest suite (see Testing above)
```

---

## Key features in detail

**Visual topology** — Drag AWS resources (CloudFront, ALB, API Gateway, AppSync, Cognito, EC2, ECS, Lambda, S3) onto a canvas and connect them. Attach WAF WebACLs to WAF-compatible resources (CloudFront, ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access). Invalid attachment points are rejected with an explanation.

**Rule configuration** — Build custom rules (all 14 statement types) with a visual AND/OR/NOT editor. Add any of the 14 AWS Managed Rule Groups with one click. Drag to reorder priority. WCU meter updates live as you edit.

**Traffic simulation** — Build test requests manually (protocol, method, URI, headers, query, body, source IP, geo), use attack presets (SQLi, XSS, Log4Shell, path traversal, bot detection), or batch-test all presets against the current configuration. Natural-language traffic generator available when `ZAI_API_KEY` is configured.

**Evaluation trace** — See exactly which rules matched, in what order, what action was taken, what labels were applied, and the transformed content that matched each byte-level statement.

**Sampled request log** — Every simulation is logged in a table (mirroring the real WAF console) with method, URI, source IP, country, action, terminating rule, and labels. Click any row to replay.

**Export + Import** — Export the current WebACL as AWS JSON (for `aws wafv2 create-web-acl`), Terraform HCL, or a full CLI command sequence (IP sets + regex pattern sets + WebACL, in dependency order). Paste an existing WebACL JSON to populate the visual builder — the "load from prod" workflow.

---

## Limitations

- **AWS Managed Rule Groups are approximated.** AWS does not publish the regex/match logic for managed rule groups, so WAFSim models the documented behavior (e.g., `NoUserAgent_HEADER` checks for absent User-Agent) and applies the documented label namespaces. For custom rules the evaluation is exact. For managed rules, the UI displays an "Approximated behavior" indicator.
- **The XSS and SQLi heuristics are not 1:1 with AWS's libinjection implementation.** WAFSim's detectors lean aggressive to surface potential matches for support engineers. False-positive triage is the primary use case, not replacing libinjection.

See [CHANGELOG.md](./CHANGELOG.md) for the full limitation list and roadmap items deferred out of v3.

---

## Motivation

Working with AWS customers on WAF rule tuning kept running into the same wall: customers needed to validate rules outside of production but had no easy way without a dedicated lab environment and deep AWS expertise. WAFSim aims to fill that gap for both customers and the support engineers helping them.

## License

MIT
