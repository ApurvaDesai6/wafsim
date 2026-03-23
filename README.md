# AWS WAFSim

Interactive AWS WAF rule simulator. Build, test, and validate WebACL configurations against real attack patterns before deploying to production.

**Live demo:** [wafsim.apurvad.xyz](https://wafsim.apurvad.xyz)

## What it does

WAFSim lets you configure AWS WAF rules in a visual environment and test them against simulated HTTP traffic without needing a live AWS environment. It evaluates rules using the same priority-based logic as the real WAF service, including:

- All 14 WAF statement types (ByteMatch, GeoMatch, SQLi, XSS, RateBased, IPSet, Regex, Size, Label, And/Or/Not, ManagedRuleGroup, RuleGroupReference)
- All 14 AWS Managed Rule Groups with per-rule simulation criteria
- Text transformations (URL_DECODE, LOWERCASE, HTML_ENTITY_DECODE, BASE64_DECODE, etc.)
- Rate-based rule evaluation with configurable windows (1/2/5/10 min)
- WCU calculation per rule and WebACL total
- Label propagation across rules
- COUNT vs terminating action behavior
- Export to AWS JSON, Terraform HCL, and CLI commands

## Architecture

```
Next.js 16 (App Router) + TypeScript + Tailwind CSS + shadcn/ui
├── src/engines/          # Core evaluation logic
│   ├── wafEngine.ts      # WebACL evaluation loop
│   ├── statementEvaluator.ts  # All 14 statement types
│   ├── fieldExtractor.ts # HTTP request field extraction
│   ├── textTransformations.ts # All transformation types
│   ├── sqliDetector.ts   # SQL injection pattern detection
│   ├── xssDetector.ts    # XSS pattern detection
│   ├── rateEngine.ts     # Rate-based evaluation
│   ├── wcuCalculator.ts  # WCU cost calculation
│   └── exportEngine.ts   # JSON/Terraform/CLI export
├── src/components/       # React components
│   ├── TopologyCanvas.tsx # ReactFlow-based AWS topology
│   ├── WAFConfigPanel.tsx # WebACL + rule configuration
│   ├── TrafficSimulator.tsx # Request builder + presets
│   ├── RuleBuilder.tsx   # Visual rule statement editor
│   ├── EvaluationTrace.tsx # Rule-by-rule evaluation results
│   └── WCUBudgetMeter.tsx # WCU usage visualization
├── src/store/            # Zustand state management
│   └── wafsimStore.ts    # Persisted app state
├── src/lib/
│   ├── types.ts          # Full WAFv2 type definitions
│   └── managedRuleGroups.ts # All 14 AWS managed rule groups
└── src/app/
    ├── page.tsx          # Main application layout
    └── api/              # API routes for NL generation
```

## Local setup

```bash
# Clone
git clone https://github.com/ApurvaDesai6/wafsim.git
cd wafsim

# Install (requires Bun)
bun install

# Dev server
bun run dev

# Production build
bun run build
bun run start
```

Requires [Bun](https://bun.sh) v1.0+. Node.js 20+ also works with `npm install && npm run dev`.

## Docker

```bash
docker build -f Dockerfile.generic -t wafsim .
docker run -p 3000:3000 wafsim
```

## Key features

**Visual topology** - Drag AWS resources (CloudFront, ALB, API Gateway, etc.) onto a canvas, connect them, and attach WAF WebACLs to WAF-compatible resources.

**Rule configuration** - Add custom rules (ByteMatch, Geo, IP Set, Regex, Size, SQLi, XSS, Rate) or one-click add any of the 14 AWS Managed Rule Groups. Drag to reorder priority.

**Traffic simulation** - Build test requests manually, use attack presets (SQLi, XSS, Log4Shell, path traversal, bot detection), or run batch tests against all presets at once.

**Evaluation trace** - See exactly which rules matched, in what order, what action was taken, and why. Includes transformed content and matched patterns.

**Sampled request log** - Every simulation run is logged in a table (like the real WAF console) showing method, URI, source IP, country, action, terminating rule, and labels. Click any row to replay.

**Export** - Export your WebACL as AWS JSON (for `aws wafv2 create-web-acl`), Terraform HCL, or AWS CLI commands.

## Motivation

Working as a cloud engineer on the AWS WAF team, I kept running into customers who needed to test and validate WAF rules outside of production but had no easy way to do it without a dedicated lab environment and deep AWS expertise. WAFSim aims to fill that gap.

## License

MIT
