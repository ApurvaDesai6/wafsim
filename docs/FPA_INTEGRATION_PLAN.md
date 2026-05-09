# FalsePositiveAutomation Integration Plan

**Status: DRAFT** — pending confirmation from Yang Liu (WAF SXO) on what FalsePositiveAutomation exposes and how it's meant to be consumed by downstream tools.

This document is the contract and shim design so that when the internal details land we can integrate in hours, not weeks. It also documents what WAFSim already does today so there's no ambiguity about division of labor.

## What WAFSim does today (v3.0.0-rc.8)

Shipped in `src/engines/exceptionGenerator.ts` + `src/lib/wafLogParser.ts`:

- **Parse a WAF log** — accepts both the GetSampledRequests shape (from the WAF console's Sample Requests tab) and the full Kinesis Firehose log shape (from production WAF logging to S3).
- **Generate a structured exception rule** from a single blocked request, with three strategies:
  - `LABEL_MATCH_EXCEPTION` (preferred): `AND(LabelMatch(rule-emitted-label), scope-down-match)` → ALLOW. Runs AFTER the labeling rule so the label is present. Assumes the labeling rule is in COUNT mode.
  - `MANAGED_GROUP_EXCLUSION`: adds the offending sub-rule to the managed group's `ExcludedRules` list. Blunt — disables the sub-rule globally.
  - `CUSTOM_ALLOW_BYPASS`: high-priority custom ALLOW scoped by URI pattern + IP allowlist. Flags missing IP allowlist as CRITICAL.
- **Scope selection** — EXACT (specific URI+query), SAME_PATH (path only, any query), SAME_ENDPOINT (prefix of first two segments).
- **Round-trip verification** — insert the generated exception into the WebACL, re-run the evaluation engine against the original blocked request to confirm it ALLOWs, and re-run against attack variations to confirm they still BLOCK. This is the acceptance test every generated exception should pass before export.

## What FalsePositiveAutomation likely does (educated guess — to confirm)

Based on the name and WAF team context, the internal tool probably:

1. Ingests WAF CloudWatch logs (or S3 logs) at scale.
2. Identifies false-positive patterns across many customer accounts.
3. Maintains a database of known false-positive signatures (e.g. "`${jndi:` in the Authorization header is a common false positive for customers using a CMS plugin with that name").
4. Possibly auto-generates and deploys exceptions into customer WebACLs via internal SupportOps workflows.
5. Is invoked by support engineers via a ticket workflow, not directly by customers.

The exact API, access model, and data schema need confirmation. Questions to ask Yang:

1. Is FalsePositiveAutomation a hosted service with a queryable API, or a CLI / script run against specific customer accounts?
2. What's the input shape — does it take a WAF log directly, or just a customer account + WebACL ARN + time window?
3. What's the output shape — a JSON exception rule? A delta to apply to the WebACL? A ticket with remediation steps?
4. Is it customer-account-aware? If so, how does cross-account access work (same IAM roles as other SupportOps tools?)?
5. Does it maintain a knowledge base of known FP patterns that WAFSim could surface as "similar known issues"?
6. Is there an OKR / tracking metric it reports into that WAFSim integration could contribute to?
7. Is there a Public-API-ready export that could be published externally, or does the integration need to stay internal-only?

## Proposed integration shim (to build once the internal details land)

```typescript
// src/integrations/falsePositiveAutomation.ts

export interface FpaRequest {
  wafLog: ParsedWafLog;
  customerAccountId?: string;   // optional — for customer-aware lookups
  webAclArn?: string;           // optional — for same-WebACL pattern matching
  region: string;
}

export interface FpaResponse {
  ok: boolean;
  /** Known FP pattern this matches, if any. */
  knownPattern?: {
    id: string;
    description: string;
    affectedCustomerCount: number;
    recommendedStrategy: ExceptionStrategy;
    seenBefore: boolean;          // for this specific customer
  };
  /** FPA-generated exception rule (if it auto-generates). */
  suggestedException?: {
    rule: Rule;
    rationale: string;
    confidence: "HIGH" | "MEDIUM" | "LOW";
  };
  /** Internal ticket URL for human review, if auto-deployment isn't in scope. */
  ticketUrl?: string;
  error?: string;
}

export interface FalsePositiveAutomationClient {
  lookup(req: FpaRequest): Promise<FpaResponse>;
}
```

The shim would be a small wrapper around whatever FPA exposes (HTTP API, SDK, CLI), translated into the interface WAFSim consumes. WAFSim's UI flow would then be:

1. User pastes a WAF log into the Exception Generator panel.
2. WAFSim's local heuristic generator produces three candidate exceptions (one per strategy).
3. **If FPA is configured and reachable** (internal build only), query it: does this match a known pattern? Does FPA have a higher-confidence suggestion?
4. UI shows: "WAFSim suggestion" (heuristic) + "FPA match: known pattern affecting N customers" (if available) + "FPA suggested exception" (if available) side-by-side.
5. User picks one, previews the resulting WebACL, simulates, and applies.

This design means:
- Public WAFSim keeps working without FPA (no hard dependency).
- Internal WAFSim with FPA configured surfaces richer intelligence and avoids re-inventing exception patterns the WAF team already knows.
- FPA remains the source of truth for the knowledge base; WAFSim is the structured authoring + verification UI.

## What WAFSim could contribute back to FPA

If the integration becomes bidirectional:

- Every exception a user crafts in WAFSim + the WAF log that triggered it is a labeled false-positive training example. With explicit opt-in (WAFSim's BYOK / internal-tool mode), we could send `{wafLog, chosenException, userWhyChoseIt}` back to FPA's knowledge base.
- Simulation-verified exceptions — i.e. we re-ran the WebACL with the exception and confirmed (a) the original blocked request now passes, (b) a targeted attack variant still gets blocked — are higher-quality than raw pattern matches.
- Anonymized aggregates (which managed rule sub-rules see the most FP exceptions?) could help the WAF service team prioritize regex tuning upstream.

## AI-enhanced exception generator (BYOK mode)

Separate from FPA. Runs in public WAFSim with a user-supplied Anthropic API key:

- Input: a WAF log + natural-language scope intent from the user (e.g. "allow iframes embedded from youtube.com and vimeo.com; block everything else").
- Model (Claude Sonnet 4.5 or later): outputs a Rule JSON matching the `Rule` type. The prompt is heavily constrained: "output only valid JSON, no prose, follow the label-based pattern from the AWS WAF Developer Guide".
- Validation: strict schema check. Reject + fall back to heuristic on any deviation.
- Security: API key provided via request header, never logged, never committed. When in public WAFSim mode, a prominent disclosure: "this request is sent to Anthropic's API — do not paste customer data".

## Timeline

- **Week 0 (now)**: WAFSim heuristic generator shipped in rc.8. Usable internally without any FPA integration.
- **Week 1**: Apurva confirms FPA surface with Yang. This doc becomes concrete.
- **Week 2**: Ship the integration shim with a feature flag (`FPA_ENDPOINT` env var). Internal users get the enriched experience; public users see just the heuristic.
- **Week 3**: Ship the BYOK AI-enhanced generator (independently of FPA). Feature-flag it too so it's opt-in.
- **Week 4+**: Bidirectional — WAFSim contributes verified FP/exception pairs back to FPA's knowledge base, with opt-in.

## Owner / next action

- Apurva Desai (apdesai) — WAFSim side, shipping heuristic + LLM paths.
- **OPEN: reach out to Yang Liu (yangliuz)** to confirm FPA surface + integration appetite.
