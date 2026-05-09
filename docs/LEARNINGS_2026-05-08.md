# WAFSim v3 — Session Learnings (2026-05-08)

**Status:** rc.8 pushed. Apurva tested on Vercel and found three significant issues that the 169 "passing" tests did not catch. This document captures what's broken, why the tests missed it, and the concrete next steps to fix it properly.

---

## What Apurva reported

### Issue 1: Rate-based rule never fires on the topology

**Setup:** 3 WAFs — WAF_ALB (regional, attached to ALB), WAF_APIGW (regional, attached to API Gateway), WAF_CF (CLOUDFRONT scope, attached to CloudFront). WAF_CF has a rate-based rule with limit=100 over 5 minutes.

**Expectation:** Running a flood through the CF path should trigger the rate rule and visually show the CF path turning red on the topology.

**Observed:** CF path stayed green during flood. Flood tab bottom panel said "rate threshold not hit" even though 600 requests were sent over 300 seconds (6× the configured 100/5min limit).

### Issue 2: UI state inconsistency — "RED Allow with green connecting path"

**Observed:** After running a test, the topology showed an edge colored red but the node connected to it colored green, and the terminating action displayed as ALLOW. The edge color and the terminating action were in visual conflict.

### Issue 3: Topology validator banner flags things that aren't wrong

**Observed:** The TopologyIssuesBanner flags findings that are either false positives or not useful. Apurva's ask: "remove it entirely unless massively improved."

---

## Root causes (confirmed via code inspection)

### RC1 — Flood tab uses `wafs[0]`, not the WAF the user thinks it's testing

File: `src/components/TrafficSimulator.tsx` line 48

```typescript
const activeWAF = wafs.length > 0 ? wafs[0] : null;
```

`runFlood` then passes `activeWAF` to `simulateFlood`. So the flood always runs against the **first WAF in the array**, regardless of which WAF the user selected in the right panel or which resource they're floodin.

In Apurva's scenario, his CloudFront WAF (with the RBR) was probably NOT `wafs[0]` — it was created later. So the flood ran against a WAF that didn't have the rate-based rule, the rate never tripped, and the result was "rate threshold not hit". The topology didn't turn red because the flood output never feeds into topology coloring (see RC3).

**This is a UX lie**, not a subtle bug. The flood button says "Run Flood" and the panel says "simulate against rate-based rules" but it literally runs against the wrong rule.

### RC2 — "Run Simulation" cannot light up rate-based blocks because it's single-request

File: `src/engines/trafficFlowEngine.ts`, called from `src/app/page.tsx` line 144

```typescript
const result = evaluateWebACL(request, waf, { ... });
```

`simulateTrafficFlow` evaluates every WAF for each of its protected resources exactly **once** per button press. Rate-based rules require `requestCounts.filter(t > windowStart).length > limit` — i.e. many requests over a time window. A single request never exceeds a rate limit.

So: running the topology simulation against a WAF whose only blocking rule is a rate rule is architecturally guaranteed to show green. There is no path for the rate rule to trigger on a single request.

This is a legitimate architectural gap. The engines are correct in isolation; the UI's topology-coloring pipeline has no concept of flood simulation.

### RC3 — Flood tab and topology pipeline are unconnected

- `runFlood` in TrafficSimulator.tsx calls `simulateFlood` → updates `floodResult` → rendered by `FloodTimelineChart` in the bottom panel.
- `handleSimulate` in page.tsx calls `simulateTrafficFlow` → updates `trafficEdges` and `wafResults` → rendered on the canvas.
- **Neither one updates the other's state.**

So when Apurva ran a flood, `trafficEdges` kept whatever stale coloring it had from the previous single-shot simulation (which was ALLOW for the tested request). The bottom panel said "rate threshold not hit" (because of RC1). The canvas colored the CF path green (because of stale state + RC3, no flood-to-topology integration).

The "RED Allow with green node connecting path" from Issue 2 is almost certainly a leftover coloring from the previous simulation that wasn't cleared when the new action (ALLOW) was computed. The edge-flow map and evaluation result are two pieces of state that can get out of sync.

### RC4 — Tests validate engines in isolation, never workflows

169 tests pass. Every single one tests a pure function in a module. None of them test:

- A user clicking "Run Flood" and verifying the topology colors update to match.
- Multi-WAF topologies (3+ WAFs on different paths) with mixed rule types (custom + rate-based + managed) evaluated as a single flow.
- Stale-state handling when the user switches from single-shot to flood mode.
- UI state consistency (the displayed action matches the displayed edge colors).

This is a legitimate and embarrassing test-coverage gap. Apurva's "169X tests aren't testing shit" is a fair assessment of what those tests actually guarantee about user workflows.

### RC5 — TopologyIssuesBanner isn't sanity-checked against real user scenarios

The engine logic for the validator (`src/engines/topologyValidator.ts`) has 14 tests covering each individual rule (cycle detection, WAF attachment, scope match, dangling WAF, unreachable nodes). The tests are correct for the cases they cover.

But they don't exercise real user flows like: "user creates a WAF but hasn't connected it yet", "user is mid-building a topology", "user has multiple Internet entries". In those in-progress states the validator probably fires constantly with noise findings.

---

## What the tests should have been testing

### Workflow tests, not unit tests

At minimum:

1. **Multi-WAF rate-based simulation.** Build a topology with 3 WAFs. Put a rate-based rule on one of them (not `wafs[0]`). Run a flood. Verify the flood runs against the correct WAF, the rate rule triggers, and the topology edge coloring updates to show blocks on that WAF's path.

2. **Single-shot simulation with rate-based rule present.** Same topology. Click "Run Simulation" once. Verify the UI clearly indicates rate-based rules won't fire in single-shot mode — either a visible banner ("Rate-based rules require flood simulation mode"), or an explicit grayed-out state on rate-rule visualization.

3. **State clearing on simulation switch.** User runs Run Test (topology colors update), then runs Run Flood. Verify the topology colors are either updated to reflect the flood OR cleared entirely. Never stale.

4. **Consistency invariant.** Whatever terminating action is displayed in the EvaluationTrace panel, the edge coloring on the canvas must be consistent with it. If action is BLOCK, the edge leaving the WAF must be red. If action is ALLOW, that edge must be green. Runtime assertion worth adding.

5. **Topology validator real-scenario tests.** Build a topology the way a real user builds one (one node at a time, with partial connections in between). At each intermediate state, the validator should not be flagging findings that a reasonable user would consider wrong.

### Integration tests I should write

```typescript
// src/__tests__/integration/multiWafFlood.test.ts — doesn't exist yet
describe("Multi-WAF topology with CF rate-based rule", () => {
  it("flood against CF turns CF path red, regional paths stay green", () => {
    // Setup: 3 WAFs, different attachment points, RBR on CF-WAF only.
    // Simulate clicking Run Flood → verify topology state updates.
    // Specifically test that it runs against CF-WAF (not wafs[0]).
  });
});
```

None of the 169 tests look like this. All are engine-level.

---

## Step-by-step continuation plan (for next session)

### Step 1 — Fix RC1 (wrong-WAF flood) — 30 min

In TrafficSimulator.tsx:

- Replace `const activeWAF = wafs.length > 0 ? wafs[0] : null;` with a selector: let the user pick which WAF to flood against. Default to the WAF currently selected in the right panel (read from the zustand store's `selectedWAFId`).
- Add a UI dropdown labeled "Flood against WAF:" that lists all WAFs with their attachment point ("WAF on CloudFront", "WAF on ALB"). Default to the selected one.
- Add a regression test: build a fixture with 3 WAFs, confirm `runFlood` uses the selected one.

### Step 2 — Fix RC2 (single-shot hides rate-based rules) — 20 min

In `handleSimulate` (page.tsx) or EvaluationTrace:

- After simulation, if the WebACL contains any `RateBasedStatement` rule, show a banner: "Rate-based rules are not evaluated in single-request mode. Switch to Flood mode to test rate limiting."
- Optionally: mark the rate-based rule's trace entry as "skipped (single-shot mode)" instead of "did not match" so it doesn't look green.

### Step 3 — Fix RC3 (flood and topology don't talk) — 2-3 hours, biggest chunk

This is the real architectural fix.

- Extend `simulateTrafficFlow` to accept an optional `floodResult` and use its final state (who got blocked, who got allowed) to compute edge coloring. Specifically: if a rate-based rule tripped during the flood, the topology paths downstream of that WAF should be colored "partially blocked" (e.g. orange/yellow, with a count badge showing "48% blocked during flood").
- OR: make Run Flood directly call a new `simulateFloodOnTopology` engine function that walks the topology per-timestep and emits topology edge states as a time series. Bottom panel shows the final state; play/scrub animation shows the progression.
- Regardless of approach: every time Run Flood OR Run Test runs, clear prior `trafficEdges` state before updating, so no stale coloring.

### Step 4 — Fix RC5 (topology validator noise) — 1 hour

- Capture screenshots / video of Apurva's "this flags shit" scenario. Or ask him to share specific finding strings that were wrong.
- For each false-positive finding, either fix the validator logic or remove that rule entirely.
- Alternative: gate the banner behind a "Validate Topology" button (opt-in), so it's not constantly annoying users with findings while they're building.
- Acceptance criterion: in a typical mid-build topology (user has placed 5 nodes, connected 3 of them), the banner should show ≤ 1 finding — anything more is noise.

### Step 5 — Write the missing integration tests — 1-2 hours

- `src/__tests__/integration/multiWafRateFlood.test.ts` — the exact Apurva scenario. 3 WAFs, RBR on one, flood triggers, topology updates correctly.
- `src/__tests__/integration/stateConsistency.test.ts` — after every simulation action, assert the edge-flow map is consistent with the displayed action.
- `src/__tests__/integration/topologyValidator.real.test.ts` — simulate building a topology node-by-node and assert the validator doesn't spam at any intermediate state.

### Step 6 — Consider removing TopologyIssuesBanner entirely — 15 min

If Step 4 doesn't produce a clearly-useful banner, Apurva's original call to remove it is the right one. Deleting a feature that's net-negative is fine. Document it in CHANGELOG as "removed TopologyIssuesBanner — the findings weren't reliable enough to ship; validator engine is still available at `src/engines/topologyValidator.ts` for future re-integration".

### Step 7 — Ship as rc.9 with honest CHANGELOG — 15 min

- Don't call rc.9 "feature complete". Call it "bug fix + integration tests".
- CHANGELOG opens with "Three serious issues reported during Vercel testing. This release fixes all three and adds workflow-level integration tests that would have caught them."
- Update GAP_ANALYSIS.md to explicitly state: "Tests prior to rc.9 were engine-unit-level and did not catch simulation-pipeline integration failures. rc.9 adds the first integration test layer."

---

## Meta lesson

The feedback "16X tests aren't testing shit" is correct in the narrow sense: those tests validate pure engine correctness and not a single user-visible workflow. That's a test-coverage-shape problem. More unit tests wouldn't have caught these bugs; different tests would have.

For any future claim of "N tests passing", the right question is: **which of them would fail if I broke the rate-based-flood-on-the-topology user flow?** If the answer is zero, the test count isn't a credibility signal.

## Files to prioritize in next session

1. `src/components/TrafficSimulator.tsx` — fix wafs[0] selector
2. `src/app/page.tsx` — state clearing + rate-based-rule banner
3. `src/engines/trafficFlowEngine.ts` — accept flood state
4. `src/components/TopologyIssuesBanner.tsx` — reduce noise or delete
5. `src/__tests__/integration/*` — new directory, workflow tests
6. `CHANGELOG.md` — honest rc.9 framing
7. `docs/GAP_ANALYSIS.md` — add the integration-test-shape finding

## Commit this doc now

Session ran out of context budget to fix in-session. This doc captures enough that the next session can execute the plan mechanically.
