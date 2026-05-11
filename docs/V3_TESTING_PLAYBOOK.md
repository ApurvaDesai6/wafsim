# v3 Testing + Promotion Playbook

**Target:** decide whether `origin/v3` (currently at `v3.0.0-rc.6`) is safe to merge to `main` and therefore deploy to wafsim.apurvad.xyz via Vercel auto-deploy.

**Rule of thumb:** don't promote until you've done Phases 1, 2, 3, and 4 at minimum. Phase 5 (SME) is the go/no-go.

---

## Phase 0 — State of v3 as of rc.6

Automated checks (run these now to confirm they still pass):

```bash
cd /Users/apdesai/Downloads/Deploy/wafsim-v1
git checkout v3
bun install                    # if anything drifted
bun run test                   # expect 153/153 passing
bunx next build                # expect green
bunx tsc --noEmit 2>&1 | grep -c "error TS"   # expect 51 (down from 57 on main)
```

Current snapshot (2026-05-05, rc.6):
- 153/153 vitest tests green
- Next.js build green
- 51 strict-tsc errors (same categories as main; v3 is strictly ≤ main)
- Engine modules: wafEngine, statementEvaluator, textTransformations (15 types), managedRuleGroups (14 groups), wcuCalculator, exportEngine (+ 3 AWS API schema bugs fixed in rc.3), importEngine, rateEngine, postureScorer, topologyValidator
- UI new in v3: PostureScoreBadge, TopologyIssuesBanner, FloodTimelineChart, NestedStatementEditor, staggered rule-scanning animation
- All changes live on `origin/v3`; `main` untouched at v2.49

---

## Phase 1 — Local smoke test (15 min)

**Goal:** prove the app doesn't crash under routine use.

```bash
bun run dev     # http://localhost:3000
```

Walk through this checklist. All should work without console errors.

### A. Basic topology
- [ ] Page loads with default Internet → ALB → EC2 topology
- [ ] Drag each resource type from the left palette, drop on canvas, connect with edges
- [ ] **Topology Issues Banner** (top-left of canvas) shows either "Topology clean" (green) or findings with click-to-focus
- [ ] Delete a node — banner updates live

### B. WAF attachment
- [ ] Click an edge between Internet and ALB → "Attach WAF" button appears in right panel
- [ ] Click Attach WAF → WAF icon appears on the edge
- [ ] Click the WAF node → **PostureScoreBadge** appears above the rule list in the right panel (expects "Minimal" or "No Protection" since empty WebACL)
- [ ] Try to attach a WAF to an EC2 edge — **TopologyIssuesBanner shows WAF_INVALID_ATTACHMENT error** (red banner)

### C. Rule authoring
- [ ] Click "Add Rule" → RuleBuilder opens
- [ ] Add a simple rule (e.g. GeoMatch US → BLOCK). Save. Verify it appears in the config panel.
- [ ] **Nested AND/OR/NOT editor** — choose `AndStatement` for statement type. Click "Add child statement". Change child type to GeoMatch. Add another child (ByteMatch). Save. Reopen the rule — verify structure preserved.
- [ ] Nest a level deeper — inside the AND, add an OrStatement with 2 children. Save. Reopen. Structure preserved.
- [ ] Try to go 4 levels deep — the "Add child statement" button should be disabled / show "max depth reached".

### D. Traffic simulation
- [ ] Use a preset (e.g. SQL Injection Basic) → click Run. Verify result shows BLOCKED with terminating rule.
- [ ] **Scanning animation** — the EvaluationTrace panel rules should fade in top-to-bottom with a visible stagger (not all at once).
- [ ] Click Batch → run batch → verify table of preset results.

### E. Flood simulation
- [ ] Switch to Flood tab (in TrafficSimulator).
- [ ] Add a rate-based rule to the WebACL first (100 req / 5 min per IP).
- [ ] Set Flood config: 50 req/sec, 60 sec duration, 1 source IP. Click Run Flood.
- [ ] **FloodTimelineChart** renders: stacked allowed/blocked bars + rate curve + "Rate limit tripped at Xs" annotation.
- [ ] Re-run with 100 source IPs → expect fewer blocks (distributed).

### F. Export / Import
- [ ] Click Export → AWS JSON tab. Copy the JSON. Paste into a jq: `pbpaste | jq .Rules[0].Statement` — confirm fields use PascalCase (`ByteMatchStatement`, `FieldToMatch`, etc.).
- [ ] Copy CLI Commands. Verify the sequence: create-ip-set → create-regex-pattern-set → create-web-acl.
- [ ] Copy Terraform HCL. Verify it uses `aws_wafv2_web_acl`, `aws_wafv2_ip_set`, `aws_wafv2_regex_pattern_set`.
- [ ] Click Import WebACL → paste the JSON back → verify the topology + rules get recreated identically.

### G. Shortcuts + share
- [ ] Ctrl+R runs a simulation.
- [ ] Ctrl+E opens the export dialog.
- [ ] Ctrl+S copies a share link to the clipboard. Open it in a new tab — topology + rules restore.

Any failure in A–G is a blocker.

---

## Phase 2 — Export correctness (5 min, critical)

This is the one thing that **must** be right because customers will copy-paste into their AWS accounts.

Open a shell with AWS creds to an account where you can create WAFv2 resources (any non-prod account — your personal test account is perfect per `~/c/context.md`).

```bash
# Get a WebACL JSON from WAFSim — add a rate-based rule + a managed rule group first
# so we exercise the schema bug fixes from rc.3.
# Copy from the Export dialog → AWS JSON tab → save as /tmp/wafsim-export.json

aws wafv2 check-capacity \
  --scope REGIONAL \
  --rules "$(jq -c .Rules /tmp/wafsim-export.json)" \
  --region us-east-1
# Expect: { "Capacity": <number> }
# Any "ValidationException" is a schema bug that WAFSim generated — bug report.

# Optional: actually create the resources to confirm end-to-end validity
aws wafv2 create-ip-set --scope REGIONAL --region us-east-1 --cli-input-json file:///tmp/wafsim-ipset.json
aws wafv2 create-regex-pattern-set --scope REGIONAL --region us-east-1 --cli-input-json file:///tmp/wafsim-rps.json
aws wafv2 create-web-acl --cli-input-json file:///tmp/wafsim-export.json --region us-east-1
# Clean up afterward: aws wafv2 delete-web-acl / delete-ip-set / delete-regex-pattern-set
```

If `check-capacity` succeeds: v3 export engine is production-valid. If it fails with a `ValidationException`, capture the error and open a bug.

Optional Terraform validation (one-shot):

```bash
mkdir -p /tmp/wafsim-tf && cd /tmp/wafsim-tf
# Save Terraform HCL output to main.tf, then:
terraform init -backend=false
terraform validate
terraform fmt -check=true -diff  # confirms HashiCorp-idiomatic formatting
```

---

## Phase 3 — Regression check against v2.49 (10 min)

**Goal:** confirm v3 doesn't break anything that works on production today.

```bash
# Compare the two versions side by side
git checkout main
bun install && bun run dev   # runs on :3000
# Open http://localhost:3000 in browser tab 1

# Now in a second checkout or terminal:
git worktree add /tmp/wafsim-v3 v3
cd /tmp/wafsim-v3
bun install && bun run dev -- --port 3001
# Open http://localhost:3001 in browser tab 2
```

Checklist — do this in both tabs:

- [ ] Default topology renders identically
- [ ] Import a sample WebACL JSON → both tabs show same structure
- [ ] Load a share link → both tabs show same state
- [ ] Simulate the same preset (SQLi Basic) in both → same terminating rule, same final action
- [ ] Export the same configuration from both → diff the JSON

The v3 tab should show **additions** (posture badge, topology issues banner, nested editor, flood timeline, scanning animation) but **no subtractions** from v2.49's functionality.

```bash
# Diff the exports to confirm they're compatible
diff <(pbpaste < v249-export.json | jq -S .) <(pbpaste < v3-export.json | jq -S .)
# Expected differences: rc.3 fixed RateLimit→Limit + AggregateKeys→CustomKeys, so
# rate-based rules will differ. That's a fix, not a regression.
# Otherwise the two should be nearly identical.
```

Cleanup: `git worktree remove /tmp/wafsim-v3` when done.

---

## Phase 4 — Vercel preview deployment (5 min, shareable)

Vercel auto-deploys every push to any branch as a **preview deployment** with a unique URL. You've already pushed to `origin/v3` so the preview likely exists.

```bash
# Find the preview URL (easiest way)
open https://vercel.com/dashboard                   # browse your project
# Or: vercel ls wafsim                              # if vercel CLI installed
```

The preview URL looks like `https://wafsim-git-v3-apurvadesai6.vercel.app` (or similar). It runs the exact commit on `origin/v3` without touching the production domain.

Share this preview URL with stakeholders for review:
- **Yang Liu** (WAF SXO) — for authoritative WAF behavior check
- **Avi Rmani** / **Prasanj T** — for user-flow sanity
- **Andrew Stiller** (manager) — for go/no-go sign-off

Give them a test script (copy-paste from Phase 1 sections A–G above) so you get consistent feedback.

---

## Phase 5 — SME review (go/no-go)

Per the SPARK submission, SME review by Yang Liu was the gating step before customer-facing release. **Do not merge to main / expose customers to v3 without this.**

Draft the SME request message (Slack + email):

```
Hi Yang (+ team),

v3 of WAFSim is ready for your review. Live preview: <vercel preview URL>
Changes since v2.49 are listed at:
  https://github.com/ApurvaDesai6/wafsim/blob/v3/CHANGELOG.md
Gap analysis + honest state-of-project:
  https://github.com/ApurvaDesai6/wafsim/blob/v3/docs/GAP_ANALYSIS.md

Key things worth spot-checking from a WAF correctness perspective:
1. Fixed 3 AWS API schema bugs in export (RateLimit→Limit, AggregateKeys→
   CustomKeys, Terraform regex_pattern_set block structure). Worth running
   `aws wafv2 check-capacity` against an exported WebACL.
2. Posture scorer: 5-category opinionated rubric. Is the rubric
   aligned with what you'd tell a customer in rule tuning?
3. Topology validator: does the WAF-attachment rule set match what
   you'd want to warn customers about?
4. Nested AND/OR/NOT UI: up to 3 levels per v3 spec. Does the UX
   match the AWS console mental model for customers you work with?

Happy to walk through any of it on a call. Targeting [DATE] for merge
to main + wafsim.apurvad.xyz refresh, assuming no blockers.

Apurva
```

Specific SME acceptance criteria:
- [ ] `aws wafv2 check-capacity` succeeds against the export (Phase 2)
- [ ] At least one experienced WAF engineer has clicked through A–G in Phase 1
- [ ] Posture scoring rubric doesn't contradict AWS WAF best practices guidance
- [ ] No "this would confuse a customer" objections in the UI

---

## Phase 6 — Promotion to main

**Only after** Phases 1–5 succeed.

Vercel auto-deploys from `main`. Merging v3 → main will immediately refresh wafsim.apurvad.xyz.

**Safe merge workflow:**

```bash
cd /Users/apdesai/Downloads/Deploy/wafsim-v1
git checkout main
git pull origin main
git merge --no-ff v3 -m "Merge v3.0.0-rc.6 to main

Consolidated v3 work from rc.1 through rc.6:
- Real 153-test vitest suite
- Posture scorer (5-category WebACL scoring)
- Topology validator (cycle + attachment + scope)
- 3-level nested rule builder UI
- Flood simulation timeline chart
- 3 AWS API schema bug fixes (RateLimit, CustomKeys, TF regex blocks)
- Staggered rule-scanning animation
- Gap analysis doc + expanded CHANGELOG

See CHANGELOG.md for per-release details."

# Retag v2 state in case of quick rollback need
git tag v2.49-pre-v3-merge aedf3d3c   # the last main commit before the merge

# Push
git push origin main
git push origin v2.49-pre-v3-merge

# Finalize v3.0.0 (drop the -rc suffix)
git tag -a v3.0.0 -m "v3.0.0 — merged to main"
git push origin v3.0.0
```

Vercel picks up the push within ~30 seconds and builds. Watch the deployment:

```bash
open https://vercel.com/dashboard
# Or tail logs: vercel logs wafsim --follow
```

Once Vercel marks the deployment as Ready, spot-check wafsim.apurvad.xyz:
- [ ] Loads the default topology
- [ ] Version string in footer / about shows v3.0.0 (if you surface it)
- [ ] One full cycle: attach WAF → add rule → simulate → export. No console errors.

---

## Phase 7 — Rollback plan (in case of fire)

If wafsim.apurvad.xyz is broken within 15 min of the v3 merge:

```bash
# Option A: revert the merge commit. Fast, preserves history.
git checkout main
git revert -m 1 <merge-commit-sha>
git push origin main
# Vercel auto-rebuilds from the revert → site back to v2.49 behavior.

# Option B: reset main to the pre-merge tag (force push — destructive).
# Only do this if Option A doesn't work cleanly.
git checkout main
git reset --hard v2.49-pre-v3-merge
git push --force-with-lease origin main
# NEVER use --force without --force-with-lease.
```

Or, from the Vercel UI: find the last green `main` deployment and click "Promote to Production". Takes ~10 seconds.

---

## Promotion decision matrix

| Condition | Action |
|-----------|--------|
| All Phase 1 smoke tests pass | Proceed to Phase 2 |
| `aws wafv2 check-capacity` succeeds on exported JSON | Proceed to Phase 3 |
| No Phase 3 regressions vs v2.49 | Proceed to Phase 4 (Vercel preview) |
| ≥ 1 SME approves, no WAF correctness objections | Proceed to Phase 6 (merge) |
| Any of the above fails | **STOP**. File a specific bug. Iterate on v3 branch (v3.0.0-rc.N+1). |

---

## What honestly "Not Ready for Main" looks like

These are signals you should NOT promote today, even if the tests all pass:

1. You haven't actually clicked through the UI and exercised the new features yourself (Phase 1). The tests validate engine behavior; they can't validate UX.
2. You haven't run `check-capacity` against a realistic export (Phase 2). The tests validate my test fixtures, not real AWS API acceptance.
3. The SPARK SME review (Yang Liu et al.) hasn't happened. The project was scoped to require this.
4. The rc.6 branch has been untouched for < 24 hours. Customer-facing releases deserve at least a day of "use it yourself" before deployment.
5. You're about to go to sleep / head to an offsite / be unavailable for 6+ hours. Never promote a customer-facing release right before being unavailable for rollback.

## What "Ready for Main" looks like

All of:
- Phase 1–5 complete
- Preview URL has been opened by at least 2 non-Apurva reviewers
- `check-capacity` passed
- CHANGELOG + GAP_ANALYSIS have been read by a reviewer (so unknowns-unknowns are flagged)
- You have 2+ hours of availability to watch the deployment + handle a rollback if needed
