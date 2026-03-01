# PHANTOM Status — 2026-03-01 08:50 CST

## Demo Mode: READY ✅

### Demo scan command (< 3 min wall-clock):
```bash
curl -X POST https://drpod--osint-recon-fastapi-app.modal.run/scan \
  -H "Content-Type: application/json" \
  -d '{"seed":{"type":"username","value":"torvalds"},"demo_mode":true}'
```

### Verified demo_mode timings:
| Seed       | Nodes | Time  | Notes |
|------------|-------|-------|-------|
| torvalds   | 103   | ~134s | 103 platform profiles |
| antirez    | 60    | ~134s | breach data, domains |
| gvanrossum | 38    | ~157s | full report |
| simonw     | 243+  | ~225s | 2 usernames, email, subdomains |

### What demo_mode does:
- max_depth=1, max_entities=50, timeout=3 min, 8 planner turns max
- Skips GPU post-processing (eliminates 120s cold-start)
- Turn-0 blast: resolve_github + enumerate_username + resolve_social launch
  in parallel BEFORE first planner LLM call, results harvested before turn 1
- Planner gets RESOLVER FAILURES + COVERAGE GAP ANALYSIS each turn

### Good demo seeds (interesting results):
- antirez (Redis creator, breach data, 60 nodes)
- simonw (Simon Willison, 243 platforms, HIGH risk)
- torvalds (Linus Torvalds, 103 nodes)
- dhh (David Heinemeier Hansson, Rails creator)
