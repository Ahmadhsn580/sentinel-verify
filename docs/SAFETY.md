---

### `docs/SAFETY.md`

```markdown
# Safety model

## Profiles and budgets

| Profile | Methods | Request cap | Rate | Payload fuzzing |
|---|---|---|---|---|
| safe | GET, HEAD | 300 | 5/s | no |
| standard | + OPTIONS | 800 | 8/s | yes, single-shot |
| aggressive | + POST | 2000 | 15/s | yes, plus timing |

The cap is hard. When it is reached the run stops, keeps what it has, and the
report is marked `budget_exhausted`.

## Redirects

Redirects are followed only while the host stays inside the target's registrable
domain. Off-domain hops end the chain and the 30x is reported as-is.

## Scope

`--scope-domain` overrides the derived registrable domain. Private and loopback
addresses are refused unless `--allow-private` is passed, so a DNS rebind cannot
walk your scanner into an internal network.

## Non-destructive probes

- SQL injection uses `SLEEP`/`pg_sleep`/`WAITFOR DELAY` only. No `INSERT`, no `UPDATE`.
- Path traversal reads `/etc/passwd` only.
- XSS uses `<svg/onload=alert(1)>`, which fires once in a headless context.
- GraphQL introspection sends one query. No mutations.

## Before running against production

1. Start with `--dry-run` and read the plan.
2. Run `--profile safe`.
3. Add `--control https://example.com` on a neighbouring static page to suppress
   site-wide false positives.
4. Set `--fail-on high` in CI so only actionable results break the build.