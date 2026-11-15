# sentinel-verify

> Point it at a URL. Get findings that come with proof, not a wall of guesses.

![ci](https://github.com/sentinel-verify/sentinel-verify/actions/workflows/ci.yml/badge.svg)

`sentinel-verify` is a web security verification CLI built for terminals and
Termux on Android. It runs on the Python standard library alone, needs no root,
and every finding it emits is backed by captured evidence and a confidence
rating — because a scanner that cries wolf is a scanner you stop reading.

```
$ sentinel-verify scan https://staging.example.com --control https://example.com
sentinel-verify 0.1.0
target   https://staging.example.com
profile  safe   requests 41

[HIGH    ] HSTS header missing  (confirmed)
  hdr.hsts  CWE-319  https://staging.example.com/
  fix:  Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'

[MEDIUM  ] Reflected XSS via 'q'  (confirmed)
  inj.xss_reflected.q  CWE-79  https://staging.example.com/search?q=...
  diff: baseline='' probe='<svg/onload=alert(1)>'
  fix:  HTML-encode reflected values; pair with a nonce-based CSP
```

## Install

### Termux

```bash
pkg install python git openssl
git clone https://github.com/Ahmadhsn580/sentinel-verify
cd sentinel-verify
bash install.sh
```

If `venv` fails on an older Termux, run `pkg install python-venv`, or use
`proot-distro login ubuntu` and follow the Linux steps inside.

### Linux / macOS

```bash
git clone https://github.com/Ahmadhsn580/sentinel-verify
cd sentinel-verify
bash install.sh
```

### Quickstart

```bash
sentinel-verify scan https://example.com
sentinel-verify scan https://example.com --profile standard --fail-on high
sentinel-verify scan https://example.com --format sarif --out results.sarif
sentinel-verify diff old.json new.json --fail-on-new
```

## Profiles

| Profile | Methods | Requests | Rate | Use it when |
|---|---|---|---|---|
| `safe` (default) | GET, HEAD | 300 | 5/s | production, always start here |
| `standard` | + OPTIONS | 800 | 8/s | staging, CI gates |
| `aggressive` | + POST | 2000 | 15/s | pre-release, timing checks |

The cap is hard. The run stops cleanly and the report is flagged partial.

## What it verifies

53 checks across TLS, DNS, headers, cookies, CORS, methods, file exposure,
redirects, injection, host handling, API surface and fingerprinting. Each one
names its CWE and its blast radius — see [docs/CHECKS.md](docs/CHECKS.md).

```bash
sentinel-verify list-checks --tier safe
sentinel-verify explain inj.sqli_time
```

## Why findings hold up

Every check runs baseline → probe → baseline. A finding is only `confirmed` when
the two baselines agree and the probe diverges. Time-based checks need a 3σ
delay over three samples. `--control` suppresses anything that also reproduces on
a control page, which kills the site-wide false positives that make scanners
noise.

## Output

`text`, `json`, `md`, `html`, `sarif`. Exit codes: `0` clean, `1` at or above
`--fail-on`, `2` usage, `3` unreachable, `4` scope violation.

```json
{
  "check_id": "hdr.hsts",
  "severity": "high",
  "confidence": "confirmed",
  "cwe": "CWE-319",
  "fingerprint": "9f2c1a4b7d0e3a55",
  "evidence": { "status": 200, "body_sha256": "…" }
}
```

## Safety

Read [docs/SAFETY.md](docs/SAFETY.md). Short version: nothing writes to the
target, private IPs are refused unless you pass `--allow-private`, and
`--dry-run` prints the plan before a single packet leaves the device.

## Limitations

- Not a crawler. It tests the URL you give it, not a site graph.
- No JavaScript execution, so DOM XSS and SPA routes are out of reach.
- SQLi verification is error- and timing-based; it will not find every blind case.
- CVE matching is banner-based and heuristic — always confirm the build.
- No authentication flows beyond static `--header` / `--cookie` injection.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New checks need a test and a catalogue row.

## Licence

MIT. Use it against systems you are authorised to test.