"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone

from . import __version__, profiles
from .checks.base import all_checks
from .diff import compare
from .diff import render as render_diff
from .http import HttpClient, HttpError
from .models import (
    PROFILE_RANK,
    SEVERITY_RANK,
    ParsedTarget,
    Severity,
)
from .report import render as render_report
from .scope import Budget, RateLimiter, ScopePolicy, ScopeViolation
from .verify import Engine, run_checks

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_UNREACHABLE = 3
EXIT_SCOPE = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-verify",
        description="Evidence-backed web security verification for terminals and Termux.",
        epilog="Authorised testing only. Defaults to a read-only safe profile.",
    )
    parser.add_argument("--version", action="version", version=f"sentinel-verify {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a target URL")
    scan.add_argument("url")
    scan.add_argument("--profile", default="safe", choices=sorted(profiles.BUILTIN))
    scan.add_argument("--checks", default="all", help="comma separated check ids, or 'all'")
    scan.add_argument("--exclude", default="", help="comma separated check ids to skip")
    scan.add_argument("--header", action="append", default=[], metavar="K: V")
    scan.add_argument("--cookie", action="append", default=[], metavar="K=V")
    scan.add_argument("--concurrency", type=int)
    scan.add_argument("--rate", type=float)
    scan.add_argument("--timeout", type=float)
    scan.add_argument("--retries", type=int)
    scan.add_argument("--max-requests", type=int)
    scan.add_argument("--insecure", action="store_true", help="skip certificate verification")
    scan.add_argument("--allow-private", action="store_true")
    scan.add_argument("--user-agent")
    scan.add_argument("--control", metavar="URL", help="control URL for false-positive suppression")
    scan.add_argument("--format", default="text", choices=["text", "json", "md", "html", "sarif"])
    scan.add_argument("--out", metavar="PATH")
    scan.add_argument("--baseline", metavar="PATH")
    scan.add_argument("--fail-on", default=None, choices=["low", "med", "high", "crit"])
    scan.add_argument("--scope-domain")
    scan.add_argument("--no-redirect", action="store_true")
    scan.add_argument("--dry-run", action="store_true")
    scan.add_argument("--verbose", "-v", action="store_true")

    diff = sub.add_parser("diff", help="compare two JSON reports")
    diff.add_argument("baseline")
    diff.add_argument("current")
    diff.add_argument("--fail-on-new", action="store_true")

    listing = sub.add_parser("list-checks", help="list available checks")
    listing.add_argument("--tier", choices=["safe", "standard", "aggressive"])

    explain = sub.add_parser("explain", help="describe a check")
    explain.add_argument("check_id")
    return parser


def _parse_headers(pairs: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for raw in pairs:
        if ":" not in raw:
            raise SystemExit(f"--header needs 'K: V', got {raw!r}")
        key, _, value = raw.partition(":")
        out.append((key.strip(), value.strip()))
    return out


def _select_checks(args: argparse.Namespace) -> list:
    registry = all_checks()
    if args.checks == "all":
        wanted = set(registry)
    else:
        wanted = {c.strip() for c in args.checks.split(",") if c.strip()}
        missing = wanted - set(registry)
        if missing:
            raise SystemExit(f"unknown check(s): {', '.join(sorted(missing))}")
    excluded = {c.strip() for c in args.exclude.split(",") if c.strip()}
    ceiling = PROFILE_RANK[args.profile]
    selected = []
    for check_id in sorted(wanted - excluded):
        cls = registry[check_id]
        if PROFILE_RANK[cls.tier.value] > ceiling:
            continue
        selected.append(cls())
    return selected


async def _scan(args: argparse.Namespace) -> int:
    try:
        target = ParsedTarget.parse(args.url)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    profile = profiles.load(args.profile)
    policy = ScopePolicy(
        target.host,
        scope_domain=args.scope_domain,
        allow_private=args.allow_private,
        follow_redirects=not args.no_redirect and profile.follow_redirects,
    )
    try:
        policy.check_target_host(target.host)
    except ScopeViolation as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_SCOPE

    checks = _select_checks(args)
    if not checks:
        print("error: no checks selected for this profile", file=sys.stderr)
        return EXIT_USAGE

    headers = _parse_headers(args.header)
    headers.extend(("Cookie", c) for c in args.cookie)

    if args.dry_run:
        print(f"target:  {target.url}")
        print(f"profile: {profile.name} (rate {profile.rate}/s, budget {args.max_requests or profile.max_requests})")
        print(f"checks:  {len(checks)}")
        for check in checks:
            print(f"  {check.id:32} {check.tier.value:10} {check.title}")
        return EXIT_OK

    client = HttpClient(
        policy=policy,
        budget=Budget(args.max_requests or profile.max_requests),
        limiter=RateLimiter(args.rate or profile.rate),
        concurrency=args.concurrency or profile.concurrency,
        timeout=args.timeout or profile.timeout,
        retries=profile.retries if args.retries is None else args.retries,
        insecure=args.insecure,
        user_agent=args.user_agent or None or "sentinel-verify/" + __version__,
        default_headers=headers,
    )
    engine = Engine(client, target, control_url=args.control, verbose=args.verbose)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    try:
        await engine.baseline()
    except HttpError as exc:
        print(f"error: target unreachable: {exc}", file=sys.stderr)
        return EXIT_UNREACHABLE
    except ScopeViolation as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_SCOPE

    await run_checks(engine, checks, concurrency=args.concurrency or profile.concurrency)
    report = engine.build_report(started, profile.name, __version__)

    output = render_report(report, args.format, color=sys.stdout.isatty())
    if args.out:
        await asyncio.to_thread(_write_text, args.out, output)
        print(f"report written to {args.out}", file=sys.stderr)
    else:
        print(output)

    if args.baseline:
        current = args.out or _default_out()
        await asyncio.to_thread(_write_text, current, report.to_json())
        print(render_diff(compare(args.baseline, current), color=sys.stdout.isatty()))

    if args.fail_on:
        threshold = {"low": Severity.LOW, "med": Severity.MEDIUM,
                     "high": Severity.HIGH, "crit": Severity.CRITICAL}[args.fail_on]
        worst = report.worst()
        if worst is not None and SEVERITY_RANK[worst] >= SEVERITY_RANK[threshold]:
            return EXIT_FINDINGS
    return EXIT_OK


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _default_out() -> str:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    directory = os.path.join(base, "sentinel-verify", "reports")
    os.makedirs(directory, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return os.path.join(directory, f"report-{stamp}.json")


def _list_checks(args: argparse.Namespace) -> int:
    registry = all_checks()
    rows = sorted(registry.values(), key=lambda c: (PROFILE_RANK[c.tier.value], c.id))
    for cls in rows:
        if args.tier and cls.tier.value != args.tier:
            continue
        print(f"{cls.id:34} {cls.tier.value:10} {cls.cwe:10} {cls.title}")
    return EXIT_OK


def _explain(check_id: str) -> int:
    registry = all_checks()
    cls = registry.get(check_id)
    if cls is None:
        print(f"unknown check: {check_id}", file=sys.stderr)
        return EXIT_USAGE
    print(f"{cls.id} — {cls.title}")
    print(f"tier:  {cls.tier.value}")
    print(f"cwe:   {cls.cwe}")
    print()
    print(cls.description or "(no description)")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            return asyncio.run(_scan(args))
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return EXIT_USAGE
    if args.command == "diff":
        result = compare(args.baseline, args.current)
        print(render_diff(result, color=sys.stdout.isatty()))
        return EXIT_FINDINGS if (args.fail_on_new and result.regression) else EXIT_OK
    if args.command == "list-checks":
        return _list_checks(args)
    if args.command == "explain":
        return _explain(args.check_id)
    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
