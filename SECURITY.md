# Security policy

## Supported versions

The latest tagged minor release receives fixes.

## Reporting a vulnerability

Email the maintainers or open a private security advisory on GitHub. Include the
affected version, the check id if relevant, and a reproduction. Expect an
acknowledgement within five working days.

## Scope notes

sentinel-verify only issues GET/HEAD/OPTIONS and, in the aggressive profile,
non-destructive POSTs. It never writes to the target. The `safe` profile is
read-only and capped at 300 requests.

## Handling secrets

`--header` and `--cookie` values are held in memory only and are never written to
reports unless a check echoes them back in evidence.