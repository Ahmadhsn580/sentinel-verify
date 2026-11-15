# Check catalogue

Every check states what it proves, its CWE, and its blast radius.

| ID | Tier | CWE | Proves | Blast radius |
|---|---|---|---|---|
| tls.min_version.10 | safe | CWE-326 | TLS 1.0 handshake succeeds | 1 handshake |
| tls.min_version.11 | safe | CWE-326 | TLS 1.1 handshake succeeds | 1 handshake |
| tls.weak_ciphers | standard | CWE-327 | Legacy cipher negotiable | 1 handshake |
| tls.cert_expiry | safe | CWE-298 | Cert expired / expiring / future-dated | 1 GET |
| tls.cert_chain | safe | CWE-295 | Chain fails trust store | 1 handshake |
| tls.sni | standard | CWE-16 | No default vhost without SNI | 1 GET |
| tls.ct_logs | standard | CWE-200 | Extra hostnames in CT | 1 HTTPS fetch to crt.sh |
| dns.spf | safe | CWE-290 | SPF absent or soft | 1 DNS TXT |
| dns.dmarc | safe | CWE-290 | DMARC absent or p=none | 1 DNS TXT |
| dns.dkim | standard | CWE-290 | No key on common selectors | 7 DNS TXT |
| dns.caa | standard | CWE-295 | Any CA may issue | 1 DNS CAA |
| dns.dnssec | standard | CWE-350 | Zone unsigned | 1 DNS DS |
| dns.dangling_cname | standard | CWE-350 | Unclaimed SaaS target | 1 DNS + 1 GET |
| hdr.hsts | safe | CWE-319 | HSTS absent/short/no subDomains | 0 (uses baseline) |
| hdr.csp | safe | CWE-1021 | CSP absent or permissive | 0 |
| hdr.frame_ancestors | safe | CWE-1021 | Framing unrestricted | 0 |
| hdr.xcto | safe | CWE-430 | nosniff missing | 0 |
| hdr.referrer_policy | safe | CWE-200 | Referrer policy missing | 0 |
| hdr.permissions_policy | standard | CWE-16 | Feature policy missing | 0 |
| hdr.info_disclosure | safe | CWE-200 | Version banner | 0 |
| cookie.secure | safe | CWE-614 | Cookie without Secure | 0 |
| cookie.httponly | safe | CWE-1004 | Cookie without HttpOnly | 0 |
| cookie.samesite | safe | CWE-1275 | SameSite unset/None | 0 |
| cookie.prefix | standard | CWE-16 | Session cookie without __Host- | 0 |
| cors.reflection | safe | CWE-942 | Origin reflected | 3 GET (differential) |
| cors.null_origin | standard | CWE-942 | Origin: null accepted | 1 GET |
| cors.credentialed_wildcard | standard | CWE-942 | `*` plus credentials | 1 GET |
| http.options | safe | CWE-16 | Write verbs advertised | 1 OPTIONS |
| http.trace | safe | CWE-693 | TRACE enabled | 1 TRACE |
| http.verb_tamper | standard | CWE-288 | Auth differs by verb | up to 4 requests |
| exp.git | safe | CWE-538 | .git/HEAD readable | 2 GET |
| exp.env | safe | CWE-538 | dotenv readable | 4 GET |
| exp.dotfiles | standard | CWE-538 | Editor/CI files readable | 5 GET |
| exp.backups | standard | CWE-530 | Archive/dump readable | up to 8 GET |
| exp.sourcemap | standard | CWE-540 | .map served | 1 GET |
| exp.dirlisting | safe | CWE-548 | Autoindex on | 1 GET |
| exp.debug_endpoints | standard | CWE-489 | Actuator/debug live | 9 GET |
| redir.open | standard | CWE-601 | Param drives off-host redirect | up to 6 GET |
| redir.proto_relative | standard | CWE-601 | `//host` accepted | up to 4 GET |
| inj.xss_reflected | standard | CWE-79 | Marker reflected unescaped | up to 5 GET |
| inj.sqli_error | standard | CWE-89 | Driver error surfaces | up to 10 GET |
| inj.sqli_time | aggressive | CWE-89 | 3σ timing delay | 18 GET |
| inj.crlf | standard | CWE-113 | CRLF becomes a header | up to 4 GET |
| inj.traversal | standard | CWE-22 | /etc/passwd returned | up to 4 GET |
| host.header_injection | standard | CWE-20 | Host echoed into output | 1 GET |
| host.cache_poison | aggressive | CWE-524 | Unkeyed header reflected | 3 GET |
| host.xforwarded_trust | standard | CWE-348 | XFF trusted | 1 GET |
| api.graphql_introspection | standard | CWE-200 | Schema queryable | up to 4 POST |
| api.jwt_analysis | standard | CWE-347 | Weak JWT config | 0 |
| api.version_disclosure | standard | CWE-200 | Multiple API versions live | 6 GET |
| fp.stack | safe | CWE-200 | Stack identified | 0 |
| fp.waf | safe | CWE-693 | Edge protection seen | 0 |
| fp.cve_candidates | standard | CWE-1395 | Banner matches a CVE | 0 |
| fp.error_leak | standard | CWE-209 | Stack trace on 500 | 1 GET |