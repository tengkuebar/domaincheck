---
name: ssrf-review
description: Review code that makes outbound network requests (HTTP, TLS, DNS, raw sockets) for SSRF, DNS rebinding, redirect abuse, resource exhaustion and information leaks, using DomainCheck's safe-fetcher design as the standard. Use this whenever you add or change anything under app/fetcher or app/dns, add a check that fetches a URL or opens a connection, touch httpx, requests, urllib, socket or ssl code, or when the user asks to review, audit or "security check" request-making code, even if they never say SSRF.
---

# SSRF review

DomainCheck connects to hostnames that visitors type. That makes every outbound call a way to
reach things the visitor should not be able to reach: the host's own services, cloud metadata,
private networks. The defence is one choke point: all HTTP and TLS goes through
`app/fetcher/`, all DNS through `app/dns/`. This review keeps that true and checks that the choke
point itself stays tight. Read `references/safe-fetcher-design.md` for the design and its known gaps.

## Steps

1. **Find every outbound call site.** Run `python .claude/skills/ssrf-review/scripts/find_outbound.py app`.
   Anything it reports outside `app/fetcher/` and `app/dns/` is a finding by itself: a check module
   must never open its own connections, because it would skip every protection below. Also read the diff for
   things the script cannot see (a new helper that wraps the fetcher but passes it a raw URL).
2. **Walk the checklist** below against the changed code. For each item decide: holds, broken, or
   not applicable. Do not mark something as holding because the code "looks careful"; point at the
   line that enforces it or at the test that proves it.
3. **Check the tests.** Each protection needs a test in `tests/security/` that fails if it is removed.
   A missing test is a finding even when the code is right, because the next edit will silently undo it.
4. **Report** in the format at the end.

## Checklist

Why each matters is in brackets, so you can judge edge cases the list does not name.

**Target parsing**
- Only `http` and `https`, only ports 80 and 443 [other schemes and ports reach file, gopher, databases, admin ports].
- Reject credentials in the URL (`http://good.com@evil.com`) [parser confusion about which host is real].
- Reject IP literals as targets, including decimal, octal and hex forms [skips DNS-based checks].
- Hostname normalised once and the same value used for resolve, connect, Host header and TLS name [a mismatch between "checked" and "used" is the whole bug class].

**Address validation**
- Resolve first, then check the resolved addresses, never the typed name [a public name can point at 127.0.0.1].
- Reject if any address is blocked, not just the first [an attacker returns a public and a private record].
- Blocked ranges cover private, loopback, link-local (includes 169.254.169.254), unspecified, multicast,
  reserved, carrier-grade NAT, IPv4-mapped IPv6 (`::ffff:127.0.0.1`), NAT64, 6to4, Teredo and the AWS IPv6 metadata range [each is a known bypass].
- Unparseable addresses are blocked [fail closed].

**Connecting**
- Connect to the validated IP, and send the original hostname as Host and TLS SNI [stops DNS rebinding between check and use].
- Resolve once per hop; never re-resolve inside the client library after validation.
- No connection reuse that could send a later request to an address chosen earlier for another host.
- Proxies from the environment are off (`trust_env=False`) [a proxy would make the connection somewhere unchecked].
- Raw TLS or socket code (`tls_probe`) goes through the same validation as HTTP.

**Redirects**
- Library auto-redirect is off; each hop is parsed and validated from scratch [`requests` follows by default].
- Redirect count is capped. Relative `Location` values are resolved before validation.
- Redirect to a blocked address, an IP literal, another scheme or another port is refused.

**Limits**
- Timeout on connect, read and total wall-clock time [slow targets tie up workers].
- Response size cap enforced while streaming, not after reading everything.
- Compressed bodies: the cap applies to what is read from the wire; do not decompress without a separate cap.
- Queue and rate limits exist so one visitor cannot flood the fetcher.

**Output and logging**
- Errors shown to visitors are generic. The message must not reveal resolved IPs, internal hostnames or exception text, because that turns a blocked probe into a port scanner.
- Response bodies and cookie values are never stored or logged.
- User input never becomes a path, header or query on the outbound request except the validated domain; fixed path lists stay constants.

## Report format

```
## SSRF review: <scope>

Verdict: pass | pass with notes | changes needed

| Severity | Where | Problem | Fix |
|---|---|---|---|
| high | app/x.py:42 | ... | ... |

Checklist items not covered by a test: ...
Items not applicable: ...
```

Severity: **high** means a visitor can make the server reach a blocked address or bypass a limit;
**medium** means information leaks or a limit is weak; **low** is hygiene. If nothing is wrong, say
which checklist sections you verified and how, so the "pass" can be trusted.
