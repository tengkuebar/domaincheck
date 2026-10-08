# The safe fetcher: design and known gaps

Files: `app/fetcher/safe_fetcher.py`, `ranges.py`, `tls.py`; `app/dns/resolver.py`.
Tests: `tests/security/test_safe_fetcher.py`, `tests/security/test_tls_probe.py`,
`tests/unit/test_ranges.py`, `tests/integration/test_real_tls.py`.

## Flow for one fetch

1. Parse the URL (`_parse`): scheme and port allowlist, no credentials, no IP literal, lowercase host.
2. Resolve through the DNS wrapper (`resolve_ips`, A and AAAA).
3. Refuse if any address is blocked (`is_blocked_ip`).
4. Rewrite the URL to the validated IP, send `Host: <original>` and the `sni_hostname` extension so TLS
   verifies against the original name.
5. Stream the body with a byte cap and a wall-clock deadline.
6. On a redirect, go back to step 1 with the new URL, up to 5 times.

`tls_probe` does steps 1 to 3 for a host, then a raw handshake to port 443 on the validated IP.

## Test map

| Protection | Test |
|---|---|
| Internal and metadata targets refused | `test_refuses_domain_resolving_to_internal`, `test_refuses_if_any_address_is_internal` |
| Scheme, port, credentials, IP literal | `test_refuses_bad_urls` |
| Pinning and original Host/SNI | `test_connects_to_validated_ip_with_original_host` |
| Redirect to internal or bad URL | `test_public_host_redirecting_to_internal_is_refused`, `test_redirect_to_bad_url_is_refused` |
| Rebinding | `test_rebinding_between_hops_is_caught_and_single_hop_pins` |
| Redirect cap | `test_redirect_loop_is_limited` |
| Size cap, timeout, time budget | `test_oversized_body_is_cut_off`, `test_timeout_becomes_fetch_error`, `test_total_time_budget_is_enforced` |
| TLS probe uses the same rules | `tests/security/test_tls_probe.py` |
| Range checker, IPv4-mapped and friends | `tests/unit/test_ranges.py` |
| No outbound code outside the choke point | `tests/unit/test_outbound_allowlist.py` |

## Known gaps (accepted for a learning project; do not "fix" silently, raise them)

- Redirects may leave the scanned domain, as long as the new host resolves to a public address.
- DNS answers come from the system resolver. A poisoned or split-horizon resolver can feed the app
  addresses that are wrong but still public; internal answers are blocked.
- There is no DNS answer cache, so a rebinding attacker gets a fresh lookup per hop. That is intended:
  every hop is validated, and the connection is pinned within a hop.
- The mock-transport tests cannot prove the pinned connection on a real socket. The real-socket proof
  is `test_real_tls.py` for the handshake only, not for HTTP.
- Rate limits are per process and per IP.
- Responses are read as raw wire bytes, with no decompression, so the size cap cannot be bypassed with a
  compression bomb. The fetcher asks for `Accept-Encoding: identity` so content checks see plain text.

## Where new code usually goes wrong

- A new check calls `httpx.get(...)` or `socket.create_connection(...)` directly because "it is only one request".
- A helper builds a URL from the domain plus a path from data and forgets that the path can contain `@`, `#` or `..`.
- Someone adds `follow_redirects=True` to the client to "make it work".
- Someone logs `str(exception)` into a response message.
