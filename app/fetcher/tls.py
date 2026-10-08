"""Raw TLS handshakes for the certificate and protocol-version checks.

Only ``SafeFetcher.tls_probe`` calls this, after the target address has been validated.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from functools import cache

from cryptography import x509
from cryptography.x509.oid import NameOID

TLS_TIMEOUT = 5.0


@dataclass
class CertInfo:
    subject_cn: str | None
    issuer: str | None
    not_before: datetime
    not_after: datetime
    sans: list[str]


@dataclass
class TlsResult:
    ok: bool
    version: str | None = None
    cipher: str | None = None
    cert: CertInfo | None = None
    error: str | None = None
    verify_failed: bool = False  # certificate did not validate (expired, wrong name, untrusted)
    untestable: bool = False  # this machine cannot offer the requested protocol version


class TlsConnectError(Exception):
    """Could not reach the server at all (timeout, refused, reset)."""


@cache
def _verifying_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def parse_cert(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)

    def first(attrs: list[x509.NameAttribute]) -> str | None:
        return str(attrs[0].value) if attrs else None

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san.value.get_values_for_type(x509.DNSName)[:20]
    except x509.ExtensionNotFound:
        sans = []
    return CertInfo(
        subject_cn=first(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)),
        issuer=first(cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))
        or first(cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sans=sans,
    )


def real_handshake(
    ip: str,
    host: str,
    *,
    verify: bool,
    min_version: ssl.TLSVersion | None = None,
    max_version: ssl.TLSVersion | None = None,
    port: int = 443,
    timeout: float = TLS_TIMEOUT,
) -> TlsResult:
    if verify:
        ctx = _verifying_context()
        if min_version or max_version:  # never mutate the shared context
            ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if min_version or max_version:
        try:
            if min_version:
                ctx.minimum_version = min_version
            if max_version:
                ctx.maximum_version = max_version
            if min_version and min_version < ssl.TLSVersion.TLSv1_2:
                ctx.set_ciphers("ALL:@SECLEVEL=0")  # old protocols need old ciphers
        except (ValueError, ssl.SSLError):
            return TlsResult(ok=False, untestable=True, error="not supported by this machine")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                return TlsResult(
                    ok=True,
                    version=tls.version(),
                    cipher=cipher[0] if cipher else None,
                    cert=parse_cert(der) if der else None,
                )
    except ssl.SSLCertVerificationError as exc:
        return TlsResult(ok=False, verify_failed=True, error=exc.verify_message)
    except ssl.SSLError as exc:
        # Includes the server refusing the protocol version we offered.
        return TlsResult(ok=False, error=exc.reason or "handshake failed")
    except OSError as exc:
        raise TlsConnectError(type(exc).__name__) from exc
