"""Bounded, read-only mail-domain posture checks for scan runs.

Only explicitly selected FQDN targets are considered. No SMTP connection or message is sent.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit
from typing import Any
from datetime import UTC, datetime

import dns.asyncresolver
import dns.flags
import dns.resolver

MAX_DOMAINS = 25
MAX_DKIM_SELECTORS = 20
MAX_MTA_STS_BYTES = 16 * 1024
MAX_TOTAL_SECONDS = 90
MAX_DOMAIN_SECONDS = 20
DNS_LIFETIME = 2.0
HTTP_TIMEOUT = 3.0
MAIL_CHECKS = ("spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "dane")
_SELECTOR = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
_TAG = re.compile(r"^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$")


def _valid_spf_term(term: str) -> bool:
    term = term.lower()
    qualifier = term[:1] if term[:1] in "+-~?" else ""
    body = term[1:] if qualifier else term
    if body in {"all", "a", "mx", "ptr"}:
        return True
    if body.startswith("ip4:") or body.startswith("ip6:"):
        try:
            address = body.split(":", 1)[1]
            if ":" in address or "/" in address:
                ipaddress.ip_network(address, strict=False)
            else:
                ipaddress.ip_address(address)
            return (body.startswith("ip4:") and "." in address) or (body.startswith("ip6:") and ":" in address)
        except ValueError:
            return False
    mechanism = re.fullmatch(r"(include|exists):([^/]+)", body)
    if mechanism:
        return bool(_DOMAIN.fullmatch(mechanism.group(2)))
    mechanism = re.fullmatch(r"(a|mx|ptr)(?::([^/]+))?(?:/(\d{1,3})?)?(?:/(\d{1,3})?)?", body)
    if mechanism:
        try:
            if mechanism.group(3) and int(mechanism.group(3)) > 32:
                return False
            if mechanism.group(4) and int(mechanism.group(4)) > 128:
                return False
        except ValueError:
            return False
        return not mechanism.group(2) or bool(_DOMAIN.fullmatch(mechanism.group(2)))
    if body.startswith("redirect=") or body.startswith("exp="):
        return bool(_DOMAIN.fullmatch(body.split("=", 1)[1]))
    return False


def _observation(name: str, status: str, *, records: list[str] | None = None, details: dict[str, Any] | None = None,
                 message: str = "") -> dict[str, Any]:
    return {"check": name, "status": status, "message": message,
            "records": records or [], "details": details or {}, "provenance": "DNS/HTTPS observation"}


class _Lookup:
    def __init__(self, cancel_event=None) -> None:
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = DNS_LIFETIME
        self.resolver.timeout = DNS_LIFETIME
        self.cache: dict[tuple[str, str], Any] = {}
        self.lookups = 0
        self.cancel_event = cancel_event

    async def query(self, name: str, rdtype: str):
        if self.cancel_event and self.cancel_event.is_set():
            return None
        key = (name.rstrip(".").lower(), rdtype.upper())
        if key in self.cache:
            return self.cache[key]
        self.lookups += 1
        try:
            answer = await self.resolver.resolve(key[0], key[1], lifetime=DNS_LIFETIME, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException, OSError):
            answer = None
        self.cache[key] = answer
        return answer


def _txt(answer) -> list[str]:
    if not answer or answer.rrset is None:
        return []
    out = []
    for record in answer:
        try:
            out.append(b"".join(record.strings).decode("utf-8", "replace"))
        except AttributeError:
            out.append(record.to_text().strip('"'))
    return out


def _tags(record: str) -> dict[str, str] | None:
    parsed: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        match = _TAG.fullmatch(part)
        if not match or match.group(1).lower() in parsed:
            return None
        parsed[match.group(1).lower()] = match.group(2)
    return parsed


def _first_tag(record: str) -> str:
    first = record.split(";", 1)[0].strip()
    match = _TAG.fullmatch(first)
    return match.group(1).lower() if match else ""


def _valid_report_destination(value: str) -> bool:
    value = value.strip()
    if value.lower().startswith("mailto:"):
        address = value[7:]
        return bool(re.fullmatch(r"[^\s@,;<>]+@[^\s@,;<>]+", address))
    parsed = urlsplit(value)
    return parsed.scheme.lower() == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password


async def _spf(domain: str, lookup: _Lookup) -> dict[str, Any]:
    records = [r for r in _txt(await lookup.query(domain, "TXT")) if r.lower().split()[:1] == ["v=spf1"]]
    if not records:
        return _observation("spf", "warning", message="No SPF record observed.")
    if len(records) != 1:
        return _observation("spf", "non_compliant", records=records, message="Multiple SPF records were observed.")
    terms = records[0].split()[1:]
    if not terms:
        return _observation("spf", "warning", records=records, message="An SPF version marker without mechanisms does not establish a complete sender policy.")
    if not all(_valid_spf_term(term) for term in terms):
        return _observation("spf", "non_compliant", records=records, message="The SPF record contains a malformed or unsupported mechanism/modifier.")
    if any(not term or any(ch.isspace() for ch in term) for term in terms):
        return _observation("spf", "non_compliant", records=records, message="Malformed whitespace in SPF mechanisms.")
    if sum(1 for term in terms if term.lstrip("+-~?").lower() == "all") > 1:
        return _observation("spf", "non_compliant", records=records, message="SPF contains more than one all mechanism.")
    modifiers = [term.split("=", 1)[0].lower() for term in terms if "=" in term]
    if len(modifiers) != len(set(modifiers)):
        return _observation("spf", "non_compliant", records=records, message="SPF contains a duplicate modifier.")
    count = 0
    error = ""

    async def walk(name: str, depth: int = 0, ancestors: frozenset[str] = frozenset()) -> None:
        nonlocal count, error
        if depth > 10 or name in ancestors:
            error = "SPF include/redirect loop or excessive depth."
            return
        ancestors = ancestors | {name}
        values = [r for r in _txt(await lookup.query(name, "TXT")) if r.lower().split()[:1] == ["v=spf1"]]
        if name != domain and len(values) != 1:
            error = "An SPF include/redirect did not resolve to exactly one SPF record."
            return
        if not values:
            return
        for term in values[0].split()[1:]:
            mechanism = term.lstrip("+-~?").split(":", 1)[0].split("/", 1)[0].lower()
            if mechanism in {"include", "a", "mx", "ptr", "exists"} or term.lower().startswith("redirect="):
                count += 1
                if count > 10:
                    error = "SPF evaluation exceeds the RFC 10-DNS-lookup limit."
                    return
            if mechanism == "include" and ":" in term:
                await walk(term.split(":", 1)[1].split("/", 1)[0].lower(), depth + 1, ancestors)
            elif term.lower().startswith("redirect="):
                await walk(term.split("=", 1)[1].lower(), depth + 1, ancestors)
            if error:
                return

    for term in terms:
        mechanism = term.lstrip("+-~?").split(":", 1)[0].split("/", 1)[0].lower()
        if mechanism in {"include", "a", "mx", "ptr", "exists"} or term.lower().startswith("redirect="):
            count += 1
        if mechanism == "include" and ":" in term:
            await walk(term.split(":", 1)[1].split("/", 1)[0].lower(), 1)
        elif term.lower().startswith("redirect="):
            await walk(term.split("=", 1)[1].lower(), 1)
        if count > 10:
            error = "SPF evaluation exceeds the RFC 10-DNS-lookup limit."
            break
        if error:
            break
    if error:
        return _observation("spf", "non_compliant", records=records, details={"dns_lookups": count}, message=error)
    all_terms = [term.lstrip("+-~?").lower() for term in terms if term.lstrip("+-~?").lower() == "all"]
    if len(all_terms) != 1 or next((term[:1] for term in terms if term.lstrip("+-~?").lower() == "all"), "?") != "-":
        return _observation("spf", "warning", records=records, details={"dns_lookups": count},
                            message="SPF syntax and lookup budget are within limits, but the terminal all policy is absent or not -all; sender authorization is not proven.")
    return _observation("spf", "compliant", records=records, details={"dns_lookups": count},
                        message="One SPF record observed; syntax and DNS lookup budget are within limits. This does not prove sender authorization.")


async def _dmarc(domain: str, lookup: _Lookup) -> dict[str, Any]:
    txt_records = _txt(await lookup.query(f"_dmarc.{domain}", "TXT"))
    records = [r for r in txt_records if _first_tag(r) == "v"]
    if not records:
        if txt_records:
            return _observation("dmarc", "non_compliant", records=txt_records, message="A DMARC TXT record was found but its version tag is missing or not first.")
        return _observation("dmarc", "warning", message="No DMARC record observed.")
    if len(records) != 1:
        return _observation("dmarc", "non_compliant", records=records, message="Multiple DMARC records were observed.")
    tags = _tags(records[0])
    if tags is None or _first_tag(records[0]) != "v" or tags.get("v", "").lower() != "dmarc1" or tags.get("p", "").lower() not in {"none", "quarantine", "reject"}:
        return _observation("dmarc", "non_compliant", records=records, message="The DMARC record syntax or required policy tag is invalid.")
    for key in ("sp",):
        if key in tags and tags[key].lower() not in {"none", "quarantine", "reject"}:
            return _observation("dmarc", "non_compliant", records=records, details=tags, message=f"Invalid {key} policy.")
    try:
        pct = int(tags.get("pct", "100"))
        if not 0 <= pct <= 100:
            raise ValueError
    except ValueError:
        return _observation("dmarc", "non_compliant", records=records, details=tags, message="pct must be an integer from 0 to 100.")
    if tags.get("adkim", "r").lower() not in {"r", "s"} or tags.get("aspf", "r").lower() not in {"r", "s"}:
        return _observation("dmarc", "non_compliant", records=records, details=tags, message="Invalid DKIM or SPF alignment mode.")
    risk = tags["p"].lower() == "none" or pct < 100
    return _observation("dmarc", "warning" if risk else "compliant", records=records, details=tags,
                        message=("p=none or pct<100 is a monitoring/partial enforcement policy; rua only advertises a destination and does not prove reports arrive."
                                 if risk else "DMARC policy syntax is valid; rua/ruf do not prove reports are received."))


async def _dkim(domain: str, selectors: list[str], lookup: _Lookup) -> list[dict[str, Any]]:
    if not selectors:
        return [_observation("dkim", "not_evaluated", message="No DKIM selector was supplied; selectors cannot be enumerated exhaustively from DNS.")]
    results = []
    for selector in selectors[:MAX_DKIM_SELECTORS]:
        if not _SELECTOR.fullmatch(selector):
            results.append(_observation("dkim", "error", details={"selector": selector}, message="Invalid DKIM selector syntax."))
            continue
        records = _txt(await lookup.query(f"{selector}._domainkey.{domain}", "TXT"))
        records = [r for r in records if "p=" in r.lower()]
        if not records:
            results.append(_observation("dkim", "warning", details={"selector": selector}, message="No DKIM public-key record observed for the supplied selector."))
            continue
        tags = _tags(records[0]) if len(records) == 1 else None
        if tags is None or not tags.get("p"):
            results.append(_observation("dkim", "non_compliant", records=records, details={"selector": selector}, message="The DKIM public-key record is malformed or duplicated."))
            continue
        key_bits = None
        key_type = tags.get("k", "rsa").lower()
        if key_type == "rsa":
            try:
                import base64
                from cryptography.hazmat.primitives import serialization
                key = serialization.load_der_public_key(base64.b64decode(tags["p"], validate=True))
                key_bits = getattr(key, "key_size", None)
            except Exception:  # a syntactically present key need not be parseable by an older crypto backend
                key_bits = None
        status = "non_compliant" if key_bits is not None and key_bits < 1024 else "warning" if key_bits is None else "compliant"
        results.append(_observation("dkim", status, records=records,
                                    details={"selector": selector, "key_type": key_type, "key_bits": key_bits},
                                    message="Public key observed; no signed message was supplied, so signature validity is not evaluated."))
    return results


async def _tls_rpt(domain: str, lookup: _Lookup) -> dict[str, Any]:
    txt_records = _txt(await lookup.query(f"_smtp._tls.{domain}", "TXT"))
    records = [r for r in txt_records if _first_tag(r) == "v"]
    if not records:
        if txt_records:
            return _observation("tls_rpt", "non_compliant", records=txt_records, message="A TLS-RPT TXT record was found but its version tag is missing or not first.")
        return _observation("tls_rpt", "warning", message="No TLS-RPT record observed.")
    tags = _tags(records[0]) if len(records) == 1 else None
    rua = (tags or {}).get("rua", "")
    if tags is None or _first_tag(records[0]) != "v" or tags.get("v", "").lower() != "tlsrptv1" or not rua or not all(_valid_report_destination(x) for x in rua.split(",")):
        return _observation("tls_rpt", "non_compliant", records=records, message="TLS-RPT record must contain v=TLSRPTv1 and valid mailto:/https destinations.")
    return _observation("tls_rpt", "compliant", records=records, details=tags, message="TLS-RPT record syntax and destinations observed; receipt of reports is not verified.")


async def _mx(domain: str, lookup: _Lookup) -> list[str]:
    answer = await lookup.query(domain, "MX")
    if not answer or answer.rrset is None:
        return []
    return sorted({str(record.exchange).rstrip(".").lower() for record in answer if str(record.exchange) != "."})[:10]


def _resolve_public(host: str) -> list[str]:
    addresses = sorted({row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError("MTA-STS host resolves to a non-public address; request blocked.")
    return addresses


def _fetch_mta_sts(host: str) -> tuple[int, str]:
    """Fetch one bounded HTTPS response, pinning the TLS socket to a prevalidated public address."""
    addresses = _resolve_public(host)
    last_error: Exception | None = None
    for address in addresses[:2]:
        sock = None
        try:
            raw = socket.create_connection((address, 443), timeout=HTTP_TIMEOUT)
            sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            sock.settimeout(HTTP_TIMEOUT)
            request = f"GET /.well-known/mta-sts.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: text/plain\r\nUser-Agent: Orion\r\n\r\n".encode("ascii")
            sock.sendall(request)
            chunks = bytearray()
            while len(chunks) <= MAX_MTA_STS_BYTES + 4096:
                part = sock.recv(min(4096, MAX_MTA_STS_BYTES + 4097 - len(chunks)))
                if not part:
                    break
                chunks.extend(part)
            header, _, body = bytes(chunks).partition(b"\r\n\r\n")
            if len(body) > MAX_MTA_STS_BYTES:
                raise ValueError("MTA-STS response exceeds 16 KiB.")
            status_line = header.split(b"\r\n", 1)[0].decode("ascii", "replace")
            code = int(status_line.split()[1])
            headers = header.decode("iso-8859-1", "replace").split("\r\n")[1:]
            if any(line.lower().startswith("location:") for line in headers):
                raise ValueError("MTA-STS redirect was blocked.")
            return code, body.decode("utf-8", "replace")
        except Exception as error:
            last_error = error
        finally:
            if sock:
                sock.close()
    raise ValueError(str(last_error or "MTA-STS HTTPS fetch failed"))


async def _mta_sts(domain: str, lookup: _Lookup, mx: list[str]) -> dict[str, Any]:
    txt_records = _txt(await lookup.query(f"_mta-sts.{domain}", "TXT"))
    records = [r for r in txt_records if _first_tag(r) == "v"]
    if not records:
        if txt_records:
            return _observation("mta_sts", "non_compliant", records=txt_records, message="An MTA-STS TXT record was found but its version tag is missing or not first.")
        return _observation("mta_sts", "warning", message="No MTA-STS DNS record observed.")
    tags = _tags(records[0]) if len(records) == 1 else None
    if tags is None or _first_tag(records[0]) != "v" or tags.get("v", "").lower() != "stsv1" or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", tags.get("id", "")):
        return _observation("mta_sts", "non_compliant", records=records, message="MTA-STS DNS record must have a unique v=STSv1 and a valid id.")
    host = f"mta-sts.{domain}"
    try:
        code, body = _fetch_mta_sts(host)
    except Exception as error:
        return _observation("mta_sts", "error", records=records, details={"id": tags["id"]}, message=f"Policy HTTPS request failed: {error}")
    if code != 200:
        return _observation("mta_sts", "non_compliant", records=records, details={"http_status": code}, message="MTA-STS policy endpoint did not return HTTP 200.")
    values: dict[str, list[str]] = {}
    for line in body.splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep:
            return _observation("mta_sts", "non_compliant", records=records, message="Malformed MTA-STS policy line.")
        values.setdefault(key.strip().lower(), []).append(value.strip())
    mode, version = (values.get("mode") or [""])[0].lower(), (values.get("version") or [""])[0].lower()
    policy_mx = [v.lower() for v in values.get("mx", [])]
    try:
        max_age = int((values.get("max_age") or [""])[0])
    except ValueError:
        max_age = -1
    if (len(values.get("version", [])) != 1 or len(values.get("mode", [])) != 1 or len(values.get("max_age", [])) != 1
            or version != "stsv1" or mode not in {"none", "testing", "enforce"}
            or (not policy_mx and mode != "none") or not 0 <= max_age <= 31557600):
        return _observation("mta_sts", "non_compliant", records=records, details={"mode": mode, "mx": policy_mx}, message="MTA-STS policy is missing a valid version, mode or MX rule.")
    if mx and not all(any(re.fullmatch(pattern.replace(".", r"\.").replace("*", ".*"), host) for pattern in policy_mx) for host in mx):
        return _observation("mta_sts", "warning", records=records, details={"mode": mode, "mx": policy_mx}, message="One or more observed MX hosts do not match the published MTA-STS policy.")
    return _observation("mta_sts", "warning" if mode != "enforce" else "compliant", records=records,
                        details={"id": tags["id"], "mode": mode, "mx": policy_mx, "max_age": max_age},
                        message="MTA-STS policy and verified HTTPS endpoint observed; mode is not enforce." if mode != "enforce" else "MTA-STS policy is in enforce mode and matches observed MX hosts.")


async def _dane(domain: str, lookup: _Lookup, mx: list[str]) -> dict[str, Any]:
    if not mx:
        return _observation("dane", "not_evaluated", message="No MX host was observed; DANE/TLSA was not queried.")
    records, validated = [], True
    for host in mx[:5]:
        answer = await lookup.query(f"_25._tcp.{host}", "TLSA")
        if answer and answer.response:
            validated = validated and bool(answer.response.flags & dns.flags.AD)
            records.extend(f"{host} {record.to_text()}" for record in answer)
    if not records:
        return _observation("dane", "not_evaluated", message="No TLSA records were observed for MX hosts.")
    if not validated:
        return _observation("dane", "not_evaluated", records=records, message="TLSA data was observed but DNSSEC validation is not confirmed by the configured recursive resolver.")
    return _observation("dane", "warning", records=records, details={"dnssec_validated_by_resolver": True}, message="TLSA records were returned with the DNSSEC AD bit set; association with a live SMTP certificate and SMTP TLSA usage are not actively tested.")


async def inspect_domain(domain: str, config: dict[str, Any], cancel_event=None) -> dict[str, Any]:
    lookup = _Lookup(cancel_event)
    checks = config.get("checks") or {}
    results: list[dict[str, Any]] = []
    mx = await _mx(domain, lookup) if any(checks.get(key) for key in ("mta_sts", "dane")) else []
    for key, check in (("spf", lambda: _spf(domain, lookup)), ("dmarc", lambda: _dmarc(domain, lookup)),
                       ("dkim", lambda: _dkim(domain, list(config.get("dkim_selectors") or []), lookup)),
                       ("mta_sts", lambda: _mta_sts(domain, lookup, mx)),
                       ("tls_rpt", lambda: _tls_rpt(domain, lookup)), ("dane", lambda: _dane(domain, lookup, mx))):
        if not checks.get(key):
            continue
        if cancel_event and cancel_event.is_set():
            results.append(_observation(key, "not_evaluated", message="The scan was cancelled before this check completed."))
            continue
        checked = await check()
        results.extend(checked if isinstance(checked, list) else [checked])
    return {"domain": domain, "checked_at": datetime.now(UTC).isoformat(),
            "mx": mx, "checks": results, "dns_queries": lookup.lookups}


def inspect_domains(domains: list[str], config: dict[str, Any], cancel_event=None) -> list[dict[str, Any]]:
    import asyncio

    async def inspect_all():
        semaphore = asyncio.Semaphore(3)

        async def bounded(domain: str):
            async with semaphore:
                try:
                    return await asyncio.wait_for(inspect_domain(domain, config, cancel_event), timeout=MAX_DOMAIN_SECONDS)
                except asyncio.TimeoutError:
                    return {"domain": domain, "checked_at": datetime.now(UTC).isoformat(), "mx": [], "dns_queries": 0,
                            "checks": [_observation(key, "not_evaluated", message="The per-domain mail-check time budget expired.")
                                       for key, enabled in (config.get("checks") or {}).items() if enabled]}
                except Exception as error:  # one domain must not discard other observations
                    return {"domain": domain, "checks": [_observation("mail_security", "error", message=f"Check failed: {type(error).__name__}")],
                            "mx": [], "dns_queries": 0}

        tasks = {asyncio.create_task(bounded(domain)): domain for domain in domains[:MAX_DOMAINS]}
        done, pending = await asyncio.wait(tasks, timeout=MAX_TOTAL_SECONDS)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        results = [task.result() for task in tasks if task in done and not task.cancelled()]
        results.extend({"domain": tasks[task],
                        "checked_at": datetime.now(UTC).isoformat(), "mx": [], "dns_queries": 0,
                        "checks": [_observation(key, "not_evaluated", message="The overall mail-check time budget expired.")
                                   for key, enabled in (config.get("checks") or {}).items() if enabled]}
                       for task in pending)
        by_domain = {result["domain"]: result for result in results}
        return [by_domain[domain] for domain in domains[:MAX_DOMAINS] if domain in by_domain]

    return asyncio.run(inspect_all()) if domains else []


def attach_smtp_observations(mail_results: list[dict[str, Any]], endpoints: list[dict[str, Any]]) -> None:
    """Link only already-collected SMTP STARTTLS endpoint results to MX hosts; never probes SMTP."""
    by_host: dict[str, list[dict[str, Any]]] = {}
    for endpoint in endpoints:
        try:
            port = int(endpoint.get("port", 0))
        except (TypeError, ValueError):
            continue
        hostname = str(endpoint.get("hostname", "")).rstrip(".").lower()
        if hostname and port in {25, 587}:
            by_host.setdefault(hostname, []).append(endpoint)
    for domain_result in mail_results:
        observations = []
        for mx_host in domain_result.get("mx", []):
            matches = by_host.get(str(mx_host).rstrip(".").lower(), [])
            endpoint = next((item for item in matches if item.get("supported_tls_versions")), None)
            if endpoint:
                observations.append({"host": mx_host, "port": int(endpoint["port"]), "status": "observed",
                                     "tls_versions": list(endpoint.get("supported_tls_versions", [])),
                                     "message": "TLS was observed by the existing SMTP STARTTLS scan."})
            elif matches:
                observations.append({"host": mx_host, "port": int(matches[0]["port"]), "status": "indeterminate",
                                     "tls_versions": [], "message": "An SMTP endpoint was scanned, but no successful TLS version was observed."})
            else:
                observations.append({"host": mx_host, "port": None, "status": "not_tested", "tls_versions": [],
                                     "message": "No matching SMTP STARTTLS result exists in this scan."})
        domain_result["smtp_starttls"] = observations
