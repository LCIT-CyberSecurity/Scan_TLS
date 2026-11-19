"""Bounded, passive lookalike-domain candidate generation for explicitly enabled monitoring.

This module only proposes names. It does not query DNS, CT or RDAP and therefore cannot create
network traffic unless a caller explicitly schedules an enabled monitor.
"""
from __future__ import annotations

import asyncio
import inspect
import secrets
from collections.abc import Iterable
from datetime import UTC, datetime
from difflib import SequenceMatcher
from typing import Any

import idna

from .model import DnsLookup, Lookup, LookupFailure
from .policy import DiscoveryError, is_public_domain, normalize_domain

# A conservative keyboard adjacency map; one edit per candidate keeps the result inspectable.
_ADJACENT = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}
_CONFUSABLES = {
    "a": "аα", "c": "сϲ", "e": "еε", "i": "іι", "j": "ј", "o": "оο",
    "p": "рρ", "s": "ѕ", "x": "хχ", "y": "у", "b": "Ь", "k": "κ",
}
_DEFAULT_TLDS = ("com", "net", "org", "io")
MAX_TLDS = 20
MAX_CANDIDATES = 200


async def _bounded_call(function, argument: str, timeout: float) -> Any:
    if inspect.iscoroutinefunction(function):
        return await asyncio.wait_for(function(argument), timeout=timeout)
    return await asyncio.wait_for(asyncio.to_thread(function, argument), timeout=timeout)


def _ascii_domain(value: str) -> str:
    """Strictly encode IDN input as lowercase IDNA labels and use the existing domain policy."""
    try:
        encoded = ".".join(idna.encode(label, uts46=False, std3_rules=True).decode("ascii") for label in value.strip().rstrip(".").split("."))
    except (idna.IDNAError, UnicodeError):
        raise DiscoveryError("The reference domain is not valid IDNA") from None
    return normalize_domain(encoded)


def validate_tlds(values: Iterable[str]) -> list[str]:
    out = []
    for value in values:
        tld = value.strip().lower().lstrip(".")
        if not tld or len(tld) > 63 or not tld.isascii() or any(not (c.isalnum() or c == "-") for c in tld) or tld.startswith("-") or tld.endswith("-"):
            raise DiscoveryError(f"Invalid lookalike TLD: {value[:40]!r}")
        if tld not in out:
            out.append(tld)
    if len(out) > MAX_TLDS:
        raise DiscoveryError(f"At most {MAX_TLDS} alternate TLDs may be monitored")
    return out


def generate_candidates(domain: str, *, tlds: Iterable[str] = (), max_candidates: int = 100,
                         exclusions: Iterable[str] = (), min_score: float = 0.0) -> list[dict[str, str | float]]:
    """Return deterministic one-edit labels, homoglyphs and configured TLD variants, strictly capped."""
    if not 1 <= max_candidates <= MAX_CANDIDATES:
        raise DiscoveryError(f"Candidate limit must be between 1 and {MAX_CANDIDATES}")
    if not 0 <= min_score <= 1:
        raise DiscoveryError("Similarity threshold must be between 0 and 1")
    canonical = _ascii_domain(domain)
    if not is_public_domain(canonical):
        raise DiscoveryError("Lookalike monitoring is limited to explicitly authorised public domains")
    labels = canonical.split(".")
    if len(labels) < 2:
        raise DiscoveryError("A registrable-looking public domain is required")
    stem, original_tld = labels[-2], labels[-1]
    excluded = {_ascii_domain(x) for x in exclusions if x.strip()}
    raw: dict[str, set[str]] = {}

    def add(name: str, kind: str) -> None:
        try:
            host = _ascii_domain(name)
        except DiscoveryError:
            return
        if host == canonical or host in excluded or not is_public_domain(host):
            return
        raw.setdefault(host, set()).add(kind)

    # Deletion, adjacent transposition, duplicate character, substitution and keyboard neighbor.
    for index, char in enumerate(stem):
        add(stem[:index] + stem[index + 1:] + "." + original_tld, "missing-character")
        add(stem[:index] + char + stem[index:] + "." + original_tld, "repeated-character")
        if index + 1 < len(stem):
            swapped = list(stem)
            swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
            add("".join(swapped) + "." + original_tld, "transposition")
        replacements = set(_ADJACENT.get(char, ""))
        replacements.update({"0" if char == "o" else "o"} if char == "o" else set())
        replacements.update({"1" if char in "il" else "i"} if char in "il" else set())
        for replacement in sorted(replacements):
            add(stem[:index] + replacement + stem[index + 1:] + "." + original_tld, "substitution")
        # Emit Unicode confusables as Punycode only; never emit visually confusable raw Unicode labels.
        for replacement in _CONFUSABLES.get(char, "")[:1]:
            add(stem[:index] + replacement + stem[index + 1:] + "." + original_tld, "idn-homoglyph")
        add(stem[:index] + "-" + stem[index:] + "." + original_tld, "hyphenation")
    for tld in validate_tlds(tlds):
        if tld != original_tld:
            add(stem + "." + tld, "alternate-tld")
    # Exclude wildcard-like/invalid/oversized names and return stable relevance ordering.
    ranked = sorted((item for item in raw.items() if SequenceMatcher(None, canonical, item[0]).ratio() >= min_score),
                    key=lambda item: (-max(SequenceMatcher(None, stem, item[0].split(".")[-2]).ratio(), 0.0), item[0]))
    return [{"domain": name, "score": round(SequenceMatcher(None, canonical, name).ratio(), 4),
             "techniques": ",".join(sorted(techniques))} for name, techniques in ranked[:max_candidates]]


async def observe_candidates(candidates: list[dict[str, Any]], *, lookup: Lookup | None = None,
                             ct_fetch=None, rdap_fetch=None, max_ct: int = 5, max_rdap: int = 10,
                             concurrency: int = 5, timeout_seconds: float = 3.0,
                             wildcard_records: dict[str, list[str]] | None = None,
                             should_stop=lambda: False) -> list[dict[str, Any]]:
    """Make bounded DNS observations and optional injected CT/RDAP lookups; callers gate this on an enabled monitor."""
    if len(candidates) > MAX_CANDIDATES or not 1 <= concurrency <= 10 or not 1 <= timeout_seconds <= 10:
        raise DiscoveryError("Lookalike observation exceeds the configured limits")
    if max_ct < 0 or max_ct > 5 or max_rdap < 0 or max_rdap > 10:
        raise DiscoveryError("CT and RDAP lookups are limited to five and ten candidates per run")
    lookup = lookup or DnsLookup(timeout=timeout_seconds, concurrency=concurrency, cache_size=MAX_CANDIDATES * 6)
    semaphore = asyncio.Semaphore(concurrency)
    ct_candidates = {c["domain"] for c in sorted(candidates, key=lambda x: (-float(x.get("score", 0)), x["domain"]))[:max_ct]} if ct_fetch else set()
    rdap_candidates = {c["domain"] for c in sorted(candidates, key=lambda x: (-float(x.get("score", 0)), x["domain"]))[:max_rdap]} if rdap_fetch else set()

    async def inspect(candidate: dict[str, Any]) -> dict[str, Any]:
        name = _ascii_domain(str(candidate["domain"]))
        if not is_public_domain(name):
            raise DiscoveryError("Non-public lookalike candidate rejected")
        records: dict[str, list[str]] = {}
        failed: list[str] = []
        present = 0
        if should_stop():
            return {"domain": name, "status": "cancelled", "dns_status": "inconclusive", "records": {},
                    "source": "DNS resolver", "observed_at": datetime.now(UTC).isoformat(),
                    "ct_status": "not_checked", "rdap_status": "not_checked", "errors": ["cancelled"], "malicious": False}
        async with semaphore:
            for kind in ("A", "AAAA", "CNAME", "MX", "NS"):
                if should_stop():
                    break
                try:
                    answer = await asyncio.wait_for(lookup.query(name, kind), timeout=timeout_seconds + 1)
                    records[kind] = answer.values[:8]
                    present += 1
                except LookupFailure as error:
                    if error.kind not in ("nxdomain", "nodata"):
                        failed.append(error.kind)
                except TimeoutError:
                    failed.append("timeout")
        cancelled = should_stop()
        dns_status = "resolved" if present else ("inconclusive" if failed or cancelled else "not_observed")
        observation: dict[str, Any] = {
            "domain": name, "status": "cancelled" if cancelled else ("suspect_to_review" if present else dns_status),
            "dns_status": dns_status, "records": records, "source": "DNS resolver", "observed_at": datetime.now(UTC).isoformat(),
            "score": float(candidate.get("score", 0)), "techniques": candidate.get("techniques", ""),
            "ct_status": "not_checked", "rdap_status": "not_checked", "errors": failed[:5],
            "malicious": False, "note": "Lookalike resemblance is not evidence of malicious intent.",
        }
        if cancelled:
            observation["errors"] = ["cancelled"]
            return observation
        if any(values and records.get(kind) == values for kind, values in (wildcard_records or {}).items()):
            observation.update(status="wildcard", wildcard=True,
                               note="DNS response matches the random wildcard probe; review manually.")
        if name in ct_candidates:
            try:
                raw = await _bounded_call(ct_fetch, name, timeout=8)
                observation.update(ct_status="observed" if raw else "not_observed", ct_names=min(len(raw), 100), ct_source="Certificate Transparency")
            except Exception as error:  # noqa: BLE001 - source failure is an explicit inconclusive result
                observation.update(ct_status="error", ct_error=type(error).__name__)
        if name in rdap_candidates:
            try:
                value = await _bounded_call(rdap_fetch, name, timeout=10)
                observation.update(rdap_status="registered" if value else "not_observed", rdap_source="RDAP")
            except Exception as error:  # noqa: BLE001 - source failure is an explicit inconclusive result
                observation.update(rdap_status="error", rdap_error=type(error).__name__)
        return observation

    tasks = [inspect(candidate) for candidate in candidates]
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=900)
    except TimeoutError:
        raise DiscoveryError("Lookalike observation exceeded the 15-minute run budget") from None
    out = []
    for candidate, result in zip(candidates, results):
        if isinstance(result, Exception):
            # Keep bad/unavailable observations distinct and never disclose exception messages.
            out.append({"domain": str(candidate.get("domain", ""))[:253], "status": "error", "dns_status": "inconclusive",
                        "records": {}, "source": "DNS resolver", "observed_at": datetime.now(UTC).isoformat(),
                        "errors": [type(result).__name__], "malicious": False})
        else:
            out.append(result)
    return out


async def run_monitor(domain: str, options: dict[str, Any], *, lookup: Lookup | None = None, ct_fetch=None,
                      should_stop=lambda: False) -> dict[str, Any]:
    """Run one bounded observation pass. The caller must re-check that the monitor is still enabled."""
    canonical = _ascii_domain(domain)
    candidates = generate_candidates(canonical, tlds=options.get("tlds", []),
                                     max_candidates=int(options.get("max_candidates", 50)),
                                     exclusions=options.get("exclusions", []),
                                     min_score=float(options.get("min_score", 0.0)))
    lookup = lookup or DnsLookup(timeout=min(10, int(options.get("timeout_seconds", 3))),
                                 concurrency=min(10, int(options.get("concurrency", 5))),
                                 cache_size=MAX_CANDIDATES * 6)
    wildcard_records: dict[str, list[str]] = {}
    probe = f"orion-{secrets.token_hex(8)}.{canonical}"
    for kind in ("A", "AAAA", "CNAME", "MX", "NS"):
        if should_stop():
            break
        try:
            answer = await asyncio.wait_for(lookup.query(probe, kind), timeout=min(10, int(options.get("timeout_seconds", 3))) + 1)
            if answer.values:
                wildcard_records[kind] = answer.values[:8]
        except (LookupFailure, TimeoutError):
            continue
    observations = await observe_candidates(
        candidates, lookup=lookup,
        ct_fetch=ct_fetch if options.get("ct_enabled", False) else None,
        rdap_fetch=None,  # no provider is configured; report RDAP as not checked, never infer registration
        max_ct=int(options.get("max_ct", 5)) if options.get("ct_enabled", False) else 0,
        max_rdap=0,
        concurrency=min(10, int(options.get("concurrency", 5))),
        timeout_seconds=min(10, int(options.get("timeout_seconds", 3))),
        wildcard_records=wildcard_records,
        should_stop=should_stop,
    )
    return {
        "domain": canonical, "monitor_version": 1, "generated": len(candidates), "observations": observations,
        "queries": getattr(lookup, "queries", 0), "completed_at": datetime.now(UTC).isoformat(),
        "sources": {"dns": True, "ct": bool(options.get("ct_enabled", False) and ct_fetch), "rdap": False},
        "partial": any(o.get("dns_status") == "inconclusive" or o.get("ct_status") == "error" or o.get("status") == "cancelled" for o in observations),
    }
