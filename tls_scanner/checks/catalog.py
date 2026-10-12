"""
Catalogue of the complementary TLS checks and their execution for one endpoint.

The catalogue is the single description of what exists: the YAML parser, the WebUI profile
validation, the profile form (through the backend catalogue endpoint) and the reports all read it.
Adding a check in a later lot means writing its function and adding one `CheckSpec` line.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from .contracts import (
    DEFAULT_PROBE_TIMEOUT_SECONDS,
    DEFAULT_TIME_BUDGET_SECONDS,
    CheckContext,
    CheckFunction,
    CheckResult,
    run_check,
)
from .client_auth import CHECK_ID as CLIENT_AUTH_ID
from .client_auth import check_client_auth
from .early_data import CHECK_ID as EARLY_DATA_ID
from .early_data import check_early_data
from .groups import ECDHE_ID, FFDHE_ID, check_ecdhe_groups, check_ffdhe_groups
from .handshake import COMPRESSION_ID, EMS_ID, FALLBACK_ID, RENEGOTIATION_ID, check_extended_master_secret, check_fallback_scsv, check_renegotiation, check_tls_compression
from .identity import CHECK_ID as HOSTNAME_ID
from .identity import check_hostname_san
from .protocols import OPT_IN_PROTOCOLS, resolve_protocol
from .protocols.checks import applies as protocol_applies
from .protocols.checks import check_id as protocol_check_id
from .protocols.checks import make_check as make_protocol_check
from .sessions import DEFAULT_ATTEMPTS, DEFAULT_TICKET_WAIT_SECONDS, RESUMPTION_ID, TICKETS_ID, check_session_resumption, check_session_tickets
from .stapling import CHECK_ID as STAPLING_ID
from .stapling import check_ocsp_stapling

FAMILY_IDENTITY = "identity"
FAMILY_HANDSHAKE = "handshake"
FAMILY_GROUPS = "groups"
FAMILY_SESSIONS = "sessions"
FAMILY_AUTHENTICATION = "authentication"
FAMILY_PROTOCOLS = "protocols"
FAMILIES = (FAMILY_IDENTITY, FAMILY_HANDSHAKE, FAMILY_GROUPS, FAMILY_SESSIONS, FAMILY_AUTHENTICATION, FAMILY_PROTOCOLS)

TIMEOUT_RANGE = (1, 30)
BUDGET_RANGE = (10, 600)


@dataclass(frozen=True)
class OptionSpec:
    """A technical parameter of a check: validated by the common parser, shown in the profile's advanced options."""

    name: str
    kind: str  # "int" | "bool" | "ports"
    default: Any
    low: int | None = None
    high: int | None = None


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    family: str
    function: CheckFunction
    recommended: bool  # pre-selected for new profiles in the WebUI; never enabled for existing configurations
    options: tuple[OptionSpec, ...] = ()
    applies: Callable[[CheckContext], bool] | None = None  # False = the check does not concern this endpoint and is skipped


CATALOG: tuple[CheckSpec, ...] = (
    CheckSpec(HOSTNAME_ID, FAMILY_IDENTITY, check_hostname_san, True),
    CheckSpec(STAPLING_ID, FAMILY_IDENTITY, check_ocsp_stapling, True),
    CheckSpec(COMPRESSION_ID, FAMILY_HANDSHAKE, check_tls_compression, True),
    CheckSpec(RENEGOTIATION_ID, FAMILY_HANDSHAKE, check_renegotiation, True),
    CheckSpec(FALLBACK_ID, FAMILY_HANDSHAKE, check_fallback_scsv, True),
    CheckSpec(EMS_ID, FAMILY_HANDSHAKE, check_extended_master_secret, True),
    CheckSpec(ECDHE_ID, FAMILY_GROUPS, check_ecdhe_groups, False),
    CheckSpec(FFDHE_ID, FAMILY_GROUPS, check_ffdhe_groups, False),
    CheckSpec(RESUMPTION_ID, FAMILY_SESSIONS, check_session_resumption, True, (
        OptionSpec("attempts", "int", DEFAULT_ATTEMPTS, 1, 3),
        OptionSpec("ticket_wait_seconds", "int", DEFAULT_TICKET_WAIT_SECONDS, 0, 10),  # also used by session_tickets (shared probes)
    )),
    CheckSpec(TICKETS_ID, FAMILY_SESSIONS, check_session_tickets, True),
    CheckSpec(EARLY_DATA_ID, FAMILY_SESSIONS, check_early_data, True, (
        OptionSpec("probe", "bool", False),  # deep acceptance probe: sends an empty line as early data; off by default
        OptionSpec("ticket_wait_seconds", "int", 3, 0, 10),
    )),
    CheckSpec(CLIENT_AUTH_ID, FAMILY_AUTHENTICATION, check_client_auth, True),
    *(
        CheckSpec(protocol_check_id(protocol), FAMILY_PROTOCOLS, make_protocol_check(protocol), True, (OptionSpec("ports", "ports", ()),), protocol_applies(protocol))
        for protocol in OPT_IN_PROTOCOLS
    ),
)
CHECK_IDS = tuple(spec.check_id for spec in CATALOG)


CHECK_LABELS = {
    HOSTNAME_ID: "FQDN / SAN identity",
    STAPLING_ID: "OCSP stapling",
    COMPRESSION_ID: "TLS compression",
    RENEGOTIATION_ID: "Renegotiation",
    FALLBACK_ID: "TLS_FALLBACK_SCSV",
    EMS_ID: "Extended Master Secret",
    ECDHE_ID: "ECDHE groups",
    FFDHE_ID: "FFDHE / DH parameters",
    RESUMPTION_ID: "TLS session resumption",
    TICKETS_ID: "TLS session tickets",
    EARLY_DATA_ID: "TLS 1.3 early data (0-RTT)",
    CLIENT_AUTH_ID: "Client authentication (mTLS)",
    **{protocol_check_id(protocol): f"{protocol.upper() if protocol != 'postgres' else 'PostgreSQL'} STARTTLS" for protocol in OPT_IN_PROTOCOLS},
}


def summarize_observations(observations: dict) -> str:
    """Flat `key: value` text of the scalar / list-of-scalar observations (for text reports)."""
    parts = []
    for key, value in (observations or {}).items():
        if value is None or isinstance(value, dict):
            continue
        if isinstance(value, (list, tuple)):
            if any(isinstance(item, (dict, list)) for item in value):
                continue
            value = ", ".join(str(item) for item in value) or "none"
        parts.append(f"{key}: {value}")
    return " · ".join(parts)


def catalog_as_dicts() -> list[dict]:
    return [
        {
            "id": spec.check_id,
            "family": spec.family,
            "recommended": spec.recommended,
            "options": [{"name": o.name, "kind": o.kind, "default": list(o.default) if o.kind == "ports" else o.default, "min": o.low, "max": o.high} for o in spec.options],
        }
        for spec in CATALOG
    ]


def run_complementary_checks(
    selected,
    host: str,
    port,
    reference_names=(),
    sni: str = "",
    observed_versions=(),
    timeout_seconds: int = DEFAULT_PROBE_TIMEOUT_SECONDS,
    budget_seconds: int = DEFAULT_TIME_BUDGET_SECONDS,
    cancel_event=None,
    options: dict[str, dict] | None = None,
) -> tuple[CheckResult, ...]:
    """Run the selected checks one after the other for one endpoint, within one time budget.

    `options` holds the technical parameters explicitly set per check (defaults come from the catalogue).
    Checks that do not concern the endpoint (a STARTTLS protocol check on another port) are skipped."""
    options = options or {}
    chosen = set(selected)
    context = CheckContext(
        host=host,
        port=int(port),
        reference_names=tuple(reference_names),
        sni=sni,
        observed_versions=tuple(observed_versions),
        timeout_seconds=timeout_seconds,
        deadline=time.monotonic() + budget_seconds,
        cancel_event=cancel_event,
        starttls_protocol=resolve_protocol(port, chosen, options),
    )
    results = []
    for spec in CATALOG:
        if spec.check_id not in chosen:
            continue
        scoped = replace(context, options=dict(options.get(spec.check_id, {})))  # same shared cache, own parameters
        if spec.applies is not None and not spec.applies(scoped):
            continue
        results.append(run_check(spec.check_id, spec.function, scoped))
    return tuple(results)
