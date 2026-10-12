"""
Catalogue of the complementary TLS checks and their execution for one endpoint.

The catalogue is the single description of what exists: the YAML parser, the WebUI profile
validation, the profile form (through the backend catalogue endpoint) and the reports all read it.
Adding a check in a later lot means writing its function and adding one `CheckSpec` line.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .contracts import (
    DEFAULT_PROBE_TIMEOUT_SECONDS,
    DEFAULT_TIME_BUDGET_SECONDS,
    CheckContext,
    CheckFunction,
    CheckResult,
    run_check,
)
from .groups import ECDHE_ID, FFDHE_ID, check_ecdhe_groups, check_ffdhe_groups
from .handshake import COMPRESSION_ID, EMS_ID, FALLBACK_ID, RENEGOTIATION_ID, check_extended_master_secret, check_fallback_scsv, check_renegotiation, check_tls_compression
from .identity import CHECK_ID as HOSTNAME_ID
from .identity import check_hostname_san
from .stapling import CHECK_ID as STAPLING_ID
from .stapling import check_ocsp_stapling

FAMILY_IDENTITY = "identity"
FAMILY_HANDSHAKE = "handshake"
FAMILY_GROUPS = "groups"
FAMILIES = (FAMILY_IDENTITY, FAMILY_HANDSHAKE, FAMILY_GROUPS)

TIMEOUT_RANGE = (1, 30)
BUDGET_RANGE = (10, 600)


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    family: str
    function: CheckFunction
    recommended: bool  # pre-selected for new profiles in the WebUI; never enabled for existing configurations


CATALOG: tuple[CheckSpec, ...] = (
    CheckSpec(HOSTNAME_ID, FAMILY_IDENTITY, check_hostname_san, True),
    CheckSpec(STAPLING_ID, FAMILY_IDENTITY, check_ocsp_stapling, True),
    CheckSpec(COMPRESSION_ID, FAMILY_HANDSHAKE, check_tls_compression, True),
    CheckSpec(RENEGOTIATION_ID, FAMILY_HANDSHAKE, check_renegotiation, True),
    CheckSpec(FALLBACK_ID, FAMILY_HANDSHAKE, check_fallback_scsv, True),
    CheckSpec(EMS_ID, FAMILY_HANDSHAKE, check_extended_master_secret, True),
    CheckSpec(ECDHE_ID, FAMILY_GROUPS, check_ecdhe_groups, False),
    CheckSpec(FFDHE_ID, FAMILY_GROUPS, check_ffdhe_groups, False),
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
    return [{"id": spec.check_id, "family": spec.family, "recommended": spec.recommended} for spec in CATALOG]


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
) -> tuple[CheckResult, ...]:
    """Run the selected checks one after the other for one endpoint, within one time budget."""
    context = CheckContext(
        host=host,
        port=int(port),
        reference_names=tuple(reference_names),
        sni=sni,
        observed_versions=tuple(observed_versions),
        timeout_seconds=timeout_seconds,
        deadline=time.monotonic() + budget_seconds,
        cancel_event=cancel_event,
    )
    return tuple(run_check(spec.check_id, spec.function, context) for spec in CATALOG if spec.check_id in set(selected))
