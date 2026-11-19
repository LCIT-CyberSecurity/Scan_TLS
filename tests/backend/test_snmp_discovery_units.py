from __future__ import annotations

import asyncio

import pytest

from orion_app.services import snmp_discovery as snmp


def test_lldp_numeric_oid_rows_are_joined_with_local_port_and_partial_fields() -> None:
    local = [(f"{snmp.LLDP_LOCAL_PORT}.0.7", "TenGigabitEthernet1/0/7")]
    rows = [
        (f"{snmp.LLDP_REMOTE}.4.0.7.1", "4"),
        (f"{snmp.LLDP_REMOTE}.5.0.7.1", "00:11:22:33:44:55"),
        (f"{snmp.LLDP_REMOTE}.8.0.7.1", "Ethernet1/4"),
        (f"{snmp.LLDP_REMOTE}.9.0.7.1", "core-switch"),
        ("1.3.6.1.2.1.1.1.0", "not an LLDP row"),
    ]

    parsed = snmp.parse_lldp_rows(rows, local)

    assert len(parsed) == 1
    assert parsed[0]["local_port"] == "TenGigabitEthernet1/0/7"
    assert parsed[0]["chassis_id"] == "00:11:22:33:44:55"
    assert parsed[0]["port_id"] == "Ethernet1/4"
    assert parsed[0]["system_name"] == "core-switch"


def test_snmp_collection_requires_server_side_authpriv_and_is_bounded() -> None:
    with pytest.raises(ValueError, match="authPriv"):
        asyncio.run(snmp.collect(["192.0.2.10"], "", "", ""))
    with pytest.raises(ValueError, match="between 1"):
        asyncio.run(snmp.collect([], "snmp-ro", "auth-key", "priv-key"))
    with pytest.raises(ValueError, match="between 1"):
        asyncio.run(snmp.collect(["192.0.2.10"] * (snmp.MAX_TARGETS + 1), "snmp-ro", "auth-key", "priv-key"))
