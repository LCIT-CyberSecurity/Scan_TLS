#!/usr/bin/env python3
"""Small read-only LLDP-MIB fixture for the isolated integration stack."""
from __future__ import annotations

import sys

local_root = "1.0.8802.1.1.2.1.3.7.1.3"
remote_root = "1.0.8802.1.1.2.1.4.1.1"
table = {
    f"{local_root}.7": ("string", "GigabitEthernet0/1"),
    f"{remote_root}.4.0.7.1": ("integer", "4"),
    f"{remote_root}.5.0.7.1": ("string", "00:11:22:33:44:55"),
    f"{remote_root}.7.0.7.1": ("integer", "5"),
    f"{remote_root}.8.0.7.1": ("string", "GigabitEthernet0/2"),
    f"{remote_root}.9.0.7.1": ("string", "fixture-edge-switch"),
}
table = {oid: value for oid, value in table.items() if sys.argv[-1] == "remote" and oid.startswith(remote_root) or sys.argv[-1] == "local" and oid.startswith(local_root)}

for line in sys.stdin:
    command = line.strip()
    if command == "PING":
        print("PONG", flush=True)
        continue
    if command not in {"get", "getnext"}:
        print("NONE", flush=True)
        continue
    requested = sys.stdin.readline().strip().lstrip(".")
    candidates = sorted(oid for oid in table if (oid == requested if command == "get" else oid > requested))
    if not candidates:
        print("NONE", flush=True)
        continue
    oid = candidates[0]
    kind, value = table[oid]
    print(f".{oid}\n{kind}\n{value}", flush=True)
