"""Documented, deterministic evidence rules used by the hypothesis evaluator.

Each rule id is referenced from findings and stored on SUPPORTS/CONTRADICTS relationships.
Weights are ordinal heuristics, NOT calibrated probabilities.
"""
from __future__ import annotations

import ipaddress

OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"}
SCRIPT_INTERPRETERS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                       "rundll32.exe", "regsvr32.exe"}
EXECUTABLE_FILE_TYPES = {"dll", "exe", "ps1", "vbs", "js", "hta", "scr", "bat"}
ADMIN_TOOL_HINTS = ("admintools", "remote_admin", "sccm", "patch")
OBFUSCATION_FLAGS = ("-encodedcommand", "-enc ", "-windowstyle hidden", "-w hidden")

RULES: dict[str, dict] = {
    "R1": {"name": "Authentication origin from inventory", "kind": "inference",
           "text": "An authentication's source_ip equals an address the asset inventory assigns to a host; the "
                   "authentication is linked ORIGINATED_FROM that host. Caveat: DHCP/NAT can invalidate the mapping."},
    "C1": {"weight": 2, "text": "A document/office application is an ancestor of a script interpreter (process lineage)."},
    "C2": {"weight": 2, "text": "The seed process tree wrote a file with an executable type."},
    "C3": {"weight": 1, "text": "The seed process tree connected to a non-private, non-inventory network endpoint."},
    "C4": {"weight": 2, "text": "An identity authenticated from the seed host although its prior baseline shows only "
                               "other origin hosts."},
    "C5": {"weight": 1, "text": "Failed authentication(s) followed by success for the same identity and origin."},
    "C6": {"weight": 1, "text": "After an out-of-baseline authentication, the identity accessed files on the target host."},
    "C7": {"weight": 1, "text": "Script interpreter command line contains obfuscation/hidden-window flags."},
    "X1": {"weight": 2, "text": "An approved change record covers the seed host at the seed time."},
    "X2": {"weight": 1, "text": "The external endpoint was also contacted by other hosts (it may be a common service)."},
    "X3": {"weight": 0.5, "text": "The EDR alert was not high severity and the control allowed the activity."},
    "X4": {"weight": 2, "text": "The identity's prior baseline already includes this origin host."},
    "X5": {"weight": 1, "text": "The script interpreter was launched by signed administrative tooling, not a document "
                               "application."},
    "M1": {"text": "EDR sensor was offline on the seed host during part of the investigation window."},
    "M2": {"text": "No authentication telemetry from a domain controller is present."},
    "M3": {"text": "A parent process referenced by parent_process_id has no process-creation record."},
    "M4": {"text": "No authentication telemetry exists at all in this dataset."},
}


def basename(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def is_external(ip: str | None, inventory_owners: list | None = None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if inventory_owners:
        return False
    return not (addr.is_private and not _is_documentation(addr)) and not addr.is_loopback


def _is_documentation(addr) -> bool:
    # RFC 5737 ranges are flagged private by Python; in this synthetic dataset they model internet hosts.
    return any(addr in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def has_obfuscation(cmd: str | None) -> bool:
    c = (cmd or "").lower()
    return any(f in c for f in OBFUSCATION_FLAGS)


def is_admin_tool(path: str | None) -> bool:
    p = (path or "").lower()
    return any(h in p for h in ADMIN_TOOL_HINTS)
