#!/usr/bin/env python3
"""
Sigma-style field matching example.

Demonstrates how to use the fields: section in .syara rules to match
structured event data (log entries, alerts, API payloads) by key:value pairs.

Run from the repo root:
    source venv/bin/activate
    python examples/field_matching.py
"""

import syara

# ─────────────────────────────────────────────────────────────────────────────
# 1. Define rules with a fields: section
# ─────────────────────────────────────────────────────────────────────────────

RULES = syara.compile_string('''
    // Detects failed logon events targeting privileged accounts (Sigma T1110)
    rule FailedLogon : endpoint authentication {
        meta:
            description = "Failed logon targeting admin accounts"
            mitre       = "T1110"

        fields:
            $evt  = EventID        = "4625"
            $type = LogonType      = "3"
            $user = TargetUserName = /^(admin|administrator|root)$/i

        condition:
            $evt and $type and $user
    }

    // Detects known attacker tools by process name + event ID
    rule SuspiciousProcess : endpoint execution {
        meta:
            description = "Attacker tool execution (Mimikatz, PsExec, etc.)"
            mitre       = "T1059"

        fields:
            $proc = process.name = /^(mimikatz|psexec|wce|pwdump)\.exe$/i
            $evt  = EventID      = "4688"

        strings:
            $cmd = /lsadump|sekurlsa|pass-the-hash/i

        condition:
            $evt and ($proc or $cmd)
    }

    // Detects SMB lateral movement from RFC-1918 source
    rule LateralMovementSMB : network {
        meta:
            description = "SMB lateral movement from internal IP"
            mitre       = "T1021.002"

        fields:
            $port  = destination.port = "445"
            $proto = network.protocol = "smb" nocase
            $src   = source.ip = /^(10\.|192\.168\.)/

        condition:
            $port and $proto and $src
    }
''')


# ─────────────────────────────────────────────────────────────────────────────
# 2. Simulate a stream of log events
# ─────────────────────────────────────────────────────────────────────────────

EVENTS = [
    # Should trigger FailedLogon
    {
        "EventID":        "4625",
        "LogonType":      "3",
        "TargetUserName": "Administrator",
        "message":        "",
    },
    # Should trigger SuspiciousProcess (process.name match)
    {
        "EventID":      "4688",
        "process.name": "mimikatz.exe",
        "message":      "Process created",
    },
    # Should trigger SuspiciousProcess ($cmd string match)
    {
        "EventID": "4688",
        "message": "Process run with lsadump::sam arguments",
    },
    # Should trigger LateralMovementSMB
    {
        "destination.port": "445",
        "network.protocol": "SMB",
        "source.ip":        "192.168.1.50",
        "message":          "",
    },
    # Clean event — should not trigger anything
    {
        "EventID":        "4624",
        "LogonType":      "2",
        "TargetUserName": "alice",
        "message":        "Logon successful",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Process events
# ─────────────────────────────────────────────────────────────────────────────

print("=" * 60)
print("SYara — Sigma-style Fields Matching Demo")
print("=" * 60)

for i, event in enumerate(EVENTS, 1):
    text   = event.get("message", "")
    fields = {k: v for k, v in event.items() if k != "message"}

    hits = RULES.match_any(text, fields=fields)

    status = "ALERT" if hits else "  OK "
    print(f"\nEvent {i}: [{status}]")
    print(f"  {event}")

    for match in hits:
        print(f"  → Rule: {match.rule_name}  tags={match.tags}")
        for idf, details in match.matched_patterns.items():
            if details:
                print(f"     {idf}: matched '{details[0].matched_text}'")

print("\n" + "=" * 60)
total_alerts = sum(1 for e in EVENTS
                   if RULES.matched(e.get("message", ""),
                                    fields={k: v for k, v in e.items() if k != "message"}))
print(f"Total events: {len(EVENTS)}  |  Alerts: {total_alerts}")
