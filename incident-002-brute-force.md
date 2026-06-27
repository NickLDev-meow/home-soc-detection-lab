# INC-002 — SMB Brute Force Against Local Administrator on DC01

**Classification:** Lab exercise. A T1110 simulation: ran an authenticated SMB password-guessing attack from a lab Kali host against an owned, isolated Windows target to validate failed-logon detection.

| | |
|---|---|
| Incident ID | INC-002 |
| Date (UTC) | 2026-06-27 |
| Analyst | Nick |
| Target host | DC01 / `WIN-N2HLCR2J87K` — 10.0.10.20, Windows Server 2022 Std, Wazuh agent 001 |
| Targeted account | `WIN-N2HLCR2J87K\Administrator` (local) |
| Source | 10.0.10.30 (Kali attacker) |
| Technique | T1110 — Brute Force (Credential Access) |
| Detecting source | Windows Security log, Event ID 4625, forwarded by Wazuh agent |
| Disposition | True positive (simulated) |
| Status | Closed |

## Summary

A burst of failed-logon events (Event ID 4625) was generated on DC01 from a single source, `10.0.10.30`, all targeting the local `Administrator` account over SMB. The failure substatus (`0xC000006A` — bad password) confirms the account name is valid and the password was wrong on every attempt: a targeted password-guessing attack against a known privileged account. The activity was the expected result of a controlled `netexec` SMB brute force run from the Kali host.

## Telemetry

- Source: Windows **Security** event log, **Event ID 4625** (an account failed to log on).
- Forwarding: Wazuh agent on DC01 → Wazuh manager (10.0.10.10).
- Prerequisite: "Logon" failure auditing enabled on DC01 (`auditpol`); DC01 firewall opened for SMB (File and Printer Sharing) so the authentication attempts reach the host.

## Detection

The attack produced a cluster of 4625 events in a short window, all sharing the same source IP and target account — the signature of a brute force.

![Failed-logon (4625) event in Wazuh Discover showing the source IP, target account, and failure substatus](/screenshots/08-detection-bruteforce-4625.png)

Key fields from a representative event:

| Field | Value | Meaning |
|---|---|---|
| `data.win.system.eventID` | 4625 | Failed logon |
| `data.win.eventdata.targetUserName` | Administrator | Account targeted |
| `data.win.eventdata.ipAddress` | 10.0.10.30 | Source (Kali attacker) |
| `data.win.eventdata.logonType` | 3 | Network logon (SMB) |
| `data.win.eventdata.authenticationPackageName` | NTLM | Auth protocol |
| `data.win.eventdata.subStatus` | 0xC000006A | **Valid username, bad password** |

## Analysis


| Substatus | Meaning | Signal |
|---|---|---|
| **0xC000006A** | Username valid, **password wrong** | Attacker is guessing passwords for a **real** account → higher risk |
| 0xC0000064 | **Username does not exist** | Name spraying / enumeration |
| 0xC0000234 | Account **locked out** | Lockout policy engaged |
| 0xC0000072 | Account **disabled** | |

Every event here returned **0xC000006A** against `Administrator`. That distinguishes this from a spray of random usernames: the attacker is hammering a **known-good, privileged** account.

### Scope
- Single source IP (`10.0.10.30`), single target account (`Administrator`), `LogonType 3` (network/SMB), NTLM.
- No successful logon (4624) from that source followed the failures → **no compromise**.


## IOCs

| Type | Value | Note |
|---|---|---|
| Source IP | 10.0.10.30 | Originating host of the failed logons (lab attacker) |
| Targeted account | `Administrator` | Privileged local account |
| Pattern | Repeated 4625 / `LogonType 3` / NTLM from one IP to one account | Brute-force signature |

## Containment / remediation

None required — simulation, no successful authentication. For a real true positive: block the source IP at the firewall, confirm the account was not compromised (check for a subsequent 4624 from the same IP), reset the account's password if any doubt, and enforce a lockout threshold to throttle guessing.

## Detection notes

- Windows native 4625 logging + the Wazuh agent's Security-channel forwarding were sufficient to surface this with no custom rule. Wazuh's built-in authentication-failure rules also correlate repeated 4625s into a higher-severity alert.


