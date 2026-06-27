# T1110 — Brute Force & Password Spray

| | |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) (incl. .003 Password Spraying) |
| **Severity** | High |
| **Data source** | Windows Security log — 4625 (failed logon), 4624 (success), 4768/4769 (Kerberos) |
| **Status** | written · ⬜ verified in lab |

## Why this matters

Two distinct attacker behaviors live under T1110, and a good analyst distinguishes them:

- **Brute force (.001):** many password guesses against **one** account → a burst of 4625s for a single user.
- **Password spray (.003):** **one** common password tried against **many** accounts → 4625s spread thin across users, each below the lockout threshold. This is the stealthy one — it slips past per-account lockout policies and is how a lot of real account takeovers start.

The detection below catches **both**, and — critically — flags the dangerous case: a **spray that then succeeds** (failures across many users, followed by a 4624 success). That "failure burst → success" pivot is the alert you never want to miss.

## What "normal" vs. attack looks like

- **Benign:** a user fat-fingers a password 2–3 times, then logs in. One account, low count, quick success.
- **Brute force:** 20+ failures for `bastion\\admin` from one source in minutes.
- **Spray:** 1–2 failures each across 15+ accounts from one source IP/host in a short window.

## Detection logic A — failed-logon burst (brute force)

### Sentinel KQL
```kql
// T1110.001 Brute force — burst of failed logons for a single account
SecurityEvent
| where EventID == 4625                       // failed logon
| summarize Failures = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen  = max(TimeGenerated),
            SourceIPs = make_set(IpAddress, 10)
        by TargetAccount = TargetUserName, Computer
| where Failures >= 10                          // tune to your lockout policy
| where LastSeen - FirstSeen <= 10m
| order by Failures desc
```

### Wazuh
Wazuh ships built-in brute-force correlation (rules 60204/60122-class group `authentication_failures`). Add a lab-tuned override:
```xml
<group name="windows,authentication_failures,attack,t1110,">
  <rule id="100301" level="12" frequency="10" timeframe="600">
    <if_matched_sid>60122</if_matched_sid>   <!-- Windows logon failure -->
    <same_source_ip />
    <description>Brute force: 10+ Windows logon failures from same source (T1110.001)</description>
    <mitre><id>T1110.001</id></mitre>
  </rule>
</group>
```

## Detection logic B — password spray (the stealthy one)

```kql
// T1110.003 Password spray — one source failing against MANY distinct accounts
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress) and IpAddress != "-"
| summarize DistinctAccounts = dcount(TargetUserName),
            Accounts = make_set(TargetUserName, 25),
            Attempts = count()
        by IpAddress, bin(TimeGenerated, 15m)
| where DistinctAccounts >= 8                   // many users, few tries each = spray
| order by DistinctAccounts desc
```

## Detection logic C — spray that SUCCEEDED (highest priority)

```kql
// Failure burst across many accounts from an IP, THEN a successful logon from it
let window = 30m;
let sprays =
    SecurityEvent
    | where EventID == 4625
    | summarize FailedAccounts = dcount(TargetUserName) by IpAddress, bin(TimeGenerated, window)
    | where FailedAccounts >= 8
    | project IpAddress, sprayWindow = TimeGenerated;
let successes =
    SecurityEvent
    | where EventID == 4624 and LogonType in (3, 10)   // network / RDP
    | project IpAddress, SuccessTime = TimeGenerated, TargetUserName, Computer;
sprays
| join kind=inner successes on IpAddress
| where SuccessTime between (sprayWindow .. (sprayWindow + window))
| project IpAddress, CompromisedAccount = TargetUserName, Computer, sprayWindow, SuccessTime
```
> This is the rule to set as **High** severity with an incident — it represents a likely successful account takeover.

## False positives & tuning

| Noise source | Tuning |
|---|---|
| Service accounts with stale cached creds spamming 4625 | Allowlist the specific account+host, or exclude `LogonType 5` (service) |
| A locked-out user retrying | Per-account burst is expected; spray rule (distinct-account based) avoids this |
| Vuln scanners / NAC | Allowlist known scanner source IPs |
| Lockout threshold lower than `Failures >= 10` | Lower the threshold below your lockout policy so you alert before lockout |

## Validation
Run [`emulation/T1110-brute-force-spray.md`](../emulation/) from Kali, confirm A/B/C fire appropriately, screenshot to `assets/`, then write `investigations/incident-002-password-spray.md`.
