# 🛡️ Bastion — Home SOC & Detection Range

> An isolated, hands-on Security Operations Center built from scratch. Attacks are emulated against a **Sysmon-instrumented Windows endpoint**, telemetry flows into a **Wazuh SIEM**, and every attack is taken full-circle — **detection → investigation → MITRE ATT&CK mapping**. Built to practice the day-to-day work of a SOC analyst / junior detection engineer, and documented so the work is visible without logging in.

<!-- "Bastion" is just the project name — rename freely. -->

<p align="center">
  <img src="assets/architecture.svg" alt="SOC architecture: a Kali attacker emulates attacks against a Windows endpoint; Sysmon and Windows Security telemetry flow to a Wazuh SIEM where an analyst triages and investigates." width="100%">
</p>

<p align="center"><sub><b>Designed architecture (target).</b> The on-prem Wazuh half is built and verified today; the cloud Microsoft Sentinel half and the full AD domain are the documented roadmap — see <a href="#whats-built-today">status</a> below.</sub></p>

![Status](https://img.shields.io/badge/status-active-brightgreen)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.9-blue)
![ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK%20mapped-red)
![Detections](https://img.shields.io/badge/techniques%20verified-2-orange)
![Code](https://img.shields.io/badge/detection--as--code-Sigma%20%2F%20Wazuh%20%2F%20KQL-9cf)

---

## <a id="whats-built-today"></a>What's built today vs. planned

I designed the full dual-SIEM range up front, then build it in vertical slices. Here's the honest current state:

| Component | Status |
|---|---|
| Isolated host-only lab network (`10.0.10.0/24`, no internet route) | ✅ Built |
| **Wazuh 4.9 SIEM** (manager + indexer + dashboard) | ✅ Built |
| **Windows Server 2022 endpoint** — Sysmon (tuned config) + Wazuh agent | ✅ Built |
| **Kali attacker** on the lab network | ✅ Built |
| **T1059.001 Encoded PowerShell** — detected, investigated end-to-end | ✅ Verified |
| **T1110 Brute Force** — network attack from Kali, failed-logon burst detected | ✅ Verified |
| MITRE ATT&CK Navigator coverage layer | ✅ Built |
| Detection library (Sigma + Wazuh + Sentinel KQL) | ✅ Authored |
| Microsoft Sentinel (cloud SIEM, KQL) — *dual-SIEM half* | ⬜ Roadmap |
| Promote endpoint to an **Active Directory domain** + add a workstation | ⬜ Roadmap |
| More techniques (persistence, discovery, lateral movement, Kerberoasting) | ⬜ Roadmap |
| PowerShell Script Block Logging (Event 4104) + SOAR automation | ⬜ Roadmap |

---

## See it working

From the SIEM, to a monitored endpoint, to live detections — each image below is the lab actually running.

**1. The Wazuh SIEM monitoring the lab**

![Wazuh SIEM dashboard](screenshots/01-wazuh-siem-dashboard.png)

**2. A Windows endpoint reporting in — Sysmon + Wazuh agent**

![DC01 enrolled as an active agent](screenshots/02-dc01-endpoint-enrolled.png)

**3. Detection — encoded PowerShell (T1059.001)** · the base64 `-EncodedCommand` payload is captured right in the event for the analyst to decode

![Encoded PowerShell detection in Wazuh](screenshots/04-detection-encoded-powershell.png)

**4. Detection — brute force from Kali (T1110)** · a burst of failed logons (Event 4625); the `subStatus` field reveals valid-username / wrong-password

![Brute-force 4625 detection in Wazuh](screenshots/08-detection-bruteforce-4625.png)

---

## Why this is more than a tutorial lab

| Common entry-level lab | This lab |
|---|---|
| "I installed a SIEM and ran one script" | Each attack is taken **full-circle**: emulate → detect → **investigate** → map to ATT&CK |
| Detections live in screenshots | **Detection-as-code** — rules version-controlled here in **Sigma + Wazuh + KQL** formats |
| No framework mapping | **MITRE ATT&CK** matrix + an importable **Navigator coverage layer** |
| "The alert fired, done" | A real **incident report** with triage, a decoded payload, alert correlation, and a **false-positive disposition** |
| Only the happy path | Documents the **realistic debugging** when a rule *didn't* fire (raw-event inspection, rule precedence) |

---

## The core loop

```
emulate attack  →  endpoint telemetry (Sysmon / Windows Security)
       →  forwarded by the Wazuh agent  →  detection rule fires
       →  analyst triages  →  investigates (timeline, IOCs, scope)
       →  writes incident report  →  maps to MITRE ATT&CK  →  updates coverage map
```

Nothing stops at "the alert fired" — it always ends in a written investigation.

---

## Detections verified

| Technique | ATT&CK | Tactic | How it was caught | Writeup |
|---|---|---|---|---|
| Encoded PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Execution | Sysmon EID 1 → Wazuh rule (base64 `-EncodedCommand`) | [incident-001](investigations/incident-001-encoded-powershell.md) |
| Brute force | [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Access | `netexec` SMB from Kali → Windows 4625 burst in the SIEM | [incident-002](investigations/incident-002-brute-force.md) |

Full matrix (incl. roadmap techniques): [docs/ATTACK-MAPPING.md](docs/ATTACK-MAPPING.md) · Coverage heatmap: [mitre/bastion-coverage.json](mitre/bastion-coverage.json)

---

## Repository map

| Path | What's in it |
|---|---|
| [`docs/`](docs/) | Architecture, full build guide, ATT&CK attack→detection matrix |
| [`detections/`](detections/) | Detection library — one file per technique (Sigma + Wazuh + KQL, tuning notes) |
| [`investigations/`](investigations/) | Incident reports in real SOC-ticket format |
| [`emulation/`](emulation/) | Attack playbooks used to generate the telemetry |
| [`mitre/`](mitre/) | MITRE ATT&CK Navigator coverage layer (`.json`) |
| [`config/`](config/) | Sysmon config notes, agent config, logging-hardening script |
| [`screenshots/`](screenshots/) | Evidence — detections firing, dashboards, attacks |

---

## What this project demonstrates

- Standing up and operating a **SIEM** (Wazuh) end-to-end: log ingestion, agents, dashboards, custom rules
- **Endpoint telemetry engineering** with Sysmon (process creation, file creation) + Windows Security logs
- **Detection engineering** as code — authoring and testing rules, mapping to MITRE ATT&CK
- **Alert triage & investigation** — timelines, IOC analysis, decoding obfuscated payloads, correlating alerts, false-positive disposition
- **Detection debugging** — using raw-event inspection (`logall_json`) and understanding SIEM rule precedence
- **Adversary emulation** — local (PowerShell) and network-based (Kali / `netexec`) attacks against an instrumented target

---

## Safety & ethics

Everything here is **benign adversary *emulation* against my own isolated lab VMs** to generate detection telemetry — on a host-only network with no route to the internet or any third party. Simulated payloads carry `LAB-SIM` markers. Nothing here is weaponized or aimed at any system I don't own.

---

## Build it yourself

Step-by-step in [docs/BUILD.md](docs/BUILD.md) — from a 32 GB host with VirtualBox to a working SIEM ingesting attacks.
