# INC-001 — Encoded PowerShell Execution on DC01


| | |
|---|---|
| Incident ID | INC-001 |
| Date (UTC) | 2026-06-27 |
| Analyst | Nick |
| Host | DC01 / `WIN-N2HLCR2J87K` — 10.0.10.20, Windows Server 2022 Std, Wazuh agent 001 |
| Account | `WIN-N2HLCR2J87K\Administrator` (local) |
| Technique | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Detecting rule | Wazuh 92057 (level 12) |
| Disposition | True positive (simulated). Concurrent rule 92213 alerts: false positive. |
| Status | Closed |

## Summary

PowerShell was executed on DC01 with a base64 `-EncodedCommand` argument — a technique used to obscure commands from log review. Wazuh rule 92057 alerted on the process creation; the rule fired six times across repeated test executions. The decoded payload was a whoami command executed through elevated powershell.

Two concurrent level-15 alerts (rule 92213, "executable dropped into folder used by malware") fired in the same window. Both were traced to PowerShell's own `__PSScriptPolicyTest_*.ps1` temp files which are as false positives.

## Telemetry

- Endpoint: Sysmon (SwiftOnSecurity config) — Event ID 1 (process creation), Event ID 11 (file creation).
- Forwarding: Wazuh agent 4.9.2, channel `Microsoft-Windows-Sysmon/Operational`.
- SIEM: Wazuh 4.9, manager 10.0.10.10, decoder `windows_eventchannel`.

## Detection

Rule 92057 (built-in), level 12, groups `sysmon, sysmon_eid1_detections, windows`, mapped to T1059.001. Matches a PowerShell process created with an encoded-command argument.

Triggering command (DC01):
```
powershell -NoProfile -EncodedCommand <dwBoAG8AYQBtAGkA>
```

Verification: `rule.id:92057` returned 6 hits in Discover — one per test execution.

![Encoded PowerShell detection — the decoded `-EncodedCommand` payload is visible in the Wazuh event](/screenshots/04-detection-encoded-powershell.png)


## Analysis

Assessing intent requires decoding the argument:
```
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<blob>'))
```
Decoded content: `whoami` / `Write-Host 'LAB-SIM T1059.001'` — a benign marker, no malicious action. In a real intrusion the decoded content would expose the actual payload (e.g. download cradle, in-memory loader).

Process context: `powershell.exe`, PID 3712, processGuid `{97423b1c-...-000000000200}`, parent `powershell.exe`. No child processes, network connections, or persistence mechanisms observed.

## False positives — rule 92213

| Field | Value |
|---|---|
| Rule | 92213, level 15 (Critical) |
| Event | Sysmon EID 11 (FileCreate) |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (PID 3712) |
| File | `C:\Users\Administrator\AppData\Local\Temp\__PSScriptPolicyTest_2w2ffblt.j05.ps1` |

Both alerts shared PID 3712 and processGuid `{...-000000000200}`, confirming a single source process rather than multiple events. `__PSScriptPolicyTest_*.ps1` is written by PowerShell on every launch to test the execution policy; its content is fixed and unrelated to the command executed. Rule 92213 alerts on any new script/executable in a temp path, so it flags this benign file. Disposition: false positive.

![Correlating the two critical alerts to a single process via processGuid in Wazuh Discover](/screenshots/05-investigation-correlation.png)

Decision: alert retained, not suppressed. The file is benign, but the rule offers low-cost visibility into temp-folder writes, and command-level visibility for PowerShell is already provided by process-creation telemetry (EID 1) and can be extended with Script Block Logging (EID 4104). The suppression rule below is recorded as an option if alert volume becomes a problem.

```xml
<!-- Optional: suppress the PowerShell execution-policy test file FP. Not applied. -->
<group name="sysmon,">
  <rule id="100210" level="0">
    <if_sid>92213</if_sid>
    <field name="win.eventdata.targetFilename">__PSScriptPolicyTest_</field>
    <description>Benign PowerShell ScriptPolicyTest temp file</description>
  </rule>
</group>
```

## IOCs

None. The encoded command was a controlled simulation; the temp file is known-good PowerShell behavior and is explicitly not an indicator.


## References
- Detection: [detections/T1059.001-encoded-powershell.md](/detections/T1059.001-encoded-powershell.md)
- Screenshots: [detection event](/screenshots/04-detection-encoded-powershell.png), [alert correlation](/screenshots/05-investigation-correlation.png)
