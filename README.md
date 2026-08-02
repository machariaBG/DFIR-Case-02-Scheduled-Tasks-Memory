# DFIR Case Study #2: Malicious Scheduled Task Analysis & Volatile Memory Acquisition

## 1. Executive Summary
During a threat-hunting sweep on a Windows 11 Pro host, an unauthorized persistence mechanism was identified leveraging the Windows Task Scheduler. The scheduled task was configured to run a obfuscated PowerShell script out of a user profile space to maintain persistence across reboots. 

Additionally, because volatile artifacts could be lost upon system shutdown or reboot, live response procedures were initiated to perform RAM acquisition. Investigation confirmed a threat technique combining **Scheduled Task Persistence** ([MITRE ATT&CK T1053.053](https://attack.mitre.org/techniques/T1053/053/)) and **Command and Scripting Interpreter: PowerShell** ([MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)).

---

## 2. Threat Simulation (Attack Phase)
To establish known-good host baseline artifacts, the scheduled task persistence mechanism and memory payload were simulated in a controlled lab environment.

### Persistence Creation via PowerShell
A scheduled task named `SystemTelemetryUpdate` was injected into the host environment, configured to trigger at user logon and execute a background telemetry script:

```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "Start-Sleep -s 3600"'
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "SystemTelemetryUpdate" -Action $action -Trigger$trigger -User "SYSTEM"
