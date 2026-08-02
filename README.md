# DFIR Case Study #2: Malicious Scheduled Task Persistence & Volatile Memory Acquisition

## Executive Summary

A threat-hunting exercise was conducted on a Windows 11 Pro endpoint to investigate unauthorized persistence mechanisms. Analysis identified a malicious scheduled task configured to execute a hidden PowerShell process whenever a user logged on, providing an attacker with persistent execution across reboots.

Because advanced malware frequently resides only in volatile memory, live response procedures were initiated before any remediation activities. A physical memory image was successfully acquired using WinPmem to preserve volatile artifacts for future forensic analysis.

The investigation demonstrated how attackers combine Windows Scheduled Tasks with PowerShell to maintain persistence while minimizing user visibility. The exercise also reinforced the importance of preserving volatile evidence before altering a compromised system.

## Incident Overview

| Category | Details |
|---|---|
| Operating System | Windows 11 Pro |
| Attack Technique | Scheduled Task Persistence |
| Payload | Hidden PowerShell Process |
| Initial Access | Simulated |
| Acquisition Tool | WinPmem |
| Hash Algorithm | SHA-256 |
| MITRE ATT&CK | T1053.005, T1059.001 |

## 1. Threat Simulation

To create a controlled forensic scenario, a scheduled task was intentionally created to simulate attacker persistence.

The task was configured to execute PowerShell in the background every time a user logged on.

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -Command `"Start-Sleep -Seconds 3600`""

$trigger = New-ScheduledTaskTrigger -AtLogOn

Register-ScheduledTask `
    -TaskName "SystemTelemetryUpdate" `
    -Action $action `
    -Trigger $trigger `
    -User "SYSTEM"
```

### Why attackers use this technique

Scheduled Tasks provide several advantages for attackers:

- Survive system reboots
- Execute automatically
- Run under privileged accounts
- Blend with legitimate Windows administrative activity

**MITRE ATT&CK:**
- T1053.005 – Scheduled Task
- T1059.001 – PowerShell

## 2. Initial Detection

The investigation began by enumerating all scheduled tasks present on the endpoint.

```powershell
schtasks /query /fo LIST /v
```

Suspicious observations included:

- Unusual task name
- Execution using PowerShell
- Hidden execution window
- Automatic execution at logon
- SYSTEM privilege

The task's action contained:

```
powershell.exe -NoProfile -WindowStyle Hidden
```

Hidden PowerShell execution is a common behavioral indicator observed during persistence and malware deployment.

## 3. Scheduled Task Analysis

PowerShell was used to collect detailed metadata.

```powershell
Get-ScheduledTask -TaskName SystemTelemetryUpdate | Format-List *
```

**Key forensic findings:**

| Artifact | Finding |
|---|---|
| Task Name | SystemTelemetryUpdate |
| Account | NT AUTHORITY\SYSTEM |
| Trigger | At Logon |
| Action | powershell.exe |
| Window Style | Hidden |
| Profile Loading | Disabled |

### Analysis

Although the task name resembled legitimate Windows telemetry, closer inspection revealed several suspicious characteristics.

Legitimate Windows telemetry tasks generally execute signed Microsoft binaries rather than launching hidden PowerShell sessions from user-defined arguments.

## 4. Volatile Memory Acquisition

Before deleting the persistence mechanism, volatile memory was preserved.

Live memory acquisition is critical because many malware families operate entirely in RAM and disappear after reboot.

WinPmem was executed as Administrator.

```powershell
winpmem.exe -o memdump.raw --volume_copy
```

The acquisition completed successfully, producing:

```
memdump.raw
```

## 5. Evidence Integrity

To preserve evidentiary integrity, a SHA-256 hash of the memory image was generated immediately after acquisition.

```powershell
Get-FileHash .\memdump.raw -Algorithm SHA256
```

Example output:

```
SHA256
8D4D2A6E...
```

Generating cryptographic hashes ensures the evidence can later be verified as unmodified.

## 6. Remediation

After volatile evidence had been preserved, the malicious persistence mechanism was removed.

```powershell
Unregister-ScheduledTask `
    -TaskName "SystemTelemetryUpdate" `
    -Confirm:$false
```

Verification:

```powershell
schtasks /query | findstr SystemTelemetryUpdate
```

No results were returned, confirming successful removal.

## 7. MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|---|---|
| Scheduled Task Persistence | T1053.005 |
| PowerShell | T1059.001 |

## 8. Indicators of Compromise (IoCs)

| Indicator | Description |
|---|---|
| Scheduled Task | SystemTelemetryUpdate |
| Process | powershell.exe |
| Command Flags | -WindowStyle Hidden |
| Command Flags | -NoProfile |
| Trigger | At Logon |
| Account | NT AUTHORITY\SYSTEM |

## 9. Lessons Learned

The investigation highlighted several important DFIR principles:

- Scheduled Tasks remain a common persistence mechanism used by attackers.
- Hidden PowerShell execution should be treated as a high-confidence hunting indicator.
- Volatile memory should always be preserved before remediation whenever malware is suspected.
- Cryptographic hashing is essential for maintaining forensic integrity.
- Legitimate-looking task names should never be trusted without verification.

## 10. Conclusion

This investigation demonstrated how Windows Scheduled Tasks can be abused to establish persistence while leveraging PowerShell for stealthy execution. Through systematic evidence collection, scheduled task enumeration, live memory acquisition, evidence hashing, and controlled remediation, the simulated attack was successfully identified and contained without compromising forensic evidence.

The exercise reinforced core DFIR methodologies including live response, chain of custody, persistence analysis, and incident remediation.

## Skills Demonstrated

- Digital Forensics
- Incident Response
- Windows Internals
- Threat Hunting
- Live Response
- Memory Acquisition
- PowerShell
- WinPmem
- MITRE ATT&CK Mapping
- Evidence Preservation
- Chain of Custody

## References

- [MITRE ATT&CK – T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK – T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [WinPmem Documentation](https://github.com/Velocidex/WinPmem)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
