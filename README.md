This template is structured for direct upload to your GitHub repository (e.g., DFIR-Case-02-Scheduled-Tasks-Memory), complete with image anchors linked to a local screenshots/ directory.
Markdown

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

3. Investigation & Forensic Analysis
Methodology A: Task Scheduler & Command Line Inspection

Static analysis using schtasks and PowerShell exposed the persistent configuration details:

    Task Name: SystemTelemetryUpdate

    Account Context: NT AUTHORITY\SYSTEM

    Trigger: At Interactive Logon

    Action/Arguments: powershell.exe -NoProfile -WindowStyle Hidden ...

    Forensic Finding: Execution flags like -WindowStyle Hidden and -NoProfile are high-fidelity indicators used by attackers to execute secondary payloads without alerting the logged-in user.

Methodology B: Volatile Memory Acquisition (WinPmem)

To capture volatile memory artifacts before remediation, WinPmem was utilized to acquire a raw physical memory dump (memdump.raw).
Navigating Driver Block Policies

Due to modern Windows driver blocklists and hypervisor-protected code integrity (HVCI), native driver loading was executed with explicit privilege escalation:
DOS

winpmem.exe -o memdump.raw --volume_copy

Integrity Verification

Immediately following acquisition, a SHA-256 cryptographic hash was generated to establish a verifiable chain of custody:
PowerShell

Get-FileHash -Path .\memdump.raw -Algorithm SHA256 | Format-List

4. Remediation & Cleanup

    Unregister Malicious Task: Purged the unauthorized task via PowerShell:
    PowerShell

    Unregister-ScheduledTask -TaskName "SystemTelemetryUpdate" -Confirm:$false

    Task Scheduler Verification: Queried schtasks to confirm the persistence mechanism was completely removed.

    Artifact Archiving: Moved the captured memdump.raw and cryptographic hash manifest to secure forensic storage for off-host Volatility 3 parsing.

5. Key Incident Response Takeaways

    Monitor Hidden Execution Flags: PowerShell invocations containing -WindowStyle Hidden, -EncodedCommand, or -NoP should trigger immediate host-level SOC alerts.

    Preserve Volatile Evidence First: Always acquire physical RAM prior to terminating processes or deleting persistence mechanisms if advanced malware or in-memory injection is suspected.

    Chain of Custody Matters: Generating cryptographic hashes (SHA-256) immediately after volatile acquisition ensures legal and technical evidence integrity.


***

<ElicitationsGroup message="What would you like to do next?">
<Elicitation label="Generate a Sigma rule for hidden PowerShell scheduled tasks" query="Generate a Sigma rule for hidden PowerShell scheduled tasks" query_intent="CLICKABLE_SUGGESTION" />
<Elicitation label="Draft a LinkedIn post summarizing Case 2" query="Draft a LinkedIn post summarizing Case 2" query_intent="CLICKABLE_SUGGESTION" />
<Elicitation label="Draft Volatility 3 commands to analyze the raw memory dump" query="Draft Volatility 3 commands to analyze the raw memory dump" query_intent="CLICKABLE_SUGGESTION" />
</ElicitationsGroup>
