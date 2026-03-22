# 🛡️ Azure SOC Home Lab — Incident Response Project

> **A hands-on cybersecurity lab simulating a real-world multi-stage attack chain: RDP brute force leading to credential compromise, followed by post-exploitation PowerShell execution and persistence establishment. Full detection and incident response conducted using Microsoft Sentinel, Log Analytics Workspace, and Event Viewer.**

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Lab Architecture](#lab-architecture)
- [Tools & Technologies](#tools--technologies)
- [Attack Chain Overview](#attack-chain-overview)
- [Phase 1 — Environment Setup](#phase-1--environment-setup)
- [Phase 2 — Attack Stage 1: RDP Brute Force](#phase-2--attack-stage-1-rdp-brute-force)
- [Phase 3 — Attack Stage 2: Post-Exploitation PowerShell Execution](#phase-3--attack-stage-2-post-exploitation-powershell-execution)
- [Phase 4 — Detection & Alert Triage (Microsoft Sentinel)](#phase-4--detection--alert-triage-microsoft-sentinel)
- [Phase 5 — Investigation (Log Analytics Workspace)](#phase-5--investigation-log-analytics-workspace)
- [Phase 6 — Incident Response](#phase-6--incident-response)
  - [Containment](#containment)
  - [Eradication](#eradication)
  - [Recovery](#recovery)
- [Phase 7 — Detection Engineering](#phase-7--detection-engineering)
- [Phase 8 — Lessons Learned](#phase-8--lessons-learned)
- [KQL Queries Reference](#kql-queries-reference)
- [Incident Summary Report](#incident-summary-report)

---

## Project Overview

This project simulates a realistic, multi-stage attack scenario inside an isolated Azure environment. An attacker Linux VM first performs a **brute force attack** against an RDP endpoint to compromise credentials. After gaining access, the attacker moves into the **post-exploitation phase** — executing obfuscated PowerShell commands, establishing persistence mechanisms, and creating a backdoor admin account. These are techniques commonly observed in real-world intrusions.

The entire detection and incident response workflow is conducted using enterprise-grade tools: **Microsoft Sentinel**, **Log Analytics Workspace**, and **Windows Event Viewer**. After containing and eradicating the threat, custom **Sentinel analytic rules** are built to detect these techniques going forward.

This lab demonstrates skills directly relevant to:
- SOC Analyst roles (Tier 1 & 2)
- Incident Response
- SIEM alert triage and investigation
- Detection Engineering
- CySA+ exam objectives

---

## Lab Architecture

```
Azure Resource Group: rg-ir-lab
│
└── Virtual Network: vnet-ir-lab
    │
    ├── Subnet 1 — Victim Subnet (10.0.1.0/24)
    │   └── win-victim (Windows Server)
    │       └── NSG: nsg-victim
    │           └── Inbound: RDP allowed (initially), blocked post-incident
    │
    └── Subnet 2 — Attacker Subnet (10.0.2.0/24)
        └── linux-attacker-vm (Ubuntu)
            └── NSG: nsg-attacker
```

> Both VMs are on **separate subnets** with **separate NSGs** to simulate a segmented network environment and allow for precise containment via NSG rules.

---

## Tools & Technologies

| Category | Tool |
|---|---|
| Cloud Platform | Microsoft Azure |
| SIEM | Microsoft Sentinel |
| Log Management | Log Analytics Workspace |
| Windows Logging | Event Viewer (Windows Security Logs) |
| Attack Platform | Linux (Ubuntu) — Hydra for brute force |
| Query Language | KQL (Kusto Query Language) |
| IR Framework | NIST SP 800-61 Incident Response Lifecycle |

---

## Attack Chain Overview

This lab simulates a complete attack chain from initial access through persistence establishment:

```
Stage 1: Initial Access
└── Hydra brute forces RDP credentials on win-victim
    └── 99 failed logon attempts in 6 seconds (Event ID 4625)
        └── Successful RDP login at 13:22:19 UTC (Event ID 4624)
            │
            ▼
Stage 2: Post-Exploitation (via RDP session as cybershedd)
├── Encoded PowerShell command executed       → Event ID 4688
├── Malicious scheduled task created          → Event ID 4698
├── Backdoor user account created             → Event ID 4720
└── Backdoor user added to Administrators     → Event ID 4732
    │
    ▼
Stage 3: Detection & Incident Response
├── Sentinel alert fires on brute force volume
├── KQL investigation confirms credential compromise
├── KQL investigation uncovers persistence mechanisms
├── Containment: NSG rule blocks attacker subnet
├── Eradication: Credentials rotated, policies hardened,
│   persistence mechanisms removed
├── Recovery: System verified clean, monitoring confirmed
└── Detection Engineering: Sentinel analytic rules deployed
```

### Full MITRE ATT&CK Mapping

| Tactic | Technique | ID | Simulated With |
|---|---|---|---|
| Initial Access | Brute Force: Password Guessing | T1110.001 | Hydra |
| Execution | PowerShell | T1059.001 | Encoded PowerShell |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 `-EncodedCommand` |
| Persistence | Scheduled Task/Job | T1053.005 | `schtasks` |
| Persistence | Create Account: Local Account | T1136.001 | `net user` |
| Privilege Escalation | Local Account — Admin Group | T1136.001 | `net localgroup administrators` |

---

## Phase 1 — Environment Setup

### Resources Deployed

1. **Resource Group:** `rg-ir-lab`
2. **Virtual Network:** `vnet-ir-lab`
   - Subnet 1 (Victim): `10.0.1.0/24`
   - Subnet 2 (Attacker): `10.0.2.0/24`
3. **VMs Deployed:**
   - `win-victim` — Windows Server (Target machine)
   - `linux-attacker-vm` — Ubuntu Linux (Attack machine)
4. **NSGs Configured:**
   - `nsg-victim` — attached to the victim subnet
   - `nsg-attacker` — attached to the attacker subnet
5. **Microsoft Sentinel** connected to a **Log Analytics Workspace**
6. Windows Security Event logs forwarded to Log Analytics via the **Azure Monitor Agent**

---

## Phase 2 — Attack Stage 1: RDP Brute Force

### Attack Execution

From `linux-attacker-vm`, Hydra was used to brute force RDP credentials on `win-victim`:

```bash
hydra -l cybershedd -P /usr/share/wordlists/rockyou.txt rdp://10.0.1.4
```

### What Happened

- **99 consecutive failed logon attempts** within a **6-second window**
- Attacker IP: `10.0.2.4`
- Target Account: `cybershedd`
- Target Device: `win-victim`
- **Successful logon recorded at `13:22:19` UTC** — credentials compromised
- Attacker establishes an RDP session into `win-victim` as `cybershedd` and moves to Stage 2

### Relevant Event IDs

| Event ID | Description |
|---|---|
| 4625 | An account failed to log on |
| 4624 | An account was successfully logged on |

---

## Phase 3 — Attack Stage 2: Post-Exploitation PowerShell Execution

After gaining RDP access via the compromised `cybershedd` account, the attacker simulates **post-exploitation activity** — techniques used in real intrusions for persistence and privilege escalation.

> ⚠️ All commands were executed in a controlled, isolated lab environment. They simulate attacker TTPs mapped to [MITRE ATT&CK](https://attack.mitre.org/).

### 3a. Encoded PowerShell Command Execution

Attackers use Base64 encoding to obfuscate commands and evade simple keyword-based detection.

```powershell
$command = "Write-Host 'Malicious payload executed'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -EncodedCommand $encoded
```

The resulting Base64 encoded payload (UTF-16LE):
```
VwByAGkAdABlAC0ASABvAHMAdAAgACcATQBhAGwAaQBjAGkAbwB1AHMAIABwAGEAeQBsAG8AYQBkACAAZQB4AGUAYwB1AHQAZQBkACcA
```

**MITRE:** T1059.001, T1027 | **Detection:** Event ID 4688

---

### 3b. Malicious Scheduled Task (Persistence)

Creates a startup task masquerading as a legitimate Windows process.

```powershell
schtasks /create /tn "WindowsUpdateHelper" `
  /tr "powershell.exe -WindowStyle Hidden -Command 'Write-Host backdoor'" `
  /sc onstart /ru SYSTEM
```

Runs on every reboot as `SYSTEM` — the highest privilege level on Windows. The name `WindowsUpdateHelper` is deliberately chosen to blend in (masquerading).

**MITRE:** T1053.005, T1036 | **Detection:** Event ID 4698

---

### 3c. Backdoor Local User Account (Persistence)

Creates a hidden admin account for re-entry even if the original compromised account is locked.

```powershell
net user backdooruser ******* /add
net localgroup administrators backdooruser /add
```

**MITRE:** T1136.001 | **Detection:** Event ID 4720 (user created), Event ID 4732 (added to Administrators)

---

### Evidence of Persistence Discovered

After executing the above, the following was confirmed in Log Analytics:

- **Event ID 4688** — Suspicious process captured showing encoded PowerShell execution under the `cybershedd` account
- **Event ID 4698** — `WindowsUpdateHelper` scheduled task found, set to run on startup as SYSTEM
- **Event ID 4720** — New account `backdooruser` identified, created shortly after the breach
- **Event ID 4732** — `backdooruser` confirmed added to the local Administrators group in the same timeframe

---

## Phase 4 — Detection & Alert Triage (Microsoft Sentinel)

### Alert Triggered in Sentinel

Microsoft Sentinel generated an alert for **high-volume failed logon attempts** from a single IP address.

**Alert Details:**

| Field | Value |
|---|---|
| Alert Type | Brute Force Attack — Windows |
| Attacker IP | 10.0.2.4 |
| Target Account | cybershedd |
| Target Device | win-victim |
| Failed Attempts | 99 |
| Start Time | 2026-03-21 13:22:13 UTC |
| End Time | 2026-03-21 13:22:19 UTC |
| Duration | ~6 seconds |
| Successful Logon | Yes — 13:22:19 UTC |

### Initial Triage

| Question | Answer |
|---|---|
| Are all failed logins from the same IP? | ✅ Yes — 10.0.2.4 |
| Was there a successful logon from the attacker IP? | ✅ Yes — confirmed breach |
| True Positive or False Positive? | ✅ **True Positive** |
| Immediate Action Required? | ✅ Yes |

**Verdict:** 99 consecutive failed logons in 6 seconds is consistent with automated brute force tooling. A successful login from the same IP confirms credential compromise. The investigation now expands to determine what the attacker did post-access.

---

## Phase 5 — Investigation (Log Analytics Workspace)

### Stage 1 — Confirm the Brute Force Breach

```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-03-21T13:22:00Z)
| where EventID in (4624, 4625)
| where AccountType == "User"
| where Account in ("cybershedd", "win-victim\\cybershedd")
| project TimeGenerated, EventID, Account, IpAddress, LogonType, Computer
| order by TimeGenerated asc
```

**Findings:**
```
Start Time (first failure):   2026-03-21 13:22:13 UTC
End Time (successful logon):  2026-03-21 13:22:19 UTC
Duration:                     6 seconds
Failed Attempts:              99
Attacker IP:                  10.0.2.4
Attacker Machine:             linux-attacker-vm
Compromised Account:          cybershedd
Target Device:                win-victim
Successful Login:             YES — at 13:22:19 UTC
```

**→ Confirmed breach. Investigation expands to post-exploitation activity.**

---

### Stage 2 — Hunt for Post-Exploitation Activity

With the breach confirmed, the investigation pivots to determine what the attacker did after gaining access.

**Detect encoded PowerShell (Event ID 4688):**

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any (
    "powershell", "-enc", "-EncodedCommand",
    "bypass", "hidden", "iex", "invoke-expression"
  )
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

Two suspicious logs returned. The Base64 payload was decoded (UTF-16LE) and confirmed to contain a malicious command executed under the `cybershedd` account.

**Find scheduled task creation (Event ID 4698):**

```kql
SecurityEvent
| where EventID == 4698
| project TimeGenerated, Computer, EventID, EventData
```

The `WindowsUpdateHelper` task was found, confirming persistence was established.

**Find new user accounts (Event ID 4720):**

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, TargetUserName, SubjectUserName
```

New account `backdooruser` discovered.

**Confirm backdoor user in Administrators (Event ID 4732):**

```kql
SecurityEvent
| where EventID == 4732
| where TargetUserName == "Administrators"
| project TimeGenerated, Computer, MemberName, SubjectUserName, TargetUserName
```

Confirmed — `backdooruser` added to local Administrators immediately after creation.

**→ Full attack chain confirmed. Brute force → RDP access → encoded PowerShell → scheduled task + backdoor admin account.**

---

## Phase 6 — Incident Response

Following the NIST SP 800-61 framework:

### Containment

**Goal:** Stop the attacker from maintaining access or moving laterally.

1. **Disabled the `cybershedd` account** temporarily to block attacker re-entry.
   >In a production environment this is mandatory. In this lab, the account was left enabled to preserve investigator RDP access.

2. **Created a deny-all NSG rule** on `nsg-victim` blocking RDP from the attacker subnet (`10.0.2.0/24`):
   - Direction: Inbound | Protocol: TCP | Port: 3389
   - Source: `10.0.2.0/24` | Action: **Deny** | Priority: 100

3. **Effect:** Isolates `win-victim` from the attacker subnet, blocking further RDP access and lateral movement.

---

### Eradication

**Goal:** Remove all attacker access and eliminate every established persistence mechanism.

1. **Remove all persistence mechanisms:**
   ```powershell
   schtasks /delete /tn "WindowsUpdateHelper" /f
   net user backdooruser /delete
   ```

2. **Block attacker IP `10.0.2.4`** via NSG deny rule on `nsg-victim`.

3. **Rotate `cybershedd` credentials** with a strong, complex password.

4. **Enforce password complexity policy:**
   - Minimum 12 characters, uppercase + lowercase + number + special character

5. **Enforce account lockout policy:**
   - Lockout threshold: 10 failed attempts
   - Lockout duration: 30 minutes | Reset counter after: 15 minutes

---

### Recovery

**Goal:** Verify the machine is clean and restore normal operations.

| Check | Event ID | Finding |
|---|---|---|
| Suspicious PowerShell / new processes | 4688 | ✅ Found, investigated, and removed |
| New user accounts created | 4720 | ✅ `backdooruser` found and deleted |
| Scheduled tasks created or modified | 4698, 4702 | ✅ `WindowsUpdateHelper` found and deleted |
| New services installed | 7045 | ✅ None found |
| Startup folder / file modifications | 4663 | ✅ None found |
| Audit logs cleared | 1102 / 104 | ✅ None — attacker did not cover tracks |

**Recovery Actions:**
1. Removed temporary NSG block rule to restore normal connectivity.
2. Re-enabled `cybershedd` account with new credentials.
3. Confirmed system operating normally.
4. Continued monitoring Sentinel for follow-up alerts.

---

## Phase 7 — Detection Engineering

Custom Sentinel analytic rules were created to detect these attack techniques going forward.

### Detection 1 — Encoded PowerShell Execution

**MITRE:** T1059.001 (PowerShell), T1027 (Command Obfuscation)

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4688
| where CommandLine has_any (
    "-EncodedCommand", "-enc", "-ec",
    "-WindowStyle Hidden", "-NonInteractive", "-NoProfile"
  )
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

---

### Detection 2 — New Local User Account Created

**MITRE:** T1136.001 (Persistence — Create Local Account)

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4720
| project TimeGenerated, Computer, TargetUserName, SubjectUserName, SubjectDomainName
| order by TimeGenerated desc
```

---

### Detection 3 — User Added to Administrators Group

**MITRE:** T1136.001, Privilege Escalation

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4732
| where TargetUserName == "Administrators"
| project TimeGenerated, Computer, MemberName, SubjectUserName, TargetUserName
| order by TimeGenerated desc
```


> To deploy as a live alert: **Sentinel → Analytics → Create → Scheduled query rule**, threshold = `Results > 0`.

---

## Phase 8 — Lessons Learned

### What Went Well
- Sentinel triggered an alert quickly after the brute force began.
- KQL queries allowed fast, precise scoping of the full attack timeline.
- NSG rules provided an effective and immediate containment mechanism.
- Post-exploitation persistence was caught during the expanded investigation phase.

### Gaps Identified & Remediations

| Gap | Recommended Fix |
|---|---|
| No account lockout policy | Enforce lockout after 5–10 failed attempts across all accounts |
| Weak password allowed brute force success | Enforce minimum 12-character complex passwords via Group Policy |
| No MFA on RDP | Implement Azure AD MFA or require VPN + MFA before RDP 
| RDP exposed to internal subnet without restriction | Restrict RDP to trusted IPs only or use Azure Bastion |
| No alerting on, suspicious powershell usage, new user creation or group changes | Deploy Sentinel analytic rules (Phase 7) |

### Defensive Recommendations

```
1. Enable Account Lockout Policy (GPO)
   Computer Configuration → Windows Settings → Security Settings
   → Account Policies → Account Lockout Policy

4. Deploy Sentinel Analytic Rules (Phase 7 queries)
   Sentinel → Analytics → Create → Scheduled query rule

5. Consider deploying Microsoft Defender for Endpoint
   for richer telemetry and automated response capabilities.
```

---

## KQL Queries Reference

### Brute Force Detection
```kql
SecurityEvent
| where TimeGenerated >= datetime(2026-03-21T13:22:00Z)
| where EventID in (4624, 4625)
| where AccountType == "User"
| where Account in ("cybershedd", "win-victim\\cybershedd")
| project TimeGenerated, EventID, Account, IpAddress, LogonType, Computer
| order by TimeGenerated asc
```

### Failed Login Count by IP (Last 1 Hour)
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account, Computer
| where FailedAttempts > 10
| order by FailedAttempts desc

### Suspicious PowerShell Process Creation
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4688
| where CommandLine has_any (
    "powershell", "-enc", "-EncodedCommand",
    "bypass", "hidden", "iex", "invoke-expression", "downloadstring"
  )
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

### Scheduled Task Created
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4698
| project TimeGenerated, Computer, Account, EventData
```

### New User Account Created
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4720
| project TimeGenerated, Computer, TargetUserName, SubjectUserName, SubjectDomainName
```

### User Added to Administrators Group
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4732
| where TargetUserName == "Administrators"
| project TimeGenerated, Computer, MemberName, SubjectUserName, TargetUserName
```

---

## Incident Summary Report

| Field | Details |
|---|---|
| **Incident ID** | INC-2026-001 |
| **Date** | March 21, 2026 |
| **Classification** | True Positive |
| **Attack Type** | Brute Force + Post-Exploitation (Persistence) |
| **Attacker IP** | 10.0.2.4 (linux-attacker-vm) |
| **Victim** | win-victim (10.0.1.4) |
| **Compromised Account** | cybershedd |
| **Brute Force Duration** | ~6 seconds |
| **Failed Attempts** | 99 |
| **Breach Confirmed** | Yes — successful RDP login at 13:22:19 UTC |
| **Post-Exploitation Activity** | Encoded PowerShell, scheduled task, backdoor user, admin escalation |
| **Persistence Found** | Yes — `WindowsUpdateHelper` task + `backdooruser` account |
| **Containment Method** | NSG deny rule + account disable |
| **Eradication Method** | Persistence removed + IP blocked + credential rotation + lockout policy |
| **Logs Cleared by Attacker** | No |
| **Status** | Resolved ✅ |

---

## Repository Structure

```
azure-soc-ir-lab/
├── README.md                              ← This document
├── screenshots/
│   ├── 01-resource-group.png
│   ├── 02-vnet-subnets.png
│   ├── 03-nsg-rules.png
│   ├── 04-sentinel-alert.png
│   ├── 05-brute-force-query.png
│   ├── 06-brute-force-results.png
│   ├── 07-powershell-encoded-command.png
│   ├── 08-powershell-4688-detection/TskSchd.png
│   ├── 09-base64-decode.png
│   ├── 10-new-user-4720.png
│   ├── 11-admin-group-4732.png
│   ├── 12-containment-nsg-rule.png
│   ├── 13-eradication-ip-block.png
│   ├── 14-password-policy.png
│   ├── 15-lockout-policy.png
│   ├── 16-sentinel-detection-powershell.png
│   ├── 17-sentinel-detection-new-user.png
│   └── 18-sentinel-detection-admin-group.png
└── kql/
    ├── brute_force_detection.kql
    ├── failed_logins_by_ip.kql
    ├── powershell_execution.kql
    ├── scheduled_task_created.kql
    ├── new_user_created.kql
    └── admin_group_membership_change.kql
```

---

*Built as a home lab project for CySA+ exam prep and SOC portfolio development.*

