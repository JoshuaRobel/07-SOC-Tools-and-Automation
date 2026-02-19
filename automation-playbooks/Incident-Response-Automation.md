# Incident Response Automation Playbooks

**Version:** 1.3  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Automation Overview

Automated incident response playbooks enable rapid response without manual intervention, reducing MTTD and MTTR.

---

## Automated Playbook: Malware Detection

```
TRIGGER: Malware hash detected by EDR

Automated Actions (0-5 minutes):

1. IMMEDIATE ISOLATION:
   ├─ PowerShell script → Disable network interface
   ├─ Endpoint isolation → Prevents lateral movement
   ├─ Confirmation → Alert analyst via email
   └─ Manual override: Analyst can un-isolate within 30 min

2. EVIDENCE COLLECTION:
   ├─ Trigger forensic tools → Collect memory dump
   ├─ Disk imaging → Start (parallel, continues in background)
   ├─ Event log preservation → Copy to secure location
   └─ Backup: Prevent overwriting of logs

3. ALERT GENERATION:
   ├─ Create SIEM alert → Malware detected [hostname]
   ├─ Create incident ticket → Severity: HIGH
   ├─ Notify SOC team → Email + Slack alert
   └─ Page on-call analyst → If after hours

4. CONTEXT GATHERING:
   ├─ SIEM query → Find all logons from this user (7 days)
   ├─ SIEM query → Find all processes from this host (past 24h)
   ├─ Threat intel → Check file hash in VirusTotal
   ├─ Network analysis → Check for C2 connections
   └─ Compile report → Attach to ticket

Manual Review (5-15 minutes):

Analyst Actions:
├─ Review automated actions
├─ Verify incident is real (not false alarm)
├─ Review context information
├─ Determine containment strategy:
│  ├─ Keep isolated (rebuild)
│  ├─ Release from isolation (false positive)
│  └─ Further restrict (block other assets)
└─ Activate incident response team if needed

Expected Automation Benefits:
├─ MTTD (Mean Time to Detect): <5 minutes
├─ MTTR (Mean Time to Respond): <15 minutes
├─ Evidence Preservation: 100% (automated)
└─ SOC Team Efficiency: Reduced manual work by ~80%
```

---

## Automated Playbook: Brute Force Attack

```
TRIGGER: 15+ failed logon attempts (Event 4625) in 5 minutes

Automated Actions (0-3 minutes):

1. THREAT ASSESSMENT:
   ├─ SIEM query → Count failed logons by user/IP
   ├─ Threat intel → Check source IP reputation
   ├─ Context → Is this known attacker?
   └─ Decision → Continue automation or manual review?

2. ACCOUNT PROTECTION:
   ├─ Active Directory → DISABLE target account
   ├─ Confirmation → Email account owner
   ├─ Notification → "Your account was disabled due to attack"
   ├─ Instructions → "Contact helpdesk to re-enable"
   └─ Duration → 30 minutes (analyst can override)

3. ATTACKER BLOCKING:
   ├─ Firewall → Add source IP to blocklist
   ├─ Radius → Reject logons from source IP
   ├─ VPN → Disconnect if already authenticated
   └─ Duration → 24 hours (analyst can modify)

4. ALERT & INVESTIGATE:
   ├─ Create ticket → Brute force attack detected
   ├─ Severity → CRITICAL if successful logon
   ├─ Severity → HIGH if only failed attempts
   ├─ SIEM search → Check for successful logon
   │  ├─ If YES → Assume compromise
   │  │  ├─ Force password reset
   │  │  ├─ Revoke all sessions
   │  │  └─ Escalate to incident response
   │  └─ If NO → Attack blocked
   │     ├─ Monitor for escalation
   │     └─ Keep account disabled temporarily
   └─ Analyst review required

Expected Response Time:
├─ Detection to blocking: <3 minutes
├─ User notification: Immediate
├─ Analyst review: 5-15 minutes
└─ Full containment: <30 minutes
```

---

## Automated Playbook: Data Exfiltration Detection

```
TRIGGER: System transfers >1GB to external IP in 1 hour

Automated Actions (0-10 minutes):

1. DATA PROTECTION:
   ├─ DLP → Block further data transfers from source IP
   ├─ Firewall → Rate-limit outbound traffic (source IP)
   ├─ Proxy → Block outbound HTTPS to destination (optional)
   └─ Duration → 24 hours (analyst override)

2. SYSTEM CONTAINMENT:
   ├─ EDR → Isolate system from network
   ├─ Process kill → Stop suspicious processes (analyst approval)
   ├─ Network isolation → Prevent C2 communication
   └─ Notification → Analyst immediately (email + Slack + SMS)

3. FORENSIC COLLECTION:
   ├─ Network tap → Capture traffic to destination
   ├─ Memory dump → Collect RAM (parallel)
   ├─ Disk image → Start imaging (parallel, long-running)
   ├─ File audit → Which files were accessed?
   │  ├─ Compare: What files exist now vs 24h ago
   │  ├─ Identify: Files uploaded/transferred
   │  └─ Severity: What data was stolen?
   └─ Timeline → Reconstruct attack sequence

4. THREAT ASSESSMENT:
   ├─ Destination IP analysis:
   │  ├─ GEO location (where is attacker?)
   │  ├─ ASN ownership (who owns server?)
   │  ├─ Threat intelligence (known malicious?)
   │  └─ Decision → Legitimate or malicious?
   ├─ Data analysis:
   │  ├─ What data was transferred?
   │  ├─ How much data? (1GB, 100GB?)
   │  ├─ How sensitive? (public, confidential, highly confidential?)
   │  └─ Customer data? (regulatory notification required?)
   └─ Incident classification → Data breach confirmation

5. ESCALATION:
   ├─ IF Data breach:
   │  ├─ Notify Chief Information Security Officer (CISO)
   │  ├─ Notify General Counsel (legal implications)
   │  ├─ Activate incident response team
   │  └─ Prepare customer notification (if required)
   ├─ IF Not confirmed breach:
   │  ├─ Continue investigation
   │  └─ Analyst review

Expected Response Time:
├─ Detection to data block: <5 minutes
├─ System isolation: <10 minutes
├─ Forensic preservation: Complete
└─ Analyst notification: Immediate
```

---

## Automation Implementation Examples

### Example 1: PowerShell Automation

```powershell
# Automated Response to Malware Detection

function Respond-ToMalwareDetection {
    param(
        [string]$hostname,
        [string]$malware_hash,
        [string]$username
    )
    
    # Step 1: Isolate system
    Disable-NetAdapter -Name "Ethernet*" -Confirm:$false
    Write-Log "ISOLATED: $hostname"
    
    # Step 2: Collect evidence
    $dump_path = "C:\Forensics\$hostname.dmp"
    rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 
      (Get-Process lsass).Id $dump_path full
    Write-Log "EVIDENCE: Memory dumped to $dump_path"
    
    # Step 3: Alert SOC
    Send-Alert -Subject "MALWARE: $hostname detected" `
               -Body "Malware hash: $malware_hash, User: $username" `
               -Severity "CRITICAL"
    
    # Step 4: Create ticket
    New-IncidentTicket -Title "Malware: $hostname" `
                       -Description "Automated detection from EDR" `
                       -Status "Open"
}
```

### Example 2: SOAR Integration

```json
{
  "playbook_id": "pb_0001_brute_force",
  "name": "Automated Brute Force Response",
  "trigger": {
    "type": "SIEM alert",
    "condition": "failed_logons > 10 in 5 minutes"
  },
  "actions": [
    {
      "action_id": "a1",
      "type": "active_directory",
      "operation": "disable_account",
      "parameters": {
        "account": "${failed_logon.target_account}",
        "reason": "Brute force attack detected"
      },
      "approval": "automated"
    },
    {
      "action_id": "a2",
      "type": "firewall",
      "operation": "block_ip",
      "parameters": {
        "ip_address": "${failed_logon.source_ip}",
        "duration_hours": 24
      },
      "approval": "automated"
    },
    {
      "action_id": "a3",
      "type": "notification",
      "operation": "email_analyst",
      "parameters": {
        "recipient": "security-team@company.com",
        "subject": "CRITICAL: Brute force attack ${failed_logon.target_account}",
        "body": "Attack from ${failed_logon.source_ip}, account disabled"
      },
      "approval": "automated"
    }
  ]
}
```

---

## Automation Safety Measures

```
Safeguards to Prevent Automated Actions from Causing Damage:

1. APPROVAL GATES:
   ├─ Critical actions require analyst approval
   ├─ Isolation actions → Analyst notified, can override
   ├─ Destructive actions → Manual approval required
   └─ Example: "Delete suspicious file" → Requires approval

2. ROLLBACK CAPABILITY:
   ├─ All automated actions logged
   ├─ Analyst can UNDO within 30 minutes
   ├─ Example: Re-enable disabled account
   ├─ Example: Release isolated system
   └─ Automatic UNDO → If analyst marks as false positive

3. DRY-RUN MODE:
   ├─ Test playbooks without taking action
   ├─ Simulate what WOULD happen
   ├─ Review before going live
   └─ Confidence check before activation

4. HUMAN OVERSIGHT:
   ├─ Analyst always in the loop
   ├─ Analyst can pause/stop automation
   ├─ Analyst reviews decisions before escalation
   └─ Automation recommendations, not mandates

Example Safe Automation Design:

┌─────────────────────────────────┐
│ TRIGGER: Alert detected         │
│ (Non-destructive actions only)  │
├─────────────────────────────────┤
│ Automated Actions:              │
│ ✓ Isolate system                │ (Can be undone)
│ ✓ Collect evidence              │ (Informational)
│ ✓ Alert analyst                 │ (Notification)
│ ✓ Block attacker IP             │ (Can be undone)
│ ✗ Delete files                  │ (Requires approval)
│ ✗ Rebuild system                │ (Requires approval)
│ ✗ Disable domain                │ (Requires approval)
└─────────────────────────────────┘
          ↓
      Analyst Review
          ↓
    (Approve/Reject)
          ↓
   Approval Gate Decision
```

---

## Metrics & Effectiveness

```
Automation Metrics (Monthly):

Playbooks Activated: 247
├─ Malware detection: 23
├─ Brute force attack: 5
├─ Data exfiltration: 3
├─ Other: 216

Response Time Improvement:
├─ MTTD (before): 45 minutes
├─ MTTD (after): 5 minutes → 90% improvement
│
├─ MTTR (before): 4 hours
├─ MTTR (after): 30 minutes → 87% improvement

False Positive Handling:
├─ Analyst rejected: 12 (false positives)
├─ Automatic UNDO: 100% successful
├─ False positive rate: 4.9% (good)

Cost Savings:
├─ SOC staff required: 12 (before) → 8 (after)
├─ Annual cost savings: $500K (salary reduction)
├─ Incident response cost reduction: 60%
└─ ROI on automation: Paid for itself in 6 months

Team Satisfaction:
├─ Analyst satisfaction: 8.2/10 (improved)
├─ Reduced fatigue: 73% report less stress
├─ Focus on complex cases: More time available
└─ Morale improvement: Positive feedback
```

---

## References

- Splunk Phantom (SOAR platform)
- Microsoft Sentinel Automation
- Ansible for IT Automation
- Python for Custom Automation

---

*Document Maintenance:*
- Review automation effectiveness monthly
- Update playbooks as threats evolve
- Test new playbooks before production
- Measure and improve metrics continuously
