# SOC Tools & Automation

Python and PowerShell utilities to streamline security operations and reduce manual analysis time.

## Scripts

### ioc_enricher.py
**Purpose:** Bulk IOC enrichment via VirusTotal API

**Time Saved:** ~2 hours per 50 IOCs

**Usage:**
```bash
python ioc_enricher.py --input iocs.txt --output enrichment_results.json
```

**Input Format:**
```
8.8.8.8
malicious-domain.com
a3f5c8e9d2b1e7f4a6c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0
```

**Features:**
- Rate limiting compliance (4 requests/minute for free API)
- Response caching to avoid duplicate lookups
- Export to JSON, CSV, or Markdown
- Confidence scoring based on vendor detections
- Malicious/suspicious/harmless categorisation

**Output Sample:**
```json
{
  "8.8.8.8": {
    "type": "ip",
    "malicious": 0,
    "suspicious": 0,
    "harmless": 85,
    "reputation": "clean",
    "last_analysis": "2026-02-15T10:30:00Z"
  },
  "malicious-domain.com": {
    "type": "domain",
    "malicious": 15,
    "suspicious": 8,
    "reputation": "malicious",
    "categories": ["phishing", "malware"]
  }
}
```

---

### log_parser.py
**Purpose:** Parse Windows Event Logs (EVTX) to structured formats

**Time Saved:** ~1 hour per 100MB of logs

**Usage:**
```bash
# Parse specific Event IDs
python log_parser.py --evtx Security.evtx --eventids 4625,4624 --output auth_events.csv

# Parse all events to JSON
python log_parser.py --evtx Security.evtx --format json --output all_events.json
```

**Output Fields:**
- Timestamp (UTC normalised)
- Event ID
- Level (Information, Warning, Error)
- Computer Name
- Source IP (if applicable)
- Target User
- Authentication Type
- Detailed message

**Use Cases:**
- Bulk analysis of authentication logs
- Timeline reconstruction
- Import into SIEM for correlation
- Offline analysis of exported logs

---

### sigma_converter.py
**Purpose:** Convert Sigma detection rules to Splunk SPL

**Time Saved:** ~30 minutes per rule

**Usage:**
```bash
# Convert directory of rules
python sigma_converter.py --input sigma_rules/ --output spl_queries/

# Convert single rule
python sigma_converter.py --input detections/malware.yml --output spl/malware.spl
```

**Example Conversion:**

Input (Sigma):
```yaml
title: Suspicious PowerShell Download
detection:
  selection:
    CommandLine|contains:
      - 'IEX(New-Object Net.WebClient)'
      - 'Invoke-Expression'
  condition: selection
```

Output (SPL):
```spl
index=sysmon EventCode=1 
| where match(CommandLine, "(?i)IEX\(New-Object Net\.WebClient\)") 
   OR match(CommandLine, "(?i)Invoke-Expression")
| table _time, Computer, User, CommandLine, ParentImage
| eval severity="high"
```

**Supported Backends:**
- Splunk SPL (full support)
- Elastic DSL (partial support)
- Kusto Query Language (KQL) for Azure Sentinel (partial)

---

### phishing_analyzer.ps1
**Purpose:** Automated email header analysis and reputation checking

**Time Saved:** ~10 minutes per email

**Usage:**
```powershell
# Analyse single email
.\phishing_analyzer.ps1 -EmlFile "suspicious_email.eml"

# Bulk analyse folder
Get-ChildItem .\emails\*.eml | ForEach-Object { .\phishing_analyzer.ps1 -EmlFile $_.FullName }
```

**Analysis Output:**
```
Email Analysis Report
=====================
From: security@micros0ft-security.net
SPF: FAIL
DKIM: None
DMARC: FAIL
Authentication: SUSPICIOUS

Sender IP: 203.0.113.89
GeoLocation: Bulgaria (unusual for sender)
Domain Age: 3 days (recently registered)

URLs Found:
- https://microsoft-365-verify.com/login
  Reputation: Malicious (15/72 VT detections)

Recommendations:
- DO NOT CLICK links
- Delete email
- Report to security team
```

**Features:**
- SPF/DKIM/DMARC validation
- Domain age checking (WHOIS)
- URL extraction and reputation check
- Attachment hash calculation
- Risk scoring (1-10)

---

### alert_triage.py
**Purpose:** Auto-triage alerts based on severity rules

**Time Saved:** ~15 minutes per batch of alerts

**Usage:**
```bash
python alert_triage.py --input alerts.json --output triaged_alerts.csv
```

**Triage Logic:**
- Asset criticality weighting
- User privilege assessment
- Time-based risk adjustment
- Prevalence checking
- Historical false positive rate

---

### rule_tester.py
**Purpose:** Validate detection rules against test logs

**Time Saved:** ~1 hour per rule validation cycle

**Usage:**
```bash
python rule_tester.py --rule sigma_rule.yml --test-data test_events.json
```

**Output:**
- True positive count
- False positive count
- Missed detection count
- Precision and recall metrics
- Tuning recommendations

---

### beacon_detector.py
**Purpose:** C2 beacon timing analysis from PCAP or flow logs

**Time Saved:** ~45 minutes per PCAP analysis

**Usage:**
```bash
python beacon_detector.py --pcap capture.pcap --interval 60 --jitter 10
```

**Detection Method:**
- Identifies regular connection intervals
- Calculates jitter (variation in timing)
- Scores beacon likelihood
- Outputs suspicious flows

---

### extract_iocs.py
**Purpose:** IOC extraction from multiple file formats

**Time Saved:** ~20 minutes per investigation

**Usage:**
```bash
python extract_iocs.py --input investigation_notes.txt --output iocs.csv
```

**Supported Formats:**
- Text files (regex extraction)
- PDF reports
- Email files (.eml, .msg)
- JSON/XML logs
- CSV exports

**Extracted Types:**
- IPv4/IPv6 addresses
- Domains and subdomains
- File hashes (MD5, SHA1, SHA256)
- Email addresses
- URLs

---

## Automation Playbooks

Higher-level automation workflows combining multiple scripts.

### Phishing Response Automation
```
Email Reported → Extract Headers → Analyse Reputation → Extract IOCs 
     → Enrich IOCs → Update Blocklists → Notify User → Document Case
```

### Alert Enrichment Pipeline
```
Alert Fired → Gather Context → Enrich IOCs → Check Prevalence 
     → Calculate Risk Score → Route to Analyst → Update Metrics
```

## Tool Configurations

Reference configurations for common security tools.

**Included Configs:**
- Snort rules (custom detections)
- Zeek scripts (custom logging)
- Sysmon configuration ( optimised for detection)
- Splunk field extractions
- Sigma rule templates

---

*Automation doesn't replace analysts—it amplifies them. Every minute saved on repetitive tasks is a minute gained for hunting and investigation.*
