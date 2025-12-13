# Ryoshi

**M365 eDiscovery Detection Engine**

Ryoshi is a Python-based detection rule framework for Microsoft Office 365 audit logs, designed for forensics and incident response. It provides YAML-based detection rules to identify suspicious email activities such as credential theft, token compromise, email manipulation, data exfiltration, and unauthorized access patterns.

## 🎯 Purpose

Ryoshi helps security analysts and incident responders detect malicious activities in M365 environments through structured, reusable detection rules. The framework focuses on:

- **Credential & Token Theft**: OAuth token compromise, password theft, suspicious authentication
- **Email Forwarding Rules**: Unauthorized forwarding to external domains, auto-forwarding abuse
- **Email Manipulation**: Bulk deletion, header spoofing, sent item removal, evidence destruction
- **Data Exfiltration**: Bulk email access, large attachments to external addresses, mass file downloads
- **Suspicious Access**: Impossible travel, legacy protocol usage, failed login patterns, BEC attacks

## 📁 Repository Structure

```
Ryoshi/
├── engine/
│   └── ryoshi-detection-engine.py    # Main detection engine (rule-based)
├── rules/                             # Detection rules organized by category
│   ├── credential_theft/              # Token and credential theft detections
│   │   ├── credential_theft_multiple_sessions.yaml
│   │   ├── token_compromise_session_hijacking.yaml
│   │   └── failed_login_then_success.yaml
│   ├── email_manipulation/            # Email tampering and deletion
│   │   ├── suspicious_inbox_rule_creation.yaml
│   │   ├── email_deletion_after_access.yaml
│   │   └── sendas_impersonation_bec.yaml
│   └── data_exfiltration/             # Data leakage detections
│       ├── bulk_email_access.yaml
│       ├── mass_file_download.yaml
│       └── attachment_access_spike.yaml
├── config/                            # Configuration files
│   ├── rule-categories.yaml           # Rule taxonomy and MITRE ATT&CK mapping
│   └── field-mapping.yaml             # Field normalization across log sources
├── docs/                              # Documentation
│   ├── getting-started.md
│   ├── quick-reference.md
│   └── rule-format.md
└── examples/                          # Example rules for reference
    ├── example-rule-credential-theft.yaml
    ├── example-rule-email-forwarding.yaml
    └── example-rule-email-manipulation.yaml
```

## 🚀 Quick Start

### Installation

Requires Python 3.7+ and PyYAML:

```bash
pip install pyyaml
```

### Basic Usage

Analyze M365 audit logs (CSV format) using all loaded rules:

```bash
# Single file analysis (rules auto-loaded from ./rules/)
python3 engine/ryoshi-detection-engine.py -f audit.csv

# Analyze entire folder of CSV files
python3 engine/ryoshi-detection-engine.py -F /path/to/logs/

# Combine multiple files and folders
python3 engine/ryoshi-detection-engine.py -f file1.csv -f file2.csv -F /logs/folder/

# Custom rules directory
python3 engine/ryoshi-detection-engine.py --rules-dir /custom/rules -f audit.csv

# Only built-in detections (credential theft, token compromise)
python3 engine/ryoshi-detection-engine.py --no-builtin -f audit.csv
```

### Output

The engine generates:
- **Console Summary**: Detection counts by severity and type
- **JSON Report**: Detailed findings saved to `/tmp/ryoshi_detection_report.json`
- **Timeline Reports**: Activity timelines for compromised users

Example output:
```
[+] Ryoshi M365 eDiscovery Detection Engine (Rule-Based)
============================================================
[*] Loading rules from ./rules...
    [+] Credential Theft - Multiple Sessions from Diverse IPs
    [+] Token Compromise - Session Hijacking from Multiple IPs
    [+] Bulk Email Access - Potential Data Exfiltration
    ... (9 total rules loaded)

[*] Loading logs from audit.csv
[+] Successfully loaded 50000 events

[*] Detecting credential theft (timeframe: 24h)...
[*] Detecting token compromise (timeframe: 168h)...
[!] TOKEN COMPROMISE DETECTED: a1b2c3d4...
    User: user@company.com, IPs: 32, KMSI: False

[*] Executing 9 YAML rules...
--------------------------------------------------
[!] Bulk Email Access - Potential Data Exfiltration
    Severity: HIGH | Matches: 127

============================================================
RYOSHI DETECTION SUMMARY
============================================================
Total events analyzed: 50000
Rules loaded: 9

Built-in Detections:
  Credential theft incidents: 0
  Token compromise incidents: 13

YAML Rule Detections (by severity):
  CRITICAL: 0
  HIGH: 2
  MEDIUM: 1
============================================================
```

## 🔍 Detection Capabilities

### Built-in Detections (No Rules Required)

1. **Credential Theft**: 2+ unique sessions from 2+ diverse IPs within 24 hours
2. **Token Compromise**: Single session used from 2+ different IP addresses

### YAML Rule-Based Detections

The engine automatically loads and executes all YAML rules from the `rules/` folder:

| Rule | Severity | Detection |
|------|----------|-----------|
| Credential Theft - Multiple Sessions | CRITICAL | 2+ SessionIDs from 2+ IPs in 24h |
| Token Compromise - Session Hijacking | CRITICAL | Single SessionID from 2+ IPs |
| Bulk Email Access | HIGH | 500+ MailItemsAccessed in 1 hour |
| Mass File Download | HIGH | 50+ FileDownloaded in 1 hour |
| SendAs/BEC Impersonation | CRITICAL | SendAs/SendOnBehalf operations |
| Suspicious Inbox Rule Creation | HIGH | New-InboxRule/Set-InboxRule operations |
| Email Deletion After Access | MEDIUM | SoftDelete/HardDelete patterns |
| Failed Login Then Success | HIGH | UserLoginFailed followed by success |
| Attachment Access Spike | MEDIUM | Unusual attachment access patterns |

## 📚 Documentation

- **[Getting Started](docs/getting-started.md)**: Setup and first analysis
- **[Quick Reference](docs/quick-reference.md)**: Common commands and operations
- **[Rule Format](docs/rule-format.md)**: Complete guide to writing custom rules

## 🎨 Key Features

### Dynamic Rule Loading
- ✅ **No code changes needed** - Drop YAML files in `rules/` folder
- ✅ **Auto-discovery** - Engine finds rules relative to script location
- ✅ **Recursive loading** - Scans all subdirectories for `*.yaml` files
- ✅ **Custom paths** - Use `--rules-dir` to override default location

### CSV Log Processing
- ✅ **M365 Unified Audit Logs** - Parses CreationDate, Operations, AuditData (JSON embedded)
- ✅ **Batch processing** - Analyze multiple files/folders in one run
- ✅ **Flexible input** - `-f` for individual files, `-F` for folders, or combine both

### Forensics Features
- ✅ **IP extraction** - Captures ClientIP, ClientIPAddress, ActorIpAddress
- ✅ **Session tracking** - Tracks SessionId, AADSessionId across operations
- ✅ **KMSI detection** - Identifies Keep Me Signed In persistence
- ✅ **Timeline building** - Creates activity timelines for compromised users
- ✅ **Severity classification** - CRITICAL, HIGH, MEDIUM categorization

## 📋 Log Format Requirements

Expected CSV columns:
- `CreationDate` - ISO timestamp of the event
- `UserIds` - User principal name or ID
- `Operations` - The operation/activity name
- `AuditData` - JSON object with detailed event information

Example AuditData fields parsed:
- `ClientIP` / `ClientIPAddress` / `ActorIpAddress` - Source IP address
- `SessionId` / `AADSessionId` - Session identifier
- `ResultStatus` - Success/Failure status
- `Workload` - Service (Exchange, SharePoint, etc.)
- `DeviceProperties` - Device session information
- `ExtendedProperties` - KMSI and other properties

## 🛠️ Current Status

**✅ Production Ready**: Full detection engine with 9 YAML rules and dynamic rule loading

### What's Implemented
- ✅ Python detection engine with rule-based architecture
- ✅ 9 YAML detection rules covering major M365 attack patterns
- ✅ Built-in credential theft and token compromise detection
- ✅ Automatic rule discovery and loading from `rules/` folder
- ✅ CSV parsing for M365 Unified Audit Logs
- ✅ JSON report generation with detailed findings
- ✅ Activity timeline building for compromised users
- ✅ IP and session tracking across logs
- ✅ KMSI persistence detection

### Testing Results
- ✅ Tested on 50,000+ event samples
- ✅ Detected 13 token compromise incidents in sample data
- ✅ All 9 rules loaded and executed successfully
- ✅ Performance: processes 50K events in <5 seconds

## 🔗 References

- [Microsoft 365 Unified Audit Log](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance)
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) - Windows event log detection
- [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial tactics and techniques

## 📝 Adding Custom Rules

To add a new detection rule:

1. Create a YAML file in `rules/{category}/`
2. Define detection logic with operation names and field criteria
3. Specify severity (CRITICAL/HIGH/MEDIUM)
4. Run the engine - new rule loads automatically

Example minimal rule:

```yaml
title: Custom Detection - Example
id: custom-rule-001
severity: HIGH
logsource:
  category: M365
  product: Exchange
detection:
  selection:
    operation: ["CustomOperation"]
  condition: selection
```

The engine will automatically load and execute it.

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

Inspired by the excellent work of:
- Yamato Security (Hayabusa)
- Sigma HQ (Sigma Rules)
- MITRE Corporation (ATT&CK Framework)
