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

Requires Python 3.7+ and PyYAML. Optional: `requests` for IP geolocation and AbuseIPDB integration:

```bash
pip install pyyaml
pip install requests  # Optional: for IP geolocation and reputation checks
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

# Custom output directory
python3 engine/ryoshi-detection-engine.py -f audit.csv -o /path/to/output/
```

### Advanced Options

#### IP Reputation Checking (AbuseIPDB)

Enable IP reputation analysis for token theft detection:

```bash
# Using command-line argument
python3 engine/ryoshi-detection-engine.py -f audit.csv --abuseipdb-key YOUR_API_KEY

# Using environment variable
export ABUSEIPDB_API_KEY="your_api_key_here"
python3 engine/ryoshi-detection-engine.py -f audit.csv
```

When enabled, the engine will:
- Query AbuseIPDB for IP abuse scores
- Flag known TOR and proxy exit nodes
- Include reputation data in HTML reports
- Reduce false positives from known malicious infrastructure

#### Country Exclusion for Token Theft Detection

Filter out known legitimate locations to reduce false positives:

```bash
# Exclude single country (e.g., Spain)
python3 engine/ryoshi-detection-engine.py -f audit.csv --exclude-country="Spain"

# Exclude multiple countries (comma-separated)
python3 engine/ryoshi-detection-engine.py -f audit.csv --exclude-country="Spain,France,Germany"
```

This is useful when:
- Organization is primarily based in specific countries
- Corporate VPN exits are in known locations
- Legitimate users travel to certain regions regularly

### Output

The engine generates:
- **Output** The default output directory is saved to `/tmp/ryoshi_detection_report.json` you can change it by using the -o flag
- **Console Summary**: Detection counts by severity and type
- **JSON Report**: Detailed findings 
- **HTML Report**: Interactive detection dashboard with IP reputation data
- **Timeline Reports**: Activity timelines for compromised users (JSON & CSV)

Example output:
```
[+] Ryoshi M365 eDiscovery Detection Engine (Rule-Based)
============================================================
[+] AbuseIPDB integration enabled
[+] Excluding countries from token theft detection: Spain
[*] Loading rules from ./rules...
    [+] Credential Theft - Multiple Sessions from Diverse IPs
    [+] Token Compromise - Session Hijacking from Multiple IPs
    [+] Bulk Email Access - Potential Data Exfiltration
    ... (9 total rules loaded)

[*] Executing 9 YAML rules...
--------------------------------------------------
[*] Analyzing 191 sessions for token theft indicators...
    [*] Session 009988c9-a0c3-08e0-87eb-4... has 21 subnets - checking geolocation...
    [*] Session 009988c9-9bfd-74ba-74b3-3... has 8 subnets - checking geolocation...

[!] Token Compromise - Session Hijacking from Multiple IPs
    Severity: CRITICAL | Sessions Affected: 8
    - Session 009988c9-a0c3-08e0-8...: 21 IPs, 21 subnets
      Countries: NO, ES, SE
    - Session 009988c9-9bfd-74ba-7...: 11 IPs, 8 subnets
      Countries: ES, FR, SE, IE
      Suspicious IPs (AbuseIPDB): 4

============================================================
RYOSHI DETECTION SUMMARY
============================================================
Total events analyzed: 19619
Rules loaded: 9
Compromised users: 2

Rule Detections by Severity:
  CRITICAL: 2
  HIGH: 1
  MEDIUM: 2
============================================================
```

## 🔍 Detection Capabilities

### YAML Rule-Based Detections (Rule-Based Approach)

The engine dynamically loads and executes all YAML rules from the `rules/` folder. Rules are organized by threat category:

| Rule | Severity | Key Detection Method |
|------|----------|-----|
| **Credential Theft - Multiple Sessions** | CRITICAL | 2+ SessionIDs from 2+ IPs in 24h |
| **Token Compromise - Session Hijacking** | CRITICAL | **Hybrid detection**: 3+ /24 subnets + geolocation + IP reputation |
| **Bulk Email Access** | HIGH | 500+ MailItemsAccessed in 1 hour |
| **Mass File Download** | HIGH | 50+ FileDownloaded in 1 hour |
| **SendAs/BEC Impersonation** | CRITICAL | SendAs/SendOnBehalf operations |
| **Suspicious Inbox Rule Creation** | HIGH | New-InboxRule/Set-InboxRule operations |
| **Email Deletion After Access** | MEDIUM | SoftDelete/HardDelete patterns |
| **Failed Login Then Success** | HIGH | UserLoginFailed followed by success in 1 hour |
| **Attachment Access Spike** | MEDIUM | Unusual attachment access patterns |

### Token Compromise Detection (Enhanced)

The token hijacking rule uses a **hybrid multi-layer approach**:

1. **Subnet Diversity (Primary)**: Requires 3+ distinct /24 subnets to trigger
2. **Geolocation Analysis**: Detects impossible travel (multiple countries)
3. **IP Reputation** (Optional): AbuseIPDB integration checks for known malicious IPs
4. **Country Filtering** (Optional): Excludes legitimate locations to reduce false positives

**Example Detection:**
- User in Spain with sessions from Nigeria, New Zealand, and Europe
- 17 distinct subnets across 4 countries
- 4 IPs flagged as suspicious by AbuseIPDB
- Result: **CRITICAL** token theft alert

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

### Token Compromise Detection
- ✅ **Subnet diversity analysis** - 3+ /24 subnets required
- ✅ **Geolocation checking** - Detects impossible travel via ip-api.com
- ✅ **IP reputation integration** - AbuseIPDB API for abuse scores & TOR/proxy detection
- ✅ **Country filtering** - Exclude known legitimate locations
- ✅ **Multi-layer detection** - Reduces false positives from VPNs and corporate networks

### CSV Log Processing
- ✅ **M365 Unified Audit Logs** - Parses CreationDate, Operations, AuditData (JSON embedded)
- ✅ **Batch processing** - Analyze multiple files/folders in one run
- ✅ **Flexible input** - `-f` for individual files, `-F` for folders, or combine both

### Forensics Features
- ✅ **IP extraction** - Captures ClientIP, ClientIPAddress, ActorIpAddress
- ✅ **Session tracking** - Tracks SessionId, AADSessionId across operations
- ✅ **Subnet mapping** - Calculates /16 and /24 subnets for diversity analysis
- ✅ **Timeline building** - Creates activity timelines for compromised users (JSON & CSV)
- ✅ **Severity classification** - CRITICAL, HIGH, MEDIUM categorization
- ✅ **HTML reporting** - Interactive dashboard with IP reputation data

## 📋 Log Format Requirements

Expected CSV columns:
- `CreationDate` - ISO timestamp of the event
- `UserId` - User principal name or ID
- `Operation` - The operation/activity name
- `AuditData` - JSON object with detailed event information

Example AuditData fields parsed:
- `ClientIP` / `ClientIPAddress` / `ActorIpAddress` - Source IP address
- `SessionId` / `AADSessionId` - Session identifier
- `ResultStatus` - Success/Failure status
- `Workload` - Service (Exchange, SharePoint, etc.)
- `DeviceProperties` - Device session information
- `ExtendedProperties` - KMSI and other properties

## 🛠️ Current Status

**✅ Production Ready**: Full rule-based detection engine with 9 YAML rules, IP geolocation, and AbuseIPDB integration

### What's Implemented
- ✅ Python detection engine with hybrid rule-based architecture
- ✅ 9 YAML detection rules covering major M365 attack patterns
- ✅ Automatic rule discovery and loading from `rules/` folder
- ✅ Token compromise detection with subnet diversity analysis
- ✅ IP geolocation (ip-api.com) for impossible travel detection
- ✅ AbuseIPDB API integration for IP reputation checking
- ✅ Country exclusion filtering to reduce false positives
- ✅ Activity timeline generation for compromised users (JSON & CSV)
- ✅ Multi-format reporting (JSON, HTML, Markdown, CSV)
- ✅ CSV parsing for M365 Unified Audit Logs
- ✅ JSON report generation with detailed findings
- ✅ Activity timeline building for compromised users
- ✅ IP and session tracking across logs
- ✅ KMSI persistence detection

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
