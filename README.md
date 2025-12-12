# Ryoshi

**Forensics Framework for Outlook Email Analysis**

Ryoshi is a detection rule framework for Outlook and Office 365 email forensics, inspired by [Hayabusa](https://github.com/Yamato-Security/hayabusa) and [Sigma](https://github.com/SigmaHQ/sigma). It provides YAML-based detection rules to identify suspicious email activities such as credential theft, email manipulation, data exfiltration, and unauthorized forwarding rules.

## 🎯 Purpose

Ryoshi helps security analysts and incident responders detect malicious email-related activities through structured, reusable detection rules. The framework focuses on:

- **Credential & Token Theft**: OAuth token theft, password theft, suspicious authentication
- **Email Forwarding Rules**: Unauthorized forwarding to external domains
- **Email Manipulation**: Header spoofing, bulk deletion, sent item removal
- **Data Exfiltration**: Large attachments to external addresses, bulk downloads
- **Suspicious Access**: Impossible travel, legacy protocol usage, brute force attempts

## 📁 Repository Structure

```
Ryoshi/
├── rules/                      # Detection rules organized by category
│   ├── credential_theft/       # Token and credential theft detections
│   ├── email_manipulation/     # Email tampering and deletion
│   ├── forwarding_rules/       # Forwarding and redirection rules
│   ├── data_exfiltration/      # Data leakage detections
│   └── suspicious_access/      # Anomalous access patterns
├── config/                     # Configuration files
│   ├── rule-categories.yaml    # Rule taxonomy and MITRE ATT&CK mapping
│   └── field-mapping.yaml      # Field normalization across log sources
├── docs/                       # Documentation
│   └── rule-format.md          # Complete rule format specification
└── examples/                   # Example rules for reference
    ├── example-rule-credential-theft.yaml
    ├── example-rule-email-forwarding.yaml
    └── example-rule-email-manipulation.yaml
```

## 🚀 Quick Start

### Understanding Rules

Ryoshi rules are YAML files that define detection logic for suspicious email activities. Each rule includes:

- **Metadata**: Title, ID, description, author, tags
- **Log Source**: Which email system logs to analyze
- **Detection Logic**: Conditions that trigger the rule
- **Context**: Severity, false positives, references

### Example Rule

```yaml
title: Suspicious Email Forwarding to External Domain
id: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
status: stable
description: Detects inbox rules that forward emails to external domains
tags:
  - forwarding_rules
  - data_exfiltration
severity: high
logsource:
  category: outlook
  product: office365
detection:
  selection:
    action: "New-InboxRule"
    mailbox_rule_action: "ForwardTo"
  filter_internal:
    forwarding_address|endswith: "@company.com"
  condition: selection and not filter_internal
falsepositives:
  - Legitimate business automation
level: high
```

## 📚 Documentation

- **[Rule Format Specification](docs/rule-format.md)**: Complete guide to writing Ryoshi rules
- **[Rule Categories](config/rule-categories.yaml)**: Taxonomy and MITRE ATT&CK mapping
- **[Field Mapping](config/field-mapping.yaml)**: Field name normalization across platforms

## 🔍 Detection Categories

| Category | Description | Example Detections |
|----------|-------------|-------------------|
| **Credential Theft** | Token and password theft attempts | OAuth consent grants, password resets followed by rule creation |
| **Email Forwarding** | Unauthorized email forwarding | External forwarding rules, transport rules, hidden forwarding |
| **Email Manipulation** | Email tampering and deletion | Bulk deletion, header spoofing, sent item removal |
| **Data Exfiltration** | Sensitive data extraction | Large attachments, bulk downloads, sensitive keywords |
| **Suspicious Access** | Anomalous access patterns | Impossible travel, legacy protocols, failed logins |

## 🛠️ Current Status

**⚠️ Framework Setup Phase**: The rule structure and documentation are established. Detection rules will be refined once actual Outlook/Office 365 log samples are provided for accurate field mapping and detection logic.

### What's Ready
- ✅ Rule format specification (YAML-based)
- ✅ Directory structure for rule organization
- ✅ Configuration files (categories, field mappings, MITRE ATT&CK)
- ✅ Documentation for rule development
- ✅ Example rules demonstrating the format

### What's Next
- 📋 Awaiting actual log samples for field validation
- 📋 Rule refinement based on real-world data
- 📋 Analysis tools for processing rules against logs
- 📋 Integration guides for SIEM/SOAR platforms

## 🎨 Design Philosophy

Ryoshi follows these principles:

1. **Log Source Agnostic**: Rules work across Outlook, Office 365, and Exchange
2. **MITRE ATT&CK Aligned**: Mapped to relevant techniques and tactics
3. **Human-Readable**: Clear YAML format for easy review and modification
4. **Portable**: Can be integrated with various analysis tools
5. **Community-Driven**: Designed for sharing and collaboration

## 📖 Rule Development Workflow

1. **Identify Threat**: Define the suspicious behavior or attack technique
2. **Research**: Study TTPs and real-world examples
3. **Draft Rule**: Create YAML with experimental status
4. **Test**: Validate against sample data
5. **Refine**: Adjust to reduce false positives
6. **Document**: Add comprehensive descriptions
7. **Promote**: Move from experimental → test → stable

## 🔗 References

- [Hayabusa](https://github.com/Yamato-Security/hayabusa) - Windows event log forensics
- [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial tactics and techniques
- [Microsoft 365 Security](https://docs.microsoft.com/en-us/microsoft-365/security/)

## 📝 Contributing

Contributions are welcome! When actual log samples become available:

1. Validate field names against real logs
2. Test detection logic with known good/bad data
3. Document false positive scenarios
4. Add references to threat intelligence
5. Submit rules with clear descriptions

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

Inspired by the excellent work of:
- Yamato Security (Hayabusa)
- Sigma HQ (Sigma Rules)
- MITRE Corporation (ATT&CK Framework)
