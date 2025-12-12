# Ryoshi Quick Reference

## Overview

Ryoshi is a YAML-based detection rule framework for Outlook and Office 365 email forensics, inspired by Hayabusa and Sigma.

## Rule Categories

| Category | Path | Focus Area |
|----------|------|-----------|
| Credential Theft | `rules/credential_theft/` | OAuth tokens, passwords, authentication |
| Email Forwarding | `rules/forwarding_rules/` | Inbox rules, transport rules, redirection |
| Email Manipulation | `rules/email_manipulation/` | Deletion, spoofing, tampering |
| Data Exfiltration | `rules/data_exfiltration/` | Large transfers, sensitive data |
| Suspicious Access | `rules/suspicious_access/` | Anomalous logins, legacy protocols |

## Rule Template

```yaml
title: [Short descriptive name]
id: [UUID v4]
status: experimental | test | stable | deprecated
description: [What it detects and why]
author: [Your name]
date: YYYY-MM-DD
references:
  - [MITRE ATT&CK technique]
  - [Additional documentation]
tags:
  - [category]
  - [additional tags]
severity: critical | high | medium | low | informational
logsource:
  category: outlook | office365 | exchange
  product: [product name]
detection:
  selection:
    field_name: "value"
  condition: selection
falsepositives:
  - [Known benign scenarios]
level: [same as severity]
```

## Common Field Names

### Email Metadata
- `message_id` - Unique message identifier
- `subject` - Email subject line
- `sender` - Sender email address
- `recipient` - Recipient email address
- `date_sent` - When email was sent

### Actions
- `action` - Operation performed (Send, Forward, Delete, etc.)
- `operation` - Specific operation name
- `event_type` - Type of event

### Authentication
- `client_ip` - Client IP address
- `user_agent` - Email client user agent
- `auth_result` - Authentication success/failure

### Rules
- `rule_name` - Name of mailbox rule
- `mailbox_rule_action` - Rule action type
- `forwarding_address` - Forwarding destination

## Detection Operators

| Operator | Usage | Example |
|----------|-------|---------|
| Exact match | `field: "value"` | `action: "Send"` |
| Contains | `field\|contains: "value"` | `subject\|contains: "urgent"` |
| Ends with | `field\|endswith: "value"` | `sender\|endswith: "@evil.com"` |
| Starts with | `field\|startswith: "value"` | `subject\|startswith: "RE:"` |
| Regex | `field\|re: "pattern"` | `subject\|re: ".*invoice.*"` |
| Multiple values | `field: [val1, val2]` | `action: ["Send", "Forward"]` |

## Condition Logic

- `selection` - Simple match
- `selection1 and selection2` - Both must match
- `selection1 or selection2` - Either can match
- `selection and not filter` - Match but exclude filter
- `selection1 and (selection2 or selection3)` - Complex logic

## Severity Levels

| Level | Priority | Use Case |
|-------|----------|----------|
| `critical` | P1 | Immediate threat, urgent response |
| `high` | P2 | Significant risk, prompt investigation |
| `medium` | P3 | Notable concern, standard investigation |
| `low` | P4 | Minor indicator, monitoring |
| `informational` | P5 | Awareness, context |

## Standard Tags

### Primary Categories
- `credential_theft` - Token/password theft
- `forwarding_rules` - Email forwarding
- `email_manipulation` - Email tampering
- `data_exfiltration` - Data leakage
- `suspicious_access` - Unusual access
- `phishing` - Phishing attempts
- `persistence` - Maintaining access
- `defense_evasion` - Hiding activity

### Additional Tags
- `oauth` - OAuth-related
- `brute_force` - Brute force attempts
- `impersonation` - Identity spoofing
- `covering_tracks` - Evidence removal
- `account_compromise` - Compromised accounts

## MITRE ATT&CK Mapping

| Technique | Description | Categories |
|-----------|-------------|------------|
| T1078 | Valid Accounts | credential_theft, suspicious_access |
| T1114.003 | Email Forwarding Rule | forwarding_rules, persistence |
| T1528 | Steal Application Access Token | credential_theft |
| T1566 | Phishing | phishing |
| T1048.003 | Exfiltration Over Email | data_exfiltration |
| T1070.004 | Indicator Removal | email_manipulation, defense_evasion |
| T1110 | Brute Force | suspicious_access |

## Log Source Categories

| Category | Description | Common Fields |
|----------|-------------|---------------|
| `outlook` | Outlook client logs | message_id, subject, sender |
| `office365` | Microsoft 365 cloud | user_id, action, client_ip |
| `exchange` | Exchange Server | sender, recipient, server_hostname |
| `azure_ad` | Azure AD authentication | user_principal_name, auth_result |

## File Naming Conventions

- Use lowercase with underscores
- Be descriptive but concise
- Examples:
  - `oauth_token_theft.yaml`
  - `external_forwarding_rule.yaml`
  - `bulk_email_deletion.yaml`

## Rule Development Checklist

- [ ] Unique UUID generated
- [ ] Clear, descriptive title
- [ ] Comprehensive description
- [ ] Appropriate tags from taxonomy
- [ ] Detection logic tested
- [ ] False positives documented
- [ ] MITRE ATT&CK reference included
- [ ] Status set appropriately
- [ ] YAML syntax valid
- [ ] Placed in correct category directory

## Testing Checklist

- [ ] Rule triggers on malicious samples
- [ ] False positive rate is acceptable
- [ ] Field names match log source
- [ ] Description is accurate
- [ ] References are accessible
- [ ] Severity matches impact

## Common False Positive Filters

```yaml
# Filter internal domains
filter_internal:
  domain|endswith: "@company.com"

# Filter known good IPs
filter_trusted:
  client_ip:
    - "10.0.0.1"
    - "192.168.1.1"

# Filter admin actions
filter_admin:
  user_id: "admin@company.com"

# Filter compliant devices
filter_compliant:
  is_compliant_device: "true"
```

## Timeframe Examples

- `5m` - 5 minutes
- `15m` - 15 minutes
- `1h` - 1 hour
- `24h` - 24 hours
- `7d` - 7 days

## Quick Commands

### Validate YAML Syntax
```bash
# Using Python
python -c "import yaml; yaml.safe_load(open('rule.yaml'))"

# Using yamllint (if installed)
yamllint rule.yaml
```

### Generate UUID
```bash
# Linux/Mac
uuidgen | tr '[:upper:]' '[:lower:]'

# Python
python -c "import uuid; print(uuid.uuid4())"
```

### Count Rules by Category
```bash
find rules/ -name "*.yaml" | wc -l
```

## Resources

- **Full Documentation**: `docs/rule-format.md`
- **Getting Started**: `docs/getting-started.md`
- **Contributing**: `CONTRIBUTING.md`
- **Examples**: `examples/` directory
- **Configuration**: `config/` directory

## Support

- Check existing documentation in `docs/`
- Review example rules in `examples/`
- Examine similar rules in `rules/`
- Open an issue for questions

---

**Last Updated**: 2025-01-10  
**Framework Version**: 1.0.0 (Initial Release)
