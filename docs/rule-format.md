# Ryoshi Rule Format Specification

## Overview

Ryoshi uses YAML-based detection rules similar to Sigma rules but tailored for Outlook email forensics. Each rule defines patterns and conditions to detect suspicious or malicious email-related activities.

## Rule Structure

A Ryoshi rule consists of the following fields:

```yaml
title: [string] # Short, descriptive name of the detection rule
id: [string] # Unique identifier (UUID format recommended)
status: [string] # Rule maturity: experimental, test, stable, deprecated
description: [string] # Detailed description of what the rule detects
author: [string] # Rule author name
date: [string] # Rule creation date (YYYY-MM-DD format)
modified: [string] # Last modification date (YYYY-MM-DD format)
references: [list] # Links to relevant documentation, articles, or threat reports
tags: [list] # Classification tags (e.g., credential_theft, email_manipulation)
severity: [string] # Impact level: critical, high, medium, low, informational
logsource: [object] # Defines the source of the email logs
  category: [string] # Log category (e.g., outlook, office365, exchange)
  product: [string] # Product name
detection: [object] # Detection logic
  selection: [object/list] # Conditions that must match
  condition: [string] # Boolean logic combining selections
  timeframe: [string] # Optional time-based correlation
falsepositives: [list] # Known scenarios that may trigger false positives
level: [string] # Synonym for severity (kept for compatibility)
```

## Field Descriptions

### Required Fields

- **title**: A concise, human-readable name for the rule
- **id**: A unique identifier, preferably in UUID format
- **status**: Current state of the rule (experimental, test, stable, deprecated)
- **description**: Comprehensive explanation of the threat or behavior detected
- **logsource**: Specifies which email system logs are analyzed
- **detection**: The core logic defining what patterns trigger the rule

### Recommended Fields

- **author**: Creator or maintainer of the rule
- **date**: When the rule was first created
- **references**: External sources for additional context
- **tags**: Categorization labels for organizing rules
- **severity**: Impact assessment (critical, high, medium, low, informational)
- **falsepositives**: Common legitimate scenarios that might match

### Optional Fields

- **modified**: Date of last update
- **timeframe**: For correlation-based detections

## Detection Logic

The `detection` section defines the conditions that trigger the rule:

### Selection Objects

Selection objects contain field-value pairs to match:

```yaml
detection:
  selection:
    action: "Forward"
    destination: "*external.com"
  condition: selection
```

### Multiple Selections

Combine multiple selection objects with boolean operators:

```yaml
detection:
  selection1:
    subject: "*password reset*"
  selection2:
    sender_domain: 
      - "paypal.com"
      - "bank.com"
  condition: selection1 and not selection2
```

### Field Modifiers

Use modifiers to refine matching:

- `*`: Wildcard matching
- `|contains`: Contains substring
- `|startswith`: Starts with pattern
- `|endswith`: Ends with pattern
- `|re`: Regular expression matching

```yaml
detection:
  selection:
    subject|contains: "urgent"
    sender|endswith: "@suspicious.com"
  condition: selection
```

## Common Field Names

Standard field names for Outlook/Exchange email logs:

### Email Metadata
- `message_id`: Unique message identifier
- `subject`: Email subject line
- `sender`: Sender email address
- `sender_domain`: Domain of sender
- `recipient`: Recipient email address(es)
- `cc`: CC recipients
- `bcc`: BCC recipients
- `date_sent`: When email was sent
- `date_received`: When email was received

### Email Actions
- `action`: Action performed (Send, Receive, Forward, Delete, Move, etc.)
- `rule_name`: Name of email rule (for forwarding/automation)
- `folder_path`: Mailbox folder path

### Authentication & Access
- `client_ip`: IP address of client
- `user_agent`: Email client user agent
- `auth_type`: Authentication method used
- `auth_result`: Success/failure of authentication
- `login_location`: Geographic location of login

### Attachments & Links
- `attachment_count`: Number of attachments
- `attachment_name`: Filename of attachment
- `attachment_extension`: File extension
- `link_count`: Number of links in email
- `link_url`: URL of links

### Advanced Features
- `mailbox_rule_action`: Type of mailbox rule action
- `delegate_access`: Delegate access information
- `forwarding_address`: Auto-forwarding destination

## Severity Levels

- **critical**: Immediate threat requiring urgent response (e.g., active credential theft)
- **high**: Significant security risk (e.g., suspicious forwarding rules)
- **medium**: Notable security concern (e.g., unusual email patterns)
- **low**: Minor security indicator (e.g., non-standard client access)
- **informational**: Awareness-level detection (e.g., configuration changes)

## Rule Categories (Tags)

Organize rules using these standard tags:

- `credential_theft`: Token or password theft attempts
- `email_manipulation`: Email content or metadata tampering
- `forwarding_rules`: Unauthorized email forwarding
- `data_exfiltration`: Sensitive data being exfiltrated
- `phishing`: Phishing attempts
- `spam`: Spam or unwanted emails
- `suspicious_access`: Unusual login or access patterns
- `persistence`: Techniques for maintaining access
- `account_compromise`: Signs of compromised accounts
- `defense_evasion`: Attempts to hide malicious activity

## Example Rule

```yaml
title: Suspicious Email Forwarding Rule Creation
id: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
status: stable
description: Detects creation of email forwarding rules that redirect emails to external domains, which may indicate account compromise or data exfiltration attempts.
author: Security Team
date: 2025-01-01
modified: 2025-01-15
references:
  - https://attack.mitre.org/techniques/T1114/003/
  - https://docs.microsoft.com/en-us/security/
tags:
  - forwarding_rules
  - data_exfiltration
  - persistence
severity: high
logsource:
  category: outlook
  product: office365
detection:
  selection:
    action: "New-InboxRule"
    mailbox_rule_action: 
      - "ForwardTo"
      - "ForwardAsAttachmentTo"
      - "RedirectTo"
  filter_internal:
    forwarding_address|endswith:
      - "@company.com"
      - "@internal.domain.com"
  condition: selection and not filter_internal
  timeframe: 15m
falsepositives:
  - Legitimate business process automation
  - IT department administrative tasks
  - Users setting up vacation auto-forwarding to work accounts
level: high
```

## Best Practices

1. **Use Unique IDs**: Generate a new UUID for each rule
2. **Comprehensive Descriptions**: Explain the threat, technique, and impact
3. **Document False Positives**: Help analysts distinguish malicious from benign
4. **Test Thoroughly**: Validate rules against known good and bad data
5. **Include References**: Link to MITRE ATT&CK, vendor documentation, or research
6. **Maintain Rules**: Update modified date when changing detection logic
7. **Use Standard Fields**: Stick to common field names for consistency
8. **Progressive Severity**: Start with experimental, promote to stable after testing
9. **Tag Appropriately**: Use multiple relevant tags for better organization
10. **Consider Performance**: Avoid overly complex regex or broad wildcards

## Rule Development Workflow

1. **Identify Threat**: Define the suspicious behavior or attack technique
2. **Research**: Study real-world examples and TTPs
3. **Draft Rule**: Create initial YAML with experimental status
4. **Test**: Validate against sample data (benign and malicious)
5. **Refine**: Adjust detection logic to reduce false positives
6. **Document**: Add comprehensive descriptions and false positive notes
7. **Review**: Have peers review for accuracy and completeness
8. **Promote**: Move from experimental → test → stable
9. **Maintain**: Update as new evasion techniques emerge

## Integration

Ryoshi rules are designed to be:
- **Portable**: Work across different Outlook/Exchange environments
- **Extensible**: Easy to add custom fields for specific environments
- **Automatable**: Can be processed by SIEM, SOAR, or custom tools
- **Human-Readable**: Clear enough for manual analysis and documentation
