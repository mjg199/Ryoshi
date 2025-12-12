# Getting Started with Ryoshi

## Introduction

Ryoshi is a detection rule framework for Outlook and Office 365 email forensics. This guide will help you understand how to use and contribute to the framework.

## Understanding the Framework

### What is Ryoshi?

Ryoshi provides a structured way to define detection rules for suspicious email activities. Similar to how Sigma rules detect security events in logs, Ryoshi rules detect malicious email behaviors in Outlook, Office 365, and Exchange environments.

### Key Concepts

1. **Detection Rules**: YAML files that define patterns to identify threats
2. **Log Sources**: The email systems being analyzed (Outlook, Office 365, Exchange)
3. **Categories**: Organized threat classifications (credential theft, forwarding, etc.)
4. **Severity Levels**: Impact assessment (critical, high, medium, low, informational)

## Rule Anatomy

Every Ryoshi rule consists of several key sections:

### 1. Metadata Section

```yaml
title: Short descriptive name
id: unique-uuid-identifier
status: experimental | test | stable | deprecated
description: Detailed explanation of what the rule detects
author: Rule creator name
date: 2025-01-10
modified: 2025-01-15
```

### 2. Classification Section

```yaml
references:
  - https://attack.mitre.org/techniques/T1114/003/
tags:
  - forwarding_rules
  - data_exfiltration
severity: critical | high | medium | low | informational
```

### 3. Log Source Section

```yaml
logsource:
  category: outlook | office365 | exchange
  product: office365 | exchange_server | azure_ad
```

### 4. Detection Logic Section

```yaml
detection:
  selection:
    action: "New-InboxRule"
    forwarding_address: "*@external.com"
  condition: selection
  timeframe: 15m
```

### 5. Context Section

```yaml
falsepositives:
  - Legitimate business processes
  - IT administrative tasks
level: high
```

## Using Ryoshi Rules

### Step 1: Identify Your Log Source

Determine what email logs you have available:
- Office 365 Unified Audit Logs
- Exchange Server logs
- Azure AD sign-in logs
- Outlook client logs

### Step 2: Map Fields

Use the `config/field-mapping.yaml` to understand how your log fields map to Ryoshi's standard field names. This ensures rules work across different environments.

### Step 3: Select Relevant Rules

Browse the `rules/` directory and select rules matching your security concerns:
- `rules/credential_theft/` - Token and password theft
- `rules/forwarding_rules/` - Email forwarding detection
- `rules/email_manipulation/` - Email tampering
- `rules/data_exfiltration/` - Data leakage
- `rules/suspicious_access/` - Unusual access patterns

### Step 4: Customize Rules

Adjust rules for your environment:
- Update `filter_internal` sections with your internal domains
- Modify thresholds (e.g., failed login attempts)
- Add environment-specific false positive filters

## Writing Your First Rule

### Example Scenario

You want to detect when users create forwarding rules to Gmail addresses.

### Step-by-Step Process

1. **Create the rule file**:
   ```bash
   touch rules/forwarding_rules/gmail_forwarding.yaml
   ```

2. **Define metadata**:
   ```yaml
   title: Email Forwarding to Gmail
   id: generate-a-uuid-here
   status: experimental
   description: Detects inbox rules forwarding to Gmail addresses
   author: Your Name
   date: 2025-01-10
   ```

3. **Add classification**:
   ```yaml
   tags:
     - forwarding_rules
     - data_exfiltration
   severity: medium
   ```

4. **Specify log source**:
   ```yaml
   logsource:
     category: outlook
     product: office365
   ```

5. **Write detection logic**:
   ```yaml
   detection:
     selection:
       action: "New-InboxRule"
       forwarding_address|endswith: "@gmail.com"
     condition: selection
   ```

6. **Document false positives**:
   ```yaml
   falsepositives:
     - Personal email forwarding if allowed by policy
   level: medium
   ```

## Testing Rules

### Manual Testing

1. **Collect sample logs** matching the detection criteria
2. **Verify field names** match your environment
3. **Test with known good data** to check false positives
4. **Test with known bad data** to verify detection
5. **Refine logic** based on results

### Validation Checklist

- [ ] Rule triggers on malicious samples
- [ ] False positive rate is acceptable
- [ ] Field names match log source
- [ ] Description is clear and accurate
- [ ] References are relevant and accessible
- [ ] Tags are appropriate
- [ ] Severity matches impact

## Best Practices

### Rule Development

1. **Start Simple**: Begin with basic detection logic
2. **Add Filters Gradually**: Introduce false positive filters as needed
3. **Use Specific Field Names**: Avoid wildcards in field names
4. **Document Everything**: Explain detection logic and false positives
5. **Include References**: Link to MITRE ATT&CK, blogs, documentation

### Performance Considerations

1. **Avoid Broad Wildcards**: `*suspicious*` is costly
2. **Use Exact Matches When Possible**: `action: "Send"` vs `action|contains: "Send"`
3. **Limit Complex Regex**: Simple patterns perform better
4. **Set Appropriate Timeframes**: Don't correlate over excessive periods

### Security Considerations

1. **Don't Include Sensitive Data**: No real usernames, domains, or IPs
2. **Use Placeholders**: `@company.com` instead of real domains
3. **Generalize Patterns**: Rules should work across organizations
4. **Review Before Sharing**: Ensure no proprietary information

## Integration with Analysis Tools

### Future Integration Points

Ryoshi rules are designed to be processed by:
- **SIEM Systems**: Splunk, Elastic, Sentinel
- **SOAR Platforms**: Automation and response workflows
- **Custom Scripts**: Python/PowerShell for log analysis
- **Email Security Tools**: Integration with email gateways

### Rule Processing Pipeline

```
Email Logs → Field Normalization → Rule Evaluation → Alerts → Response
```

## Common Use Cases

### 1. Incident Response

When investigating email-related incidents:
- Apply relevant rules to historical logs
- Identify scope of compromise
- Find related suspicious activities
- Generate timeline of events

### 2. Threat Hunting

Proactively searching for threats:
- Run rules against recent logs
- Look for patterns matching TTPs
- Investigate anomalies
- Refine rules based on findings

### 3. Continuous Monitoring

Ongoing security monitoring:
- Integrate rules with SIEM
- Set up automated alerting
- Track rule effectiveness
- Update rules as threats evolve

## Getting Help

### Resources

- **Documentation**: See `docs/rule-format.md` for complete specification
- **Examples**: Check `examples/` directory for templates
- **Configuration**: Review `config/` for categories and mappings

### Common Issues

**Issue**: Rule doesn't trigger on known malicious activity
- **Solution**: Verify field names match your log source using field-mapping.yaml

**Issue**: Too many false positives
- **Solution**: Add filter conditions to exclude benign activities

**Issue**: Rule unclear or ambiguous
- **Solution**: Improve description and add more context in falsepositives section

## Next Steps

1. **Explore existing rules** in the `rules/` directory
2. **Review the rule format** in `docs/rule-format.md`
3. **Collect sample logs** from your environment
4. **Create custom rules** for your specific threats
5. **Share your rules** with the community

## Additional Resources

- [MITRE ATT&CK Email Techniques](https://attack.mitre.org/)
- [Microsoft 365 Security Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/)
- [Office 365 Audit Log Schema](https://docs.microsoft.com/en-us/office/office-365-management-api/)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)
