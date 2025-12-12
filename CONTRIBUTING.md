# Contributing to Ryoshi

Thank you for your interest in contributing to Ryoshi! This document provides guidelines for contributing detection rules and improving the framework.

## How to Contribute

### Types of Contributions

We welcome the following contributions:

1. **Detection Rules**: New rules for email-related threats
2. **Rule Improvements**: Enhancements to existing rules
3. **Documentation**: Clarifications, examples, and guides
4. **Field Mappings**: Platform-specific field normalizations
5. **Bug Reports**: Issues with rules or documentation

## Contributing Detection Rules

### Before Creating a Rule

1. **Check for duplicates**: Search existing rules to avoid redundancy
2. **Research the threat**: Understand the TTP and real-world examples
3. **Have test data**: Ideally, access to logs showing the behavior
4. **Know your environment**: Understand which log sources you're targeting

### Rule Development Process

#### 1. Create Rule File

Place your rule in the appropriate category directory:
```
rules/
├── credential_theft/       # Token and credential theft
├── email_manipulation/     # Email tampering and deletion
├── forwarding_rules/       # Email forwarding and redirection
├── data_exfiltration/      # Data leakage
└── suspicious_access/      # Anomalous access patterns
```

#### 2. Use Standard Template

```yaml
title: Clear, Descriptive Title
id: generate-uuid-v4-here
status: experimental  # Start here
description: |
  Comprehensive explanation of:
  - What the rule detects
  - Why it's suspicious or malicious
  - What attackers achieve with this technique
author: Your Name or GitHub Handle
date: YYYY-MM-DD
modified: YYYY-MM-DD  # Update when changed
references:
  - https://attack.mitre.org/techniques/TXXXX/
  - Additional relevant documentation
tags:
  - primary_category
  - additional_tags
severity: critical | high | medium | low | informational
logsource:
  category: outlook | office365 | exchange
  product: product_name
detection:
  selection:
    field_name: "value"
  condition: selection
  timeframe: Xm  # If time-based correlation
falsepositives:
  - Document known benign scenarios
  - Help analysts distinguish legitimate from malicious
level: same as severity
```

#### 3. Follow Naming Conventions

- **File names**: Use lowercase with underscores, e.g., `oauth_token_theft.yaml`
- **Rule titles**: Clear, specific, and consistent with similar rules
- **Field names**: Use standard names from `config/field-mapping.yaml`
- **Tags**: Use existing tags from `config/rule-categories.yaml`

#### 4. Write Quality Detection Logic

**Good Detection Logic**:
```yaml
detection:
  selection:
    action: "New-InboxRule"
    mailbox_rule_action: "ForwardTo"
  filter_internal:
    forwarding_address|endswith: "@company.com"
  condition: selection and not filter_internal
```

**What Makes Good Detection**:
- Specific field matching
- Appropriate use of filters
- Balanced between false positives and false negatives
- Clear logical conditions

**Avoid**:
- Overly broad wildcards: `*suspicious*`
- Hardcoded organization-specific values
- Complex regex without documentation
- Detection logic that can't be explained

#### 5. Document Thoroughly

**Required Documentation**:
- Clear description of the threat
- Why this behavior is suspicious
- What attackers accomplish
- Known false positive scenarios
- References to external documentation

**Optional but Recommended**:
- Example log entries
- Related rules
- Mitigation strategies
- Investigation tips

### Rule Status Levels

Progress your rule through these stages:

1. **experimental**: New rule, limited testing
2. **test**: Tested in controlled environment, needs production validation
3. **stable**: Validated in production, low false positive rate
4. **deprecated**: No longer recommended, kept for reference

### Testing Your Rule

Before submitting:

1. **Validate YAML syntax**: Ensure proper formatting
2. **Test against known data**: Both malicious and benign samples
3. **Check false positive rate**: Should be acceptable for the severity
4. **Verify field names**: Match your log source
5. **Review with peers**: Get feedback on detection logic

### Submission Checklist

- [ ] Rule file in correct category directory
- [ ] Unique UUID generated (use `uuidgen` or online generator)
- [ ] Title is clear and descriptive
- [ ] Description explains threat comprehensively
- [ ] Tags are appropriate and from standard taxonomy
- [ ] Detection logic is tested
- [ ] False positives are documented
- [ ] References include MITRE ATT&CK technique
- [ ] Status is set appropriately (likely 'experimental')
- [ ] YAML syntax is valid

## Code of Conduct

### Our Standards

- **Be respectful**: Treat all contributors with respect
- **Be collaborative**: Work together to improve the framework
- **Be constructive**: Provide helpful feedback
- **Be professional**: Maintain professional communication
- **Be inclusive**: Welcome contributors of all skill levels

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Publishing others' private information
- Other unprofessional conduct

## Pull Request Process

### Submitting Changes

1. **Fork the repository**
2. **Create a branch**: `git checkout -b add-rule-name`
3. **Make your changes**: Add or modify rules
4. **Test thoroughly**: Validate your changes
5. **Commit with clear message**: Describe what and why
6. **Push to your fork**: `git push origin add-rule-name`
7. **Open pull request**: Describe changes and testing performed

### Pull Request Template

```markdown
## Description
Brief description of the rule or changes

## Type of Change
- [ ] New detection rule
- [ ] Rule improvement
- [ ] Documentation update
- [ ] Field mapping addition
- [ ] Bug fix

## Testing
Describe how you tested the rule:
- Log sources used
- Test cases (malicious and benign)
- False positive testing

## Checklist
- [ ] YAML syntax is valid
- [ ] Rule follows template structure
- [ ] Documentation is complete
- [ ] References include MITRE ATT&CK
- [ ] Tags are from standard taxonomy
- [ ] False positives documented
```

### Review Process

1. **Automated checks**: Syntax validation
2. **Peer review**: Community or maintainer feedback
3. **Testing**: Validation against sample data if available
4. **Approval**: Merge when requirements met

## Style Guidelines

### YAML Formatting

- Use 2 spaces for indentation (no tabs)
- Use lowercase for field names
- Quote string values
- Use list format for multiple values
- Keep lines under 100 characters when possible

### Writing Style

- **Descriptions**: Clear, concise, technical
- **Comments**: Explain complex logic
- **References**: Prefer official documentation
- **Tags**: Use existing taxonomy

### Field Naming

Use standard field names from `config/field-mapping.yaml`:
- `action` not `operation` or `event`
- `sender` not `from` or `sender_email`
- `recipient` not `to` or `recipient_email`

## Community

### Communication

- **Issues**: Report bugs, request features, ask questions
- **Discussions**: Share ideas, propose changes
- **Pull Requests**: Submit contributions

### Recognition

Contributors will be recognized in:
- Rule author fields
- Project acknowledgments
- Release notes

## Additional Guidelines

### Security

- **No sensitive data**: Don't include real usernames, IPs, domains
- **Use placeholders**: Generic examples like `@company.com`
- **Responsible disclosure**: Report framework vulnerabilities privately

### Licensing

- All contributions are under MIT License
- Ensure you have rights to contribute
- Don't submit copyrighted material

### Rule Quality

High-quality rules have:
- **Accuracy**: Detect real threats
- **Precision**: Minimize false positives
- **Clarity**: Easy to understand and modify
- **Documentation**: Well-explained
- **Portability**: Work across environments

## Getting Help

### Resources

- **Documentation**: `docs/` directory
- **Examples**: `examples/` directory
- **Existing Rules**: `rules/` directory

### Questions?

If you have questions:
1. Check existing documentation
2. Review similar rules
3. Open an issue for discussion

## Thank You!

Your contributions help make email security analysis more effective for everyone. We appreciate your time and effort in improving Ryoshi!
