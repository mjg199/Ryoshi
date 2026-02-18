# Correlation Fields Reference

This document details all correlation and aggregation fields used in Ryoshi YAML detection rules, with usage examples and explanations.

## Overview

Ryoshi supports four rule types with different field requirements:

1. **Correlation Rules** (`rule_type: correlation`) — Group logs by user/entity and check requirements
2. **Session Rules** (`rule_type: session_correlation`) — Analyze per-session activity
3. **Sequence Rules** (`rule_type: sequence`) — Detect event patterns (e.g., failures followed by success)
4. **Compromised Access Sequence Rules** (`rule_type: compromised_access_sequence`) — Detect post-compromise patterns

---

## Common Fields in All Rules

### `detection`
Container for all detection logic. Every rule must have this section.

```yaml
detection:
  selection: {...}              # What to search for
  filter: {...}                 # Apply filters
  correlation: {...}            # Grouping/requirements (if applicable)
  condition: selection and filter with correlation
```

### `selection`
Defines what operations and fields to match. All log entries must match selection criteria to be considered.

**Common Fields:**
- `operation` — M365 operation name (e.g., `UserLoggedIn`, `MailItemsAccessed`, `SendAs`)
- `session_id` — Match any session (use `"*"` as wildcard)
- Any standard M365 audit field

**Examples:**

```yaml
# Example 1: Match successful logins
selection:
  operation: UserLoggedIn

# Example 2: Match any session (for session-based rules)
selection:
  session_id: "*"

# Example 3: Match specific operations for email access
selection:
  operation: MailItemsAccessed
  result_status: Succeeded
```

### `filter`
Optional: Apply additional filtering to selected logs.

**Common Fields:**
- `result_status` — Filter by result (e.g., `Success`, `Succeeded`, `Failed`)
- Any M365 audit field

**Example:**

```yaml
filter:
  result_status: Success
```

---

## Correlation Rule Fields

Used in **`rule_type: correlation`** rules to group logs by user and check session/IP requirements.

### `correlation` Section

#### `by`
What field to group logs by. Always `user_id` for correlation rules.

```yaml
correlation:
  by: user_id  # Group all logs by user
```

#### `requirements`
Dictionary of thresholds that grouped logs must meet.

##### `unique_sessions`
Minimum number of distinct session IDs a user must have.

**Format:** `">= N"` where N is a number

```yaml
requirements:
  unique_sessions: ">=2"  # User must have 2+ different sessions
```

**Use Case:** Detect when compromised credentials are used across multiple sessions.

##### `unique_ips`
Minimum number of distinct IP addresses a user must authenticate from.

**Format:** `">= N"`

```yaml
requirements:
  unique_ips: ">=2"  # User must authenticate from 2+ IPs
```

**Use Case:** Detect impossible travel or multi-location access.

##### `unique_countries`
Minimum number of distinct countries a user's IPs must originate from.

**Format:** `">= N"`

```yaml
requirements:
  unique_countries: ">=2"  # User must have IPs from 2+ countries
```

**Use Case:** Detect credential theft with multi-country access (e.g., US to Germany to Japan).

**Note:** Requires IP geolocation enrichment. The engine automatically enriches IPs with geolocation when this requirement is specified.

#### `timeframe`
How far back to look when grouping logs. Logs outside this window are not grouped together.

**Format:** `"30m"`, `"1h"`, `"24h"`, etc.

```yaml
correlation:
  by: user_id
  requirements:
    unique_sessions: ">=2"
    unique_ips: ">=2"
  timeframe: 24h  # All events must occur within 24 hours
```

**Use Case:** Detect multi-country access within a specific time window (e.g., "2 countries in 24h" vs "2 countries in 30 days").

### Complete Correlation Rule Example

```yaml
title: Credential Theft - Multiple Sessions from Different Countries
id: ryoshi-m365-credential-theft-multiple-sessions
severity: CRITICAL

detection:
  rule_type: correlation
  selection:
    operation: UserLoggedIn
  filter:
    result_status: Success
  correlation:
    by: user_id
    requirements:
      unique_sessions: ">=2"
      unique_ips: ">=2"
      unique_countries: ">=2"
    timeframe: 24h
  condition: selection and filter with correlation
```

**What it detects:** Users authenticating from 2+ different sessions, 2+ different IPs, originating from 2+ countries within 24 hours.

---

## Session Correlation Rule Fields

Used in **`rule_type: session_correlation`** rules to analyze activity per session ID.

### `correlation` Section

#### `by`
What field to group logs by. Must be `session_id` for session correlation rules.

```yaml
correlation:
  by: session_id  # Group all logs by session
```

#### `requirements`
Thresholds that each session's logs must meet.

##### `unique_ips`
Minimum number of distinct IP addresses used within a single session.

**Format:** `">= N"`

```yaml
requirements:
  unique_ips: ">=3"  # Session must have 3+ different IPs
```

**Use Case:** Detect token hijacking where a single session token is used from multiple IPs.

##### `unique_subnets`
Minimum number of distinct /24 subnets (subnet diversity). A subnet is a /24 CIDR block.

**Format:** `">= N"`

```yaml
requirements:
  unique_subnets: ">=3"  # Session must span 3+ different /24 subnets
```

**Use Case:** Detect impossible travel (e.g., session jumping from US to EU to Asia simultaneously).

### Complete Session Correlation Rule Example

```yaml
title: Token Compromise - Session Hijacking from Multiple IPs
id: ryoshi-m365-token-compromise-session-hijacking
severity: CRITICAL

detection:
  rule_type: session_correlation
  selection:
    session_id: "*"
  correlation:
    by: session_id
    requirements:
      unique_ips: ">=3"
      unique_subnets: ">=3"
  condition: selection grouped by session_id where unique_subnets >= 3
```

**What it detects:** Sessions using the same token from 3+ different IP addresses across 3+ different subnet ranges (indicating impossible travel or token theft).

---

## Sequence Rule Fields

Used in **`rule_type: sequence`** rules to detect patterns in event sequences.

### `selection` Variants

Sequence rules use `selection_*` prefix for different event types:

```yaml
detection:
  selection_first:
    operation: FailedUserLogon
  selection_second:
    operation: UserLoggedIn
    result_status: Success
  correlation:
    sequence:
      - selection_first
      - selection_second
    timeframe: 1h
```

### `correlation` Section

#### `sequence`
Array of selections defining the event order.

**Format:** `[event1, event2, ...]`

```yaml
correlation:
  sequence:
    - selection_failed       # First, failures
    - selection_success      # Then, success
  timeframe: 1h              # Within 1 hour
```

#### `requirements`
Optional thresholds for the pattern (in some sequence rules).

```yaml
requirements:
  min_failures: ">=3"  # At least 3 failures before the success
```

#### `timeframe`
How much time can pass between sequence events.

**Format:** `"30m"`, `"1h"`, `"24h"`, etc.

```yaml
correlation:
  sequence:
    - selection_access
    - selection_delete
  timeframe: 30m  # Delete must occur within 30m of access
```

### Complete Sequence Rule Example

```yaml
title: Failed Login Followed by Success
id: ryoshi-m365-failed-login-then-success
severity: HIGH

detection:
  selection_failed:
    operation: FailedUserLogon
  selection_success:
    operation: UserLoggedIn
    result_status: Success
  correlation:
    sequence:
      - selection_failed
      - selection_success
    timeframe: 1h
  condition: correlation
```

**What it detects:** Users who fail to log in multiple times, then successfully log in within 1 hour (password spray / brute force attack).

---

## Compromised Access Sequence Rule Fields

Used in **`rule_type: compromised_access_sequence`** rules to detect suspicious post-compromise activity.

**Important:** These rules only trigger on users/sessions already identified as compromised by Phase 1 rules.

### `selection_access` and `selection_action`

Define two event types to correlate:

```yaml
detection:
  selection_access:
    operation: MailItemsAccessed
    result_status: Succeeded
  selection_action:
    operation:
      - SoftDelete
      - HardDelete
      - MoveToDeletedItems
```

### `correlation` Section

#### `by`
What field to group by: `session_id`, `user`, or `ip`.

```yaml
correlation:
  by: session_id  # Check within same session
  # or
  by: user        # Check within same user
  # or
  by: ip          # Check within same IP
```

#### `sequence`
Order of events to detect.

```yaml
correlation:
  sequence:
    - selection_access     # First, access
    - selection_action     # Then, delete
```

#### `timeframe`
Maximum time between access and action.

```yaml
correlation:
  timeframe: 30m  # Delete must occur within 30m of access
```

### Complete Compromised Access Sequence Rule Example

```yaml
title: Email Deletion After Access - Evidence Destruction
id: ryoshi-m365-email-deletion-after-access
severity: MEDIUM

detection:
  rule_type: compromised_access_sequence
  selection_access:
    operation: MailItemsAccessed
    result_status: Succeeded
  selection_action:
    operation:
      - SoftDelete
      - HardDelete
      - MoveToDeletedItems
  correlation:
    by: session_id
    sequence:
      - selection_access
      - selection_action
    timeframe: 30m
  condition: correlation
```

**What it detects:** Within compromised sessions, emails accessed then deleted within 30 minutes (attacker covering tracks).

---

## Aggregation Fields (Alternative Approach)

Some rules use aggregation instead of correlation:

### `aggregation` Section

Alternative grouping approach for counting events.

```yaml
detection:
  selection:
    operation: MailItemsAccessed
  aggregation:
    field: session_id
    count: ">=500"
    timeframe: 1h
  condition: selection and aggregation
```

**Fields:**
- `field` — What to group by (e.g., `session_id`, `user_id`)
- `count` — Threshold (e.g., `">=500"` means 500+ matching logs per group)
- `timeframe` — Time window for aggregation

**Use Case:** Bulk email access detection (500+ MailItemsAccessed in 1 hour per session).

---

## Field Reference Table

| Field | Rule Type | Format | Example | Purpose |
|-------|-----------|--------|---------|---------|
| `unique_sessions` | correlation | `">= N"` | `">=2"` | Min distinct session IDs per user |
| `unique_ips` | correlation, session | `">= N"` | `">=3"` | Min distinct IPs |
| `unique_subnets` | session | `">= N"` | `">=3"` | Min distinct /24 subnets |
| `unique_countries` | correlation | `">= N"` | `">=2"` | Min distinct countries (requires geolocation) |
| `timeframe` | All | Duration | `"24h"`, `"1h"`, `"30m"` | Time window for grouping |
| `by` | correlation, session, access-sequence | Field name | `"user_id"`, `"session_id"` | Group by field |
| `count` | aggregation | `">= N"` | `">=500"` | Min event count per group |
| `sequence` | sequence, access-sequence | Array | `[sel1, sel2]` | Event order to detect |

---

## Best Practices

1. **Always include `timeframe`** — Without it, rules may have very high false positive rates
2. **Use `unique_countries` sparingly** — Requires IP geolocation API calls, add latency
3. **Combine multiple requirements** — Higher fidelity (e.g., `unique_sessions >= 2` AND `unique_ips >= 2`)
4. **Order matters in sequences** — `[access, then delete]` is different from `[delete, then access]`
5. **Test with real data** — Sample CSV with known attack patterns before deploying to production

---

## See Also

- [Rule Format Guide](rule-format.md) — Complete rule YAML structure
- [Getting Started](getting-started.md) — How to write and test rules
- Engine source: `engine/ryoshi-detection-engine.py` — Implementation details
