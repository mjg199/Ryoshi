#!/usr/bin/env python3
"""
Ryoshi M365 eDiscovery Detection Engine
Dynamically loads and processes detection rules from YAML files

Usage:
  python3 ryoshi-detection-engine.py -f /path/to/file.csv
  python3 ryoshi-detection-engine.py -F /path/to/folder/
  python3 ryoshi-detection-engine.py --rules-dir ./rules -f audit.csv
"""

import csv
import json
import argparse
import os
import glob
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
import re
import socket
import struct

try:
    import yaml
except ImportError:
    print("[!] PyYAML not installed. Run: pip install pyyaml")
    yaml = None

try:
    import requests
except ImportError:
    print("[!] requests not installed. Run: pip install requests")
    requests = None


# AbuseIPDB Configuration
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')  # Set via environment variable
ABUSEIPDB_CACHE = {}  # Cache to avoid repeated API calls


def ip_to_int(ip):
    """Convert IP address string to integer for subnet calculations"""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0


def get_subnet_24(ip):
    """Extract network prefix (/24 for IPv4, /64 for IPv6)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return str(ipaddress.ip_network(f"{ip_obj}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip_obj}/64", strict=False))
    except:
        pass
    return None


def get_subnet_16(ip):
    """Extract broader network prefix (/16 for IPv4, /48 for IPv6)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return str(ipaddress.ip_network(f"{ip_obj}/16", strict=False))
        return str(ipaddress.ip_network(f"{ip_obj}/48", strict=False))
    except:
        pass
    return None


def normalize_ip_address(ip_value):
    """Normalize and validate IPv4/IPv6 addresses, handling common port formats."""
    if ip_value is None:
        return None

    candidate = str(ip_value).strip()
    if not candidate:
        return None

    bracket_match = re.match(r'^\[([^\]]+)\](?::\d+)?$', candidate)
    if bracket_match:
        candidate = bracket_match.group(1)

    if '%' in candidate:
        candidate = candidate.split('%', 1)[0]

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    if candidate.count(':') == 1 and candidate.split(':', 1)[0].count('.') == 3:
        host, port = candidate.rsplit(':', 1)
        if port.isdigit():
            try:
                return str(ipaddress.ip_address(host))
            except ValueError:
                return None

    return None


def check_abuseipdb(ip, api_key=None):
    """Query AbuseIPDB for IP reputation"""
    if not requests:
        return None
    
    api_key = api_key or ABUSEIPDB_API_KEY
    if not api_key:
        return None
    
    # Check cache first
    if ip in ABUSEIPDB_CACHE:
        return ABUSEIPDB_CACHE[ip]
    
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10, verify=True)
        if response.status_code == 200:
            data = response.json().get('data', {})
            result = {
                'ip': ip,
                'abuse_confidence': data.get('abuseConfidenceScore', 0),
                'country': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'domain': data.get('domain', ''),
                'total_reports': data.get('totalReports', 0),
                'is_tor': data.get('isTor', False),
                'is_proxy': data.get('isProxy', False) or data.get('usageType', '').lower() in ['vpn', 'proxy']
            }
            ABUSEIPDB_CACHE[ip] = result
            return result
        elif response.status_code == 401:
            print(f"    [!] AbuseIPDB: Invalid API key")
            return None
        elif response.status_code == 429:
            print(f"    [!] AbuseIPDB: Rate limit exceeded")
            return None
    except requests.exceptions.SSLError as e:
        print(f"    [!] AbuseIPDB SSL error for {ip}: {str(e)[:50]}")
    except requests.exceptions.Timeout:
        print(f"    [!] AbuseIPDB timeout for {ip}")
    except Exception as e:
        print(f"    [!] AbuseIPDB error for {ip}: {str(e)[:50]}")
    
    return None


def get_ip_geolocation(ip):
    """Get IP geolocation using free ip-api.com service"""
    if not requests:
        return None

    normalized_ip = normalize_ip_address(ip)
    if not normalized_ip:
        return None

    try:
        ip_obj = ipaddress.ip_address(normalized_ip)
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
                ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
            return {'country': 'Private', 'countryCode': 'PRIV', 'city': 'Private', 'lat': 0, 'lon': 0}
    except ValueError:
        return None

    try:
        response = requests.get(f'http://ip-api.com/json/{normalized_ip}?fields=status,country,countryCode,city,lat,lon,isp,org', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return data
    except:
        pass

    return None


def calculate_distance_km(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates using Haversine formula"""
    import math
    R = 6371  # Earth radius in km
    
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    return R * c


def get_default_rules_dir():
    """Find rules directory relative to script location"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check common locations relative to script
    possible_paths = [
        os.path.join(script_dir, '..', 'rules'),      # engine/script.py -> rules/
        os.path.join(script_dir, 'rules'),            # script.py in root -> rules/
        os.path.join(os.getcwd(), 'rules'),           # current working directory
    ]
    
    for path in possible_paths:
        if os.path.isdir(path):
            return os.path.abspath(path)
    
    return None


class RyoshiDetectionEngine:
    def __init__(self, rules_dir=None, abuseipdb_key=None, exclude_countries=None):
        self.logs = []
        self.rules = {}
        self.rule_detections = {}  # All detections from YAML rules
        self.timelines = {}
        self.compromised_users = set()  # Users flagged by critical rules
        self.compromised_sessions = {}  # Sessions flagged: {session_id: {'user': user, 'ips': set()}}
        self.compromised_ips = set()  # IPs associated with compromised sessions
        self.ip_reputation = {}  # Store IP reputation data for reports
        self.ip_geolocation = {}  # Store IP geolocation data
        self.abuseipdb_key = abuseipdb_key or ABUSEIPDB_API_KEY
        
        # Comprehensive country code mappings (bidirectional)
        self.country_name_to_code = {
            'spain': 'es', 'united states': 'us', 'usa': 'us', 'united kingdom': 'gb',
            'uk': 'gb', 'great britain': 'gb', 'germany': 'de', 'france': 'fr',
            'italy': 'it', 'portugal': 'pt', 'netherlands': 'nl', 'belgium': 'be',
            'norway': 'no', 'sweden': 'se', 'ireland': 'ie', 'nigeria': 'ng',
            'canada': 'ca', 'australia': 'au', 'brazil': 'br', 'mexico': 'mx',
            'japan': 'jp', 'china': 'cn', 'india': 'in', 'russia': 'ru',
            'south africa': 'za', 'argentina': 'ar', 'poland': 'pl', 'switzerland': 'ch',
            'austria': 'at', 'denmark': 'dk', 'finland': 'fi', 'greece': 'gr',
            'hungary': 'hu', 'czech republic': 'cz', 'czechia': 'cz', 'romania': 'ro',
            'ukraine': 'ua', 'turkey': 'tr', 'israel': 'il', 'egypt': 'eg',
            'south korea': 'kr', 'korea': 'kr', 'singapore': 'sg', 'hong kong': 'hk',
            'taiwan': 'tw', 'indonesia': 'id', 'malaysia': 'my', 'thailand': 'th',
            'vietnam': 'vn', 'philippines': 'ph', 'new zealand': 'nz', 'chile': 'cl',
            'colombia': 'co', 'peru': 'pe', 'venezuela': 've', 'ecuador': 'ec',
            'morocco': 'ma', 'kenya': 'ke', 'ghana': 'gh', 'senegal': 'sn'
        }
        self.country_code_to_name = {v: k for k, v in self.country_name_to_code.items() if len(k) > 2}
        
        # Normalize excluded countries - store as lowercase ISO codes
        # Supports both multiple --exclude-country flags and comma-separated values
        self.exclude_countries = set()
        if exclude_countries:
            for c in exclude_countries:
                # Split by comma to support "ES,FR" or "ES, FR" format
                country_parts = [part.strip().lower() for part in c.split(',')]
                for c_lower in country_parts:
                    if not c_lower:
                        continue
                    # If it's a country name, convert to ISO code
                    if c_lower in self.country_name_to_code:
                        self.exclude_countries.add(self.country_name_to_code[c_lower])
                    elif len(c_lower) == 2:
                        # Already an ISO code
                        self.exclude_countries.add(c_lower)
                    else:
                        # Try as-is (might be a name not in our mapping)
                        self.exclude_countries.add(c_lower)
        
        # Auto-discover rules directory
        if rules_dir is None:
            rules_dir = get_default_rules_dir()
        
        if rules_dir:
            self.load_rules(rules_dir)
    
    def load_rules(self, rules_dir):
        """Load all YAML rules from directory"""
        if yaml is None:
            print("[!] PyYAML not installed. Skipping rule loading.")
            return
        
        print(f"[*] Loading rules from {rules_dir}...")
        
        if not os.path.isdir(rules_dir):
            print(f"[!] Rules directory not found: {rules_dir}")
            return
        
        # Find all YAML files recursively
        yaml_files = glob.glob(os.path.join(rules_dir, '**/*.yaml'), recursive=True)
        
        for rule_file in sorted(yaml_files):
            try:
                with open(rule_file, 'r') as f:
                    rule = yaml.safe_load(f)
                    if rule and 'id' in rule:
                        rule['_file'] = rule_file
                        self.rules[rule['id']] = rule
                        print(f"    [+] {rule.get('title', rule['id'])}")
            except Exception as e:
                print(f"    [!] Error loading {rule_file}: {e}")
        
        print(f"[+] Total rules loaded: {len(self.rules)}\n")

    def load_csv(self, filepath):
        """Load and parse a CSV file with M365 audit logs"""
        print(f"[*] Loading logs from {filepath}")
        count = 0
        try:
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        audit_data = {}
                        if 'AuditData' in row and row['AuditData']:
                            try:
                                audit_data = json.loads(row['AuditData'])
                            except json.JSONDecodeError:
                                pass
                        
                        log_entry = {
                            'timestamp': row.get('CreationDate', ''),
                            'user_id': row.get('UserId', '') or row.get('UserIds', ''),
                            'operation': row.get('Operation', '') or row.get('Operations', ''),
                            'audit_data': audit_data,
                            'raw': row
                        }
                        self.logs.append(log_entry)
                        count += 1
                    except Exception:
                        continue
            print(f"[+] Successfully loaded {count} events from {os.path.basename(filepath)}")
        except FileNotFoundError:
            print(f"[!] File not found: {filepath}")
        except Exception as e:
            print(f"[!] Error loading {filepath}: {e}")
        return count

    def load_folder(self, folder_path):
        """Load all CSV files from a folder"""
        print(f"[*] Loading all CSV files from folder: {folder_path}")
        csv_files = glob.glob(os.path.join(folder_path, '*.csv'))
        if not csv_files:
            print(f"[!] No CSV files found in {folder_path}")
            return 0
        
        total = 0
        for csv_file in sorted(csv_files):
            total += self.load_csv(csv_file)
        return total

    def extract_ip_addresses(self, log_entry):
        """Extract normalized IPv4/IPv6 addresses from various fields"""
        ips = set()
        audit = log_entry.get('audit_data', {})
        
        for field in ['ClientIP', 'ClientIPAddress', 'ActorIpAddress']:
            if field in audit and audit[field]:
                raw_value = audit[field]
                values = raw_value if isinstance(raw_value, list) else [raw_value]
                for value in values:
                    normalized_ip = normalize_ip_address(value)
                    if normalized_ip:
                        ips.add(normalized_ip)
        
        return ips

    def extract_session_ids(self, log_entry):
        """Extract session IDs from various fields"""
        sessions = {}
        audit = log_entry.get('audit_data', {})
        
        if 'AppAccessContext' in audit:
            aac = audit['AppAccessContext']
            if isinstance(aac, dict) and 'AADSessionId' in aac:
                sessions['aad_session'] = aac['AADSessionId']
        
        if 'SessionId' in audit:
            sessions['session_id'] = audit['SessionId']
        
        if 'DeviceProperties' in audit:
            dp = audit['DeviceProperties']
            if isinstance(dp, list):
                for prop in dp:
                    if isinstance(prop, dict) and prop.get('Name') == 'SessionId':
                        sessions['device_session'] = prop.get('Value', '')
                        break
        
        return sessions

    def check_kmsi_enabled(self, log_entry):
        """Check if Keep Me Signed In was enabled"""
        audit = log_entry.get('audit_data', {})
        
        if 'ExtendedProperties' in audit:
            ep = audit['ExtendedProperties']
            if isinstance(ep, list):
                for prop in ep:
                    if isinstance(prop, dict):
                        name = prop.get('Name', '')
                        value = prop.get('Value', '')
                        if 'RequestType' in name and 'Kmsi:kmsi' in str(value):
                            return True
        return False

    def run_all_rules(self):
        """Execute all loaded YAML rules against the logs.
        
        Optimized two-phase execution flow:
        
        Phase 1 - Compromise Detection:
          Run ONLY token theft and credential theft rules to identify compromised accounts.
          These are rules with IDs containing 'token-compromise' or 'credential-theft',
          or rules in the credential_theft category with session_correlation or 
          sequence_correlation rule types.
        
        Phase 2 - Secondary Rule Evaluation:
          Run ALL remaining rules ONLY against accounts flagged as compromised in Phase 1.
          Non-compromised accounts are skipped entirely, significantly reducing execution time.
        """
        if not self.rules:
            print("[*] No YAML rules loaded. Skipping dynamic rule execution.")
            return
        
        print(f"\n[*] Executing {len(self.rules)} YAML rules (optimized two-phase)...")
        print("-" * 50)
        
        # Separate rules into groups based on execution phase
        compromise_detection_rules = []  # Phase 1: Token/credential theft (identify compromised accounts)
        secondary_rules = []  # Phase 2: All other rules (run only against compromised accounts)
        
        for rule_id, rule in self.rules.items():
            detection = rule.get('detection', {})
            rule_type = detection.get('rule_type', 'simple')
            rule_file = rule.get('_file', '')
            
            # Phase 1 rules: Token theft and credential theft detection
            # These identify compromised accounts
            is_compromise_detection = (
                'token-compromise' in rule_id.lower() or
                'credential-theft' in rule_id.lower() or
                'credential_theft' in rule_file.lower() or
                rule_type in ['session_correlation', 'sequence_correlation']
            )
            
            if is_compromise_detection:
                compromise_detection_rules.append((rule_id, rule))
            else:
                secondary_rules.append((rule_id, rule))
        
        # Phase 1: Execute compromise detection rules to identify compromised users/sessions
        print(f"\n[*] Phase 1 - Compromise Detection: Running {len(compromise_detection_rules)} rules...")
        print("    (Token theft and credential theft detection)")
        for rule_id, rule in compromise_detection_rules:
            self._execute_rule(rule_id, rule)
        
        # Report compromised entities found
        if self.compromised_users:
            print(f"\n[+] Phase 1 Results:")
            print(f"    - Compromised users: {len(self.compromised_users)}")
            print(f"    - Compromised sessions: {len(self.compromised_sessions)}")
            print(f"    - Compromised IPs: {len(self.compromised_ips)}")
            for user in list(self.compromised_users)[:5]:
                print(f"      • {user}")
            if len(self.compromised_users) > 5:
                print(f"      ... and {len(self.compromised_users) - 5} more")
        else:
            print(f"\n[*] Phase 1 Results: No compromised accounts detected")
        
        # Phase 2: Execute secondary rules ONLY against compromised accounts
        if secondary_rules:
            print(f"\n[*] Phase 2 - Secondary Rule Evaluation: {len(secondary_rules)} rules...")
            if not self.compromised_users and not self.compromised_sessions:
                print("    [~] Skipping Phase 2 - no compromised accounts to analyze")
                print("    [+] Performance optimization: Skipped evaluation of non-compromised accounts")
            else:
                print(f"    (Analyzing only {len(self.compromised_users)} compromised user(s))")
                for rule_id, rule in secondary_rules:
                    self._execute_rule_for_compromised_only(rule_id, rule)
    
    def _execute_rule(self, rule_id, rule):
        """Execute a single rule against the logs"""
        rule_title = rule.get('title', rule_id)
        severity = rule.get('severity', 'MEDIUM').upper()
        
        # Initialize detection results for this rule
        if rule_id not in self.rule_detections:
            self.rule_detections[rule_id] = {
                'title': rule_title,
                'severity': severity,
                'matches': [],
                'count': 0
            }
        
        # Get detection criteria from rule
        detection = rule.get('detection', {})
        rule_type = detection.get('rule_type', 'simple')
        
        # Handle different rule types
        if rule_type == 'correlation':
            self._execute_correlation_rule(rule_id, rule)
            return
        elif rule_type == 'sequence_correlation':
            self._execute_sequence_rule(rule_id, rule)
            return
        elif rule_type == 'session_correlation':
            self._execute_session_rule(rule_id, rule)
            return
        elif rule_type == 'compromised_access_sequence':
            self._execute_compromised_access_sequence_rule(rule_id, rule)
            return
        
        # Simple rule - match operations directly
        selection = detection.get('selection', {})
        ops_to_match = self._get_operations_from_selection(selection)
        
        # Get threshold and timeframe if specified
        condition = detection.get('condition', '')
        threshold = self._extract_threshold(condition)
        
        # Search logs for matching operations
        matches = []
        for log_entry in self.logs:
            if self._matches_selection(log_entry, selection, ops_to_match):
                matches.append({
                    'timestamp': log_entry['timestamp'],
                    'user': log_entry['user_id'],
                    'operation': log_entry['operation'],
                    'ips': list(self.extract_ip_addresses(log_entry))
                })
        
        # Apply threshold logic if specified
        if threshold and len(matches) < threshold:
            return  # Didn't meet threshold
        
        # Store results
        self.rule_detections[rule_id]['matches'] = matches[:10]  # Keep first 10 samples
        self.rule_detections[rule_id]['count'] = len(matches)
        
        # Print findings
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Matches: {len(matches)}")
            if matches[:2]:
                for m in matches[:2]:
                    print(f"    - {m['user']} @ {m['timestamp']}")
    
    def _execute_rule_for_compromised_only(self, rule_id, rule):
        """Execute a rule ONLY against events from compromised users/sessions/IPs.
        
        This is a performance optimization for Phase 2 rules that filters out
        all events from non-compromised accounts before rule evaluation.
        """
        rule_title = rule.get('title', rule_id)
        severity = rule.get('severity', 'MEDIUM').upper()
        
        # Initialize detection results for this rule
        if rule_id not in self.rule_detections:
            self.rule_detections[rule_id] = {
                'title': rule_title,
                'severity': severity,
                'matches': [],
                'count': 0
            }
        
        # Get detection criteria from rule
        detection = rule.get('detection', {})
        rule_type = detection.get('rule_type', 'simple')
        
        # For compromised_access_sequence rules, use the dedicated method
        if rule_type == 'compromised_access_sequence':
            self._execute_compromised_access_sequence_rule(rule_id, rule)
            return
        
        # For simple rules, filter logs to only compromised users first
        selection = detection.get('selection', {})
        ops_to_match = self._get_operations_from_selection(selection)
        
        # Pre-filter logs to only include compromised users/sessions/IPs
        compromised_logs = []
        for log_entry in self.logs:
            user = log_entry['user_id']
            sessions = self.extract_session_ids(log_entry)
            ips = self.extract_ip_addresses(log_entry)
            
            # Check if this log entry is from a compromised entity
            is_compromised = False
            if user in self.compromised_users:
                is_compromised = True
            elif any(sid in self.compromised_sessions for sid in sessions.values() if sid):
                is_compromised = True
            elif any(ip in self.compromised_ips for ip in ips):
                is_compromised = True
            
            if is_compromised:
                compromised_logs.append(log_entry)
        
        # If no compromised logs to analyze, skip
        if not compromised_logs:
            return
        
        # Search filtered logs for matching operations
        matches = []
        for log_entry in compromised_logs:
            if self._matches_selection(log_entry, selection, ops_to_match):
                matches.append({
                    'timestamp': log_entry['timestamp'],
                    'user': log_entry['user_id'],
                    'operation': log_entry['operation'],
                    'ips': list(self.extract_ip_addresses(log_entry))
                })
        
        # Get threshold and timeframe if specified
        condition = detection.get('condition', '')
        threshold = self._extract_threshold(condition)
        
        # Apply threshold logic if specified
        if threshold and len(matches) < threshold:
            return
        
        # Store results
        self.rule_detections[rule_id]['matches'] = matches[:10]
        self.rule_detections[rule_id]['count'] = len(matches)
        
        # Print findings
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Matches: {len(matches)} (compromised users only)")
            if matches[:2]:
                for m in matches[:2]:
                    print(f"    - {m['user']} @ {m['timestamp']}")

    def _execute_correlation_rule(self, rule_id, rule):
        """Execute correlation rule - group by user and check session/IP requirements"""
        rule_title = rule.get('title', rule_id)
        severity = rule.get('severity', 'MEDIUM').upper()
        detection = rule.get('detection', {})
        selection = detection.get('selection', {})
        filter_criteria = detection.get('filter', {})
        correlation = detection.get('correlation', {})
        
        ops_to_match = self._get_operations_from_selection(selection)
        required_result = filter_criteria.get('result_status')
        
        # Group logins by user
        user_data = defaultdict(lambda: {
            'sessions': set(),
            'ips': set(),
            'events': [],
            'ip_countries': defaultdict(set)
        })
        
        for log_entry in self.logs:
            if self._matches_selection(log_entry, selection, ops_to_match):
                # Check result status if required
                audit = log_entry.get('audit_data', {})
                if required_result and audit.get('ResultStatus') != required_result:
                    continue
                
                user = log_entry['user_id']
                ips = self.extract_ip_addresses(log_entry)
                sessions = self.extract_session_ids(log_entry)
                country_hint = self._extract_country_hint(audit)
                
                user_data[user]['ips'].update(ips)
                if country_hint:
                    for ip in ips:
                        user_data[user]['ip_countries'][ip].add(country_hint)
                for sid_type, sid in sessions.items():
                    if sid:
                        user_data[user]['sessions'].add(sid)
                user_data[user]['events'].append({
                    'timestamp': log_entry['timestamp'],
                    'operation': log_entry['operation'],
                    'ips': list(ips)
                })
        
        # Check correlation requirements
        requirements = correlation.get('requirements', {})
        min_sessions = self._parse_requirement(requirements.get('unique_sessions', '>=1'))
        min_ips = self._parse_requirement(requirements.get('unique_ips', '>=1'))
        min_countries = self._parse_requirement(requirements.get('unique_countries', '>=1'))
        
        matches = []
        for user, data in user_data.items():
            countries = set()
            for ip in data['ips']:
                hinted = data['ip_countries'].get(ip, set())
                if hinted:
                    countries.update(hinted)
                    continue

                resolved_country = self._resolve_ip_country(ip)
                if resolved_country:
                    countries.add(resolved_country)

            if (len(data['sessions']) >= min_sessions and
                    len(data['ips']) >= min_ips and
                    len(countries) >= min_countries):
                matches.append({
                    'timestamp': data['events'][0]['timestamp'] if data['events'] else '',
                    'user': user,
                    'operation': 'Correlation Match',
                    'ips': list(data['ips']),
                    'unique_sessions': len(data['sessions']),
                    'unique_ips': len(data['ips']),
                    'unique_countries': len(countries),
                    'countries': sorted(countries),
                    'event_count': len(data['events'])
                })
        
        self.rule_detections[rule_id]['matches'] = matches[:10]
        self.rule_detections[rule_id]['count'] = len(matches)
        
        # Track compromised users for timeline generation (CRITICAL severity only)
        if matches and severity == 'CRITICAL':
            for m in matches:
                user = m.get('user', '')
                if user and ',' not in user:  # Single user
                    self.compromised_users.add(user)
        
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Users Affected: {len(matches)}")
            for m in matches[:2]:
                print(f"    - {m['user']}: {m['unique_sessions']} sessions, {m['unique_ips']} IPs, {m.get('unique_countries', 0)} countries")

    def _extract_country_hint(self, audit):
        """Extract country hint (ISO-2) from audit payload when available."""
        if not isinstance(audit, dict):
            return None

        for key in ['Country', 'CountryCode', 'country', 'countryCode']:
            value = audit.get(key)
            if isinstance(value, str):
                code = value.strip().upper()
                if len(code) == 2 and code.isalpha():
                    return code

        geo_location = audit.get('GeoLocation')
        if isinstance(geo_location, str):
            code = geo_location.strip().upper()
            if len(code) == 2 and code.isalpha():
                return code

        return None

    def _resolve_ip_country(self, ip):
        """Resolve country code for an IP using cache + geolocation lookup."""
        if not ip:
            return None

        geo = self.ip_geolocation.get(ip)
        if not geo:
            geo = get_ip_geolocation(ip)
            if geo:
                self.ip_geolocation[ip] = geo

        if not geo:
            return None

        country_code = str(geo.get('countryCode', '')).strip().upper()
        if len(country_code) == 2 and country_code.isalpha():
            return country_code

        return None
    
    def _execute_sequence_rule(self, rule_id, rule):
        """Execute sequence correlation rule - detect patterns like failed then success"""
        rule_title = rule.get('title', rule_id)
        severity = rule.get('severity', 'MEDIUM').upper()
        detection = rule.get('detection', {})
        
        selection_failed = detection.get('selection_failed', {})
        selection_success = detection.get('selection_success', {})
        filter_success = detection.get('filter_success', {})
        correlation = detection.get('correlation', {})
        
        failed_op = selection_failed.get('operation', 'UserLoginFailed')
        success_op = selection_success.get('operation', 'UserLoggedIn')
        required_result = filter_success.get('result_status')
        
        # Parse sequence requirements
        sequence = correlation.get('sequence', [])
        min_failures = 3  # Default
        for seq_item in sequence:
            if isinstance(seq_item, dict) and 'selection_failed' in seq_item:
                min_failures = self._parse_requirement(seq_item['selection_failed'])
        
        # Group events by user
        user_events = defaultdict(lambda: {'failed': [], 'success': []})
        
        for log_entry in self.logs:
            user = log_entry['user_id']
            op = log_entry['operation']
            
            try:
                ts = log_entry['timestamp'].replace('Z', '+00:00')
                if '.' not in ts:
                    ts = ts.replace('+00:00', '.000000+00:00')
                timestamp = datetime.fromisoformat(ts.replace('+00:00', ''))
            except Exception:
                continue
            
            if op == failed_op:
                user_events[user]['failed'].append({
                    'timestamp': timestamp,
                    'ips': list(self.extract_ip_addresses(log_entry)),
                    'raw_ts': log_entry['timestamp']
                })
            elif op == success_op:
                audit = log_entry.get('audit_data', {})
                if required_result and audit.get('ResultStatus') != required_result:
                    continue
                user_events[user]['success'].append({
                    'timestamp': timestamp,
                    'ips': list(self.extract_ip_addresses(log_entry)),
                    'raw_ts': log_entry['timestamp'],
                    'sessions': self.extract_session_ids(log_entry)
                })
        
        # Check for pattern: multiple failures followed by success within timeframe
        matches = []
        for user, events in user_events.items():
            if len(events['failed']) < min_failures or len(events['success']) == 0:
                continue
            
            # Sort by timestamp
            events['failed'].sort(key=lambda x: x['timestamp'])
            events['success'].sort(key=lambda x: x['timestamp'])
            
            # Look for sequences: failures followed by success within 1 hour
            for success in events['success']:
                # Count failures in the hour before success
                failures_before = [f for f in events['failed'] 
                                   if success['timestamp'] - timedelta(hours=1) <= f['timestamp'] < success['timestamp']]
                
                if len(failures_before) >= min_failures:
                    success_sessions = [sid for sid in success.get('sessions', {}).values() if sid]
                    matches.append({
                        'timestamp': success['raw_ts'],
                        'user': user,
                        'operation': 'Failed->Success Sequence',
                        'ips': success['ips'],
                        'failed_count': len(failures_before),
                        'first_failure': failures_before[0]['raw_ts'] if failures_before else '',
                        'last_failure': failures_before[-1]['raw_ts'] if failures_before else '',
                        'success_time': success['raw_ts'],
                        'success_date': success['raw_ts'][:10],
                        'success_sessions': success_sessions
                    })
                    break  # One match per user
        
        self.rule_detections[rule_id]['matches'] = matches[:10]
        self.rule_detections[rule_id]['count'] = len(matches)
        
        # Track compromised users for timeline generation (HIGH+ severity)
        if matches and severity in ['CRITICAL', 'HIGH']:
            for m in matches:
                user = m.get('user', '')
                if user:
                    self.compromised_users.add(user)
        
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Users Affected: {len(matches)}")
            for m in matches[:2]:
                print(f"    - {m['user']}: {m['failed_count']} failures before success")
    
    def _execute_session_rule(self, rule_id, rule):
        """Execute session correlation rule with hybrid detection:
        1. Network-prefix diversity (3+ /24 IPv4 or /64 IPv6 prefixes)
        2. Geolocation impossible travel
        3. AbuseIPDB reputation check
        """
        rule_title = rule.get('title', rule_id)
        severity = rule.get('severity', 'MEDIUM').upper()
        detection = rule.get('detection', {})
        correlation = detection.get('correlation', {})
        
        requirements = correlation.get('requirements', {})
        min_ips = self._parse_requirement(requirements.get('unique_ips', '>=2'))
        min_subnets = self._parse_requirement(requirements.get('unique_subnets', '>=3'))
        
        # Group by session ID
        session_data = defaultdict(lambda: {'ips': set(), 'users': set(), 'events': [], 'subnets_24': set(), 'subnets_16': set()})
        
        for log_entry in self.logs:
            sessions = self.extract_session_ids(log_entry)
            ips = self.extract_ip_addresses(log_entry)
            user = log_entry['user_id']
            
            for sid_type, sid in sessions.items():
                if sid:
                    session_data[sid]['ips'].update(ips)
                    session_data[sid]['users'].add(user)
                    # Track subnets
                    for ip in ips:
                        subnet_24 = get_subnet_24(ip)
                        subnet_16 = get_subnet_16(ip)
                        if subnet_24:
                            session_data[sid]['subnets_24'].add(subnet_24)
                        if subnet_16:
                            session_data[sid]['subnets_16'].add(subnet_16)
                    session_data[sid]['events'].append({
                        'timestamp': log_entry['timestamp'],
                        'operation': log_entry['operation'],
                        'ips': list(ips)
                    })
        
        matches = []
        print(f"\n[*] Analyzing {len(session_data)} sessions for token theft indicators...")
        
        for session_id, data in session_data.items():
            # First filter: Minimum IPs
            if len(data['ips']) < min_ips:
                continue
            
            # Second filter: Subnet diversity (primary detection method)
            subnet_count = len(data['subnets_24'])
            if subnet_count < min_subnets:
                continue
            
            # This session has suspicious subnet diversity - enrich with geolocation
            ip_details = []
            countries = set()
            suspicious_ips = []
            excluded_ips = []  # IPs from excluded countries
            total_abuse_score = 0
            
            print(f"    [*] Session {session_id[:25]}... has {subnet_count} subnets - checking geolocation...")
            
            for ip in list(data['ips'])[:20]:  # Limit to first 20 IPs for performance
                ip_info = {'ip': ip, 'country': 'N/A', 'city': '', 'abuse_score': 0, 'excluded': False}
                
                # Detect Microsoft/Azure IPs (common M365 ranges)
                is_microsoft_ip = ip.startswith(('13.', '20.', '40.', '52.', '104.', '168.', '191.'))
                
                # Get geolocation
                geo = get_ip_geolocation(ip)
                if geo:
                    ip_info['country'] = geo.get('country', 'N/A') or 'N/A'
                    ip_info['countryCode'] = geo.get('countryCode', '')
                    ip_info['city'] = geo.get('city', '')
                    ip_info['lat'] = geo.get('lat', 0)
                    ip_info['lon'] = geo.get('lon', 0)
                    ip_info['isp'] = geo.get('isp', '')
                    
                    # Check if this country should be excluded (normalize to lowercase for comparison)
                    country_code = geo.get('countryCode', '').lower()
                    country_name = geo.get('country', '').lower()
                    # Check both ISO code and country name against exclusion list
                    is_excluded = (country_code in self.exclude_countries or 
                                   country_name in self.exclude_countries or
                                   self.country_name_to_code.get(country_name, '') in self.exclude_countries)
                    if is_excluded:
                        ip_info['excluded'] = True
                        excluded_ips.append(ip)
                    else:
                        countries.add(geo.get('countryCode', 'N/A'))
                    
                    self.ip_geolocation[ip] = geo
                elif is_microsoft_ip:
                    # Label Microsoft IPs when geolocation fails
                    ip_info['country'] = 'Microsoft/Azure'
                    ip_info['isp'] = 'Microsoft Corporation'
                
                # Check AbuseIPDB
                if self.abuseipdb_key:
                    abuse_data = check_abuseipdb(ip, self.abuseipdb_key)
                    if abuse_data:
                        ip_info['abuse_score'] = abuse_data.get('abuse_confidence', 0)
                        ip_info['is_tor'] = abuse_data.get('is_tor', False)
                        ip_info['is_proxy'] = abuse_data.get('is_proxy', False)
                        ip_info['total_reports'] = abuse_data.get('total_reports', 0)
                        total_abuse_score += ip_info['abuse_score']
                        self.ip_reputation[ip] = abuse_data
                        
                        if ip_info['abuse_score'] > 25 or ip_info['is_tor'] or ip_info['is_proxy']:
                            suspicious_ips.append(ip)
                
                ip_details.append(ip_info)
            
            # Filter: If all IPs are from excluded countries, skip this session
            non_excluded_ips = [ip for ip in ip_details if not ip.get('excluded', False)]
            if len(non_excluded_ips) == 0:
                print(f"        [~] Skipped - all IPs from excluded countries ({', '.join(set(self.exclude_countries))})")
                continue
            
            # Recalculate subnet count excluding excluded country IPs
            non_excluded_subnets = set()
            for ip_info in non_excluded_ips:
                subnet = get_subnet_24(ip_info['ip'])
                if subnet:
                    non_excluded_subnets.add(subnet)
            
            # If filtered subnets don't meet threshold, skip
            if len(non_excluded_subnets) < min_subnets:
                print(f"        [~] Skipped - only {len(non_excluded_subnets)} subnets after excluding {len(excluded_ips)} IPs from {', '.join(set(self.exclude_countries))}")
                continue
            
            # Calculate risk indicators
            multi_country = len(countries) > 1
            high_abuse_score = total_abuse_score / max(len(data['ips']), 1) > 15
            has_suspicious_ips = len(suspicious_ips) > 0
            
            # Determine detection reason
            detection_reasons = []
            if len(non_excluded_subnets) >= min_subnets:
                detection_reasons.append(f"{len(non_excluded_subnets)} distinct network prefixes (/24 IPv4 or /64 IPv6, excl. {len(excluded_ips)} IPs from allowed countries)")
            if multi_country:
                detection_reasons.append(f"Multi-country access ({', '.join(countries)})")
            if has_suspicious_ips:
                detection_reasons.append(f"{len(suspicious_ips)} suspicious IPs (AbuseIPDB)")
            
            matches.append({
                'timestamp': data['events'][0]['timestamp'] if data['events'] else '',
                'user': ', '.join(data['users']),
                'operation': 'Token Hijacking Detected',
                'ips': list(data['ips']),
                'session_id': session_id,
                'unique_ips': len(data['ips']),
                'unique_subnets_24': len(non_excluded_subnets),
                'unique_subnets_16': len(data['subnets_16']),
                'event_count': len(data['events']),
                'countries': list(countries),
                'excluded_countries': list(set(ip['countryCode'] for ip in ip_details if ip.get('excluded'))),
                'excluded_ip_count': len(excluded_ips),
                'multi_country': multi_country,
                'ip_details': ip_details,
                'suspicious_ips': suspicious_ips,
                'avg_abuse_score': total_abuse_score / max(len(ip_details), 1),
                'detection_reasons': detection_reasons
            })
        
        self.rule_detections[rule_id]['matches'] = matches[:10]
        self.rule_detections[rule_id]['count'] = len(matches)
        
        # Track compromised users, sessions, and IPs for timeline generation and follow-up rules
        if matches and severity == 'CRITICAL':
            for m in matches:
                users = m.get('user', '').split(', ')
                session_id = m.get('session_id', '')
                ips = set(m.get('ips', []))
                
                for user in users:
                    if user:
                        self.compromised_users.add(user)
                
                # Track compromised sessions and their IPs
                if session_id:
                    self.compromised_sessions[session_id] = {
                        'users': set(users),
                        'ips': ips
                    }
                
                # Track compromised IPs
                self.compromised_ips.update(ips)
        
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Sessions Affected: {len(matches)}")
            for m in matches[:3]:
                reasons = ', '.join(m.get('detection_reasons', []))
                print(f"    - Session {m['session_id']}: {m['unique_ips']} IPs, {m['unique_subnets_24']} subnets")
                print(f"      Countries: {', '.join(m.get('countries', []))}")
                if m.get('suspicious_ips'):
                    print(f"      Suspicious IPs: {len(m['suspicious_ips'])}")
    
    def _execute_compromised_access_sequence_rule(self, rule_id, rule):
        """Execute rule that detects access-then-action patterns ONLY for compromised users/sessions.
        
        This rule type is specifically designed for detecting:
        - Email deletion after access (evidence destruction)
        - File exfiltration after access
        - Other access-followed-by-action patterns
        
        CRITICAL: Only analyzes events from users/sessions/IPs already identified as compromised.
        """
        rule_title = rule.get('title', rule_id)
        severity = rule.get('severity', 'MEDIUM').upper()
        detection = rule.get('detection', {})
        
        selection_access = detection.get('selection_access', {})
        selection_action = detection.get('selection_action', detection.get('selection_delete', {}))
        correlation = detection.get('correlation', {})
        
        access_ops = self._get_operations_from_selection(selection_access)
        action_ops = self._get_operations_from_selection(selection_action)
        
        correlation_by = correlation.get('by', 'session_id')  # session_id, user, or ip
        timeframe_str = correlation.get('timeframe', '30m')
        
        # Parse timeframe (e.g., '30m', '1h', '24h')
        timeframe_minutes = 30  # Default
        if 'm' in timeframe_str:
            timeframe_minutes = int(re.search(r'(\d+)', timeframe_str).group(1))
        elif 'h' in timeframe_str:
            timeframe_minutes = int(re.search(r'(\d+)', timeframe_str).group(1)) * 60
        
        # First, check if we have any compromised users/sessions to analyze
        if not self.compromised_users and not self.compromised_sessions and not self.compromised_ips:
            # No compromised entities detected yet - skip this rule
            return
        
        # Collect access and action events ONLY for compromised users/sessions/IPs
        access_events = []
        action_events = []
        
        for log_entry in self.logs:
            user = log_entry['user_id']
            sessions = self.extract_session_ids(log_entry)
            ips = self.extract_ip_addresses(log_entry)
            
            # Check if this log entry is associated with a compromised entity
            is_compromised = False
            
            # Check by user
            if user in self.compromised_users:
                is_compromised = True
            
            # Check by session
            for sid_type, sid in sessions.items():
                if sid and sid in self.compromised_sessions:
                    is_compromised = True
                    break
            
            # Check by IP
            if any(ip in self.compromised_ips for ip in ips):
                is_compromised = True
            
            if not is_compromised:
                continue  # Skip non-compromised events
            
            # Parse timestamp
            try:
                ts = log_entry['timestamp'].replace('Z', '+00:00')
                if '.' not in ts:
                    ts = ts.replace('+00:00', '.000000+00:00')
                timestamp = datetime.fromisoformat(ts.replace('+00:00', ''))
            except Exception:
                continue
            
            # Get email details for the event
            audit = log_entry.get('audit_data', {})
            email_details = self._extract_email_details(audit)
            
            event_data = {
                'timestamp': timestamp,
                'raw_ts': log_entry['timestamp'],
                'user': user,
                'operation': log_entry['operation'],
                'sessions': sessions,
                'ips': list(ips),
                'email_details': email_details,
                'audit_data': audit
            }
            
            # Categorize event
            if log_entry['operation'] in access_ops:
                access_events.append(event_data)
            elif log_entry['operation'] in action_ops:
                action_events.append(event_data)
        
        # Find access-then-action sequences within the timeframe
        matches = []
        matched_action_ids = set()  # Avoid duplicate matching
        
        for action in action_events:
            action_id = f"{action['raw_ts']}_{action['user']}_{action['operation']}"
            if action_id in matched_action_ids:
                continue
            
            # Find access events that precede this action within the timeframe
            for access in access_events:
                # Check correlation criteria
                if correlation_by == 'session_id':
                    # Must have matching session
                    access_sids = set(access['sessions'].values())
                    action_sids = set(action['sessions'].values())
                    if not access_sids.intersection(action_sids):
                        continue
                elif correlation_by == 'user':
                    if access['user'] != action['user']:
                        continue
                elif correlation_by == 'ip':
                    if not set(access['ips']).intersection(set(action['ips'])):
                        continue
                
                # Check timeframe: access must be before action and within timeframe
                time_diff = (action['timestamp'] - access['timestamp']).total_seconds() / 60
                if time_diff < 0 or time_diff > timeframe_minutes:
                    continue
                
                # Found a match!
                matched_action_ids.add(action_id)
                
                matches.append({
                    'timestamp': action['raw_ts'],
                    'user': action['user'],
                    'operation': action['operation'],
                    'ips': action['ips'],
                    'sessions': action['sessions'],
                    'access_timestamp': access['raw_ts'],
                    'access_operation': access['operation'],
                    'time_delta_minutes': round(time_diff, 1),
                    'email_details': action.get('email_details', {}),
                    'access_email_details': access.get('email_details', {})
                })
                break  # One match per action event
        
        self.rule_detections[rule_id]['matches'] = matches[:20]  # Keep more samples for evidence
        self.rule_detections[rule_id]['count'] = len(matches)
        
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Matches: {len(matches)} (from compromised users/sessions only)")
            for m in matches[:3]:
                print(f"    - {m['user']}: {m['access_operation']} -> {m['operation']} ({m['time_delta_minutes']}m)")
    
    def _extract_email_details(self, audit_data):
        """Extract email Subject, InternetMessageId, and other details from audit data"""
        details = {
            'subject': '',
            'internet_message_id': '',
            'item_id': '',
            'folder_path': ''
        }
        
        # Check AffectedItems (for delete/move operations)
        affected_items = audit_data.get('AffectedItems', [])
        if affected_items:
            first_item = affected_items[0] if isinstance(affected_items, list) else affected_items
            if isinstance(first_item, dict):
                details['subject'] = first_item.get('Subject', '')
                details['internet_message_id'] = first_item.get('InternetMessageId', '')
                details['item_id'] = first_item.get('Id', '') or first_item.get('ImmutableId', '')
                parent_folder = first_item.get('ParentFolder', {})
                if isinstance(parent_folder, dict):
                    details['folder_path'] = parent_folder.get('Path', '')
        
        # Check Item (for send/create operations)
        item = audit_data.get('Item', {})
        if item and isinstance(item, dict):
            if not details['subject']:
                details['subject'] = item.get('Subject', '')
            if not details['internet_message_id']:
                details['internet_message_id'] = item.get('InternetMessageId', '')
            if not details['item_id']:
                details['item_id'] = item.get('Id', '') or item.get('ImmutableId', '')
        
        # Check Folders (for MailItemsAccessed)
        folders = audit_data.get('Folders', [])
        for folder in folders:
            if isinstance(folder, dict):
                folder_items = folder.get('FolderItems', [])
                for f_item in folder_items:
                    if isinstance(f_item, dict):
                        if not details['subject']:
                            details['subject'] = f_item.get('Subject', '')
                        if not details['internet_message_id']:
                            details['internet_message_id'] = f_item.get('InternetMessageId', '')
                        if not details['item_id']:
                            details['item_id'] = f_item.get('Id', '') or f_item.get('ImmutableId', '')
                if not details['folder_path']:
                    details['folder_path'] = folder.get('Path', '')
        
        # Check ObjectId for SharePoint/OneDrive operations
        object_id = audit_data.get('ObjectId', '')
        if object_id and not details['subject']:
            # Use filename as detail for file operations
            source_filename = audit_data.get('SourceFileName', '')
            if source_filename:
                details['subject'] = source_filename
            else:
                details['subject'] = object_id
        
        return details
    
    def _parse_requirement(self, req_str):
        """Parse requirement string like '>=2' into integer"""
        if isinstance(req_str, int):
            return req_str
        match = re.search(r'(\d+)', str(req_str))
        return int(match.group(1)) if match else 1
    
    def _get_operations_from_selection(self, selection):
        """Extract operation names from selection criteria"""
        ops = []
        
        if isinstance(selection, dict):
            op_value = selection.get('operation') or selection.get('Operations')
            if isinstance(op_value, list):
                ops = op_value
            elif isinstance(op_value, str):
                ops = [op_value]
        elif isinstance(selection, list):
            for item in selection:
                if isinstance(item, dict):
                    op = item.get('operation') or item.get('Operations')
                    if op:
                        ops.append(op) if isinstance(op, str) else ops.extend(op)
        
        return ops
    
    def _matches_selection(self, log_entry, selection, ops_to_match):
        """Check if a log entry matches the selection criteria"""
        # Match by operation
        if ops_to_match:
            if log_entry['operation'] not in ops_to_match:
                # Check for partial/prefix matches
                matched = False
                for op in ops_to_match:
                    if op.endswith('*') and log_entry['operation'].startswith(op[:-1]):
                        matched = True
                        break
                if not matched:
                    return False
        
        # Additional field matching from selection
        if isinstance(selection, dict):
            audit = log_entry.get('audit_data', {})
            for key, expected in selection.items():
                if key in ['operation', 'Operations']:
                    continue  # Already handled
                actual = audit.get(key) or log_entry.get('raw', {}).get(key)
                if expected and actual != expected:
                    return False
        
        return True
    
    def _extract_threshold(self, condition):
        """Extract numeric threshold from condition string"""
        import re
        match = re.search(r'count[^0-9]*([0-9]+)', str(condition), re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def build_timeline(self, user):
        """Build activity timeline for a compromised user.
        
        Format:
        - Timestamp
        - Operation
        - Detail (Subject/InternetMessageId/ObjectId)
        - IP
        """
        print(f"\n[*] Building activity timeline for {user}...")
        
        events = []
        for log_entry in self.logs:
            if log_entry['user_id'] == user:
                ips = self.extract_ip_addresses(log_entry)
                sessions = self.extract_session_ids(log_entry)
                audit = log_entry.get('audit_data', {})
                
                # Extract detail (Subject, InternetMessageId, ObjectId, etc.)
                details = self._extract_timeline_details(audit)
                
                events.append({
                    'timestamp': log_entry['timestamp'],
                    'operation': log_entry['operation'],
                    'detail': details,
                    'ip': list(ips)[0] if ips else '',  # Primary IP
                    'all_ips': list(ips),
                    'sessions': sessions,
                    'workload': audit.get('Workload', ''),
                    'result': audit.get('ResultStatus', '')
                })
        
        events.sort(key=lambda x: x['timestamp'], reverse=True)  # Most recent first
        self.timelines[user] = events
        print(f"[+] Found {len(events)} events for {user}")
        return events
    
    def _extract_timeline_details(self, audit_data):
        """Extract detail string for timeline (Subject/InternetMessageId/ObjectId).
        
        Priority order:
        1. Subject (email subject)
        2. InternetMessageId
        3. ObjectId (file path/URL)
        4. ListItemUniqueId
        5. SiteUrl + SourceRelativeUrl
        6. SourceFileName
        7. 'no_detail' if nothing found
        """
        details = []
        
        # === Exchange operations (Folders, AffectedItems, Item) ===
        
        # Check Folders (MailItemsAccessed)
        folders = audit_data.get('Folders', [])
        for folder in folders:
            if isinstance(folder, dict):
                folder_items = folder.get('FolderItems', [])
                for f_item in folder_items:
                    if isinstance(f_item, dict):
                        detail = (f_item.get('Subject') or 
                                  f_item.get('InternetMessageId') or 
                                  f_item.get('Id'))
                        if detail:
                            details.append(detail)
        
        # Check AffectedItems (SoftDelete, HardDelete, MoveToDeletedItems)
        affected_items = audit_data.get('AffectedItems', [])
        for item in affected_items:
            if isinstance(item, dict):
                detail = (item.get('Subject') or 
                          item.get('InternetMessageId') or
                          (item.get('ParentFolder') or {}).get('Path') or
                          item.get('ImmutableId') or
                          item.get('Id'))
                if detail:
                    details.append(detail)
        
        # Check Item (Send, Create)
        item = audit_data.get('Item', {})
        if item and isinstance(item, dict):
            detail = (item.get('Subject') or 
                      item.get('InternetMessageId') or
                      (item.get('ParentFolder') or {}).get('Path') or
                      item.get('ImmutableId') or
                      item.get('Id'))
            if detail:
                details.append(detail)
        
        # === OneDrive/SharePoint operations ===
        
        if not details:
            object_id = audit_data.get('ObjectId')
            list_item_id = audit_data.get('ListItemUniqueId')
            site_url = audit_data.get('SiteUrl', '')
            rel_url = audit_data.get('SourceRelativeUrl', '')
            file_name = audit_data.get('SourceFileName', '')
            
            if object_id:
                details.append(object_id)
            elif list_item_id:
                details.append(list_item_id)
            elif site_url and rel_url:
                details.append(site_url + rel_url)
            elif rel_url and file_name:
                details.append(rel_url + '/' + file_name)
            elif file_name:
                details.append(file_name)
        
        # Return first detail or 'no_detail'
        if details:
            return details[0]
        return 'no_detail'

    def generate_report(self, output_dir='/tmp'):
        """Generate detection and timeline reports (JSON, HTML, Markdown)"""
        print(f"\n[*] Generating reports to {output_dir}...")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Count rule detections by severity
        rule_findings = {}
        for rule_id, data in self.rule_detections.items():
            if data['count'] > 0:
                rule_findings[rule_id] = {
                    'title': data['title'],
                    'severity': data['severity'],
                    'count': data['count'],
                    'samples': data['matches']
                }
        
        # Calculate totals from rule findings
        total_unique_ips = set()
        for rule_id, data in rule_findings.items():
            for match in data.get('samples', []):
                ips = match.get('ips', [])
                if isinstance(ips, list):
                    total_unique_ips.update(ips)
        
        # Count by category
        credential_theft_count = sum(1 for rid in rule_findings if 'credential-theft' in rid)
        token_compromise_count = sum(1 for rid in rule_findings if 'token-compromise' in rid)
        
        # Count severity levels
        critical_count = sum(1 for d in rule_findings.values() if d['severity'] == 'CRITICAL')
        high_count = sum(1 for d in rule_findings.values() if d['severity'] == 'HIGH')
        medium_count = sum(1 for d in rule_findings.values() if d['severity'] == 'MEDIUM')
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_events_analyzed': len(self.logs),
            'unique_ips_found': len(total_unique_ips),
            'rules_loaded': len(self.rules),
            'compromised_users': list(self.compromised_users),
            'detections': {
                'total_rules_triggered': len(rule_findings),
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count
            },
            'rule_findings': rule_findings
        }
        
        # Save JSON report
        report_path = os.path.join(output_dir, 'ryoshi_detection_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Detection report saved: {report_path}")
        
        # Generate HTML report
        self._generate_html_report(output_dir, report, rule_findings)
        
        # Generate Markdown report
        self._generate_markdown_report(output_dir, report, rule_findings)
        
        # Save timelines (JSON and CSV)
        for user, timeline in self.timelines.items():
            safe_user = user.replace('@', '_').replace('.', '_')
            
            # Save JSON timeline
            timeline_path = os.path.join(output_dir, f'ryoshi_timeline_{safe_user}.json')
            with open(timeline_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'user': user,
                    'event_count': len(timeline),
                    'timeline': timeline
                }, f, indent=2, default=str)
            print(f"[+] Timeline saved: {timeline_path}")
            
            # Save CSV timeline
            self._save_timeline_csv(output_dir, user, safe_user, timeline)
        
        # Save combined timeline CSV for all users
        if self.timelines:
            self._save_combined_timeline_csv(output_dir)
        
        # Generate investigation support CSVs
        self._save_suspicious_sessions_csv(output_dir)
        self._save_session_ips_csv(output_dir)
        self._save_inbox_rules_csv(output_dir)
        
        # Generate unified detection report CSV
        self._save_detection_report_csv(output_dir, rule_findings)
    
    def _save_timeline_csv(self, output_dir, user, safe_user, timeline):
        """Save individual user timeline as CSV:
        Timestamp, Operation, Detail, IP
        """
        csv_path = os.path.join(output_dir, f'ryoshi_timeline_{safe_user}.csv')
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(['Timestamp', 'Operation', 'Detail', 'IP'])
            
            # Write data rows (already sorted by timestamp, most recent first)
            for event in timeline:
                # Clean timestamp (remove trailing Z and milliseconds if present)
                ts = event.get('timestamp', '')
                if ts.endswith('Z'):
                    ts = ts[:-1]
                if '.' in ts:
                    ts = ts.split('.')[0]  # Remove milliseconds
                
                writer.writerow([
                    ts,
                    event.get('operation', ''),
                    event.get('detail', 'no_detail'),
                    event.get('ip', '')
                ])
        print(f"[+] Timeline CSV saved: {csv_path}")
    
    def _save_combined_timeline_csv(self, output_dir):
        """Save combined timeline for all compromised users as CSV"""
        csv_path = os.path.join(output_dir, 'ryoshi_combined_timeline.csv')
        
        # Combine all timelines
        all_events = []
        for user, timeline in self.timelines.items():
            for event in timeline:
                all_events.append({
                    'user': user,
                    **event
                })
        
        # Sort by timestamp (most recent first)
        all_events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write header with user column for combined output
            writer.writerow(['Timestamp', 'User', 'Operation', 'Detail', 'IP'])
            
            for event in all_events:
                # Clean timestamp
                ts = event.get('timestamp', '')
                if ts.endswith('Z'):
                    ts = ts[:-1]
                if '.' in ts:
                    ts = ts.split('.')[0]
                
                writer.writerow([
                    ts,
                    event.get('user', ''),
                    event.get('operation', ''),
                    event.get('detail', 'no_detail'),
                    event.get('ip', '')
                ])
        print(f"[+] Combined timeline CSV saved: {csv_path}")

    def _save_suspicious_sessions_csv(self, output_dir):
        """Save suspicious sessions per user as CSV.
        
        One row per user with columns:
        - User: User identifier
        - SessionIDs: Comma-separated list of suspicious session IDs
        """
        if not self.compromised_sessions and not self.compromised_users:
            return
        
        csv_path = os.path.join(output_dir, 'ryoshi_suspicious_sessions.csv')
        
        # Group sessions by user
        user_sessions = defaultdict(set)
        for session_id, session_data in self.compromised_sessions.items():
            users = session_data.get('users', set())
            for user in users:
                user_sessions[user].add(session_id)
        
        # Also include users from compromised_users who might not have sessions tracked
        for user in self.compromised_users:
            if user not in user_sessions:
                user_sessions[user] = set()
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['User', 'SessionIDs'])
            
            for user in sorted(user_sessions.keys()):
                sessions = user_sessions[user]
                session_list = '; '.join(sorted(sessions)) if sessions else 'N/A'
                writer.writerow([user, session_list])
        
        print(f"[+] Suspicious sessions CSV saved: {csv_path}")

    def _save_session_ips_csv(self, output_dir):
        """Save IP addresses per session as CSV.
        
        One row per session with columns:
        - SessionID: Session identifier
        - IPAddresses: Comma-separated list of associated IP addresses
        - User: Associated user(s)
        """
        if not self.compromised_sessions:
            return
        
        csv_path = os.path.join(output_dir, 'ryoshi_session_ips.csv')
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['SessionID', 'IPAddresses', 'User'])
            
            for session_id, session_data in sorted(self.compromised_sessions.items()):
                ips = session_data.get('ips', set())
                users = session_data.get('users', set())
                
                ip_list = '; '.join(sorted(ips)) if ips else 'N/A'
                user_list = '; '.join(sorted(users)) if users else 'N/A'
                
                writer.writerow([session_id, ip_list, user_list])
        
        print(f"[+] Session IPs CSV saved: {csv_path}")

    def _save_inbox_rules_csv(self, output_dir):
        """Save inbox rule creation details as CSV.
        
        Extracts full details from inbox rule operations including:
        - Timestamp
        - User
        - Operation (New-InboxRule, Set-InboxRule, etc.)
        - RuleName
        - RuleCondition
        - ForwardTo
        - ForwardAsAttachmentTo
        - RedirectTo
        - DeleteMessage
        - MoveToFolder
        - MarkAsRead
        - ClientIP
        - SessionID
        - FullParameters (JSON string of all parameters)
        """
        inbox_rule_ops = ['New-InboxRule', 'Set-InboxRule', 'Enable-InboxRule', 'UpdateInboxRules']
        
        inbox_rules = []
        for log_entry in self.logs:
            if log_entry['operation'] in inbox_rule_ops:
                audit_data = log_entry.get('audit_data', {})
                parameters = audit_data.get('Parameters', [])
                
                # Extract parameters into a dict
                params_dict = {}
                if isinstance(parameters, list):
                    for param in parameters:
                        if isinstance(param, dict) and 'Name' in param and 'Value' in param:
                            params_dict[param['Name']] = param['Value']
                elif isinstance(parameters, dict):
                    params_dict = parameters
                
                # Also check OperationProperties for additional details
                op_props = audit_data.get('OperationProperties', [])
                if isinstance(op_props, list):
                    for prop in op_props:
                        if isinstance(prop, dict) and 'Name' in prop and 'Value' in prop:
                            params_dict[prop['Name']] = prop['Value']
                
                # Extract specific fields
                rule_details = {
                    'timestamp': log_entry['timestamp'],
                    'user': log_entry['user_id'],
                    'operation': log_entry['operation'],
                    'rule_name': params_dict.get('Name', audit_data.get('Name', '')),
                    'rule_condition': params_dict.get('FromAddressContainsWords', 
                                     params_dict.get('SubjectContainsWords',
                                     params_dict.get('BodyContainsWords', ''))),
                    'forward_to': params_dict.get('ForwardTo', ''),
                    'forward_as_attachment': params_dict.get('ForwardAsAttachmentTo', ''),
                    'redirect_to': params_dict.get('RedirectTo', ''),
                    'delete_message': params_dict.get('DeleteMessage', ''),
                    'move_to_folder': params_dict.get('MoveToFolder', ''),
                    'mark_as_read': params_dict.get('MarkAsRead', ''),
                    'client_ip': '',
                    'session_id': '',
                    'full_parameters': json.dumps(params_dict) if params_dict else ''
                }
                
                # Extract IP and session
                ips = list(self.extract_ip_addresses(log_entry))
                sessions = self.extract_session_ids(log_entry)
                rule_details['client_ip'] = ips[0] if ips else ''
                rule_details['session_id'] = sessions.get('session_id', sessions.get('aad_session', ''))
                
                inbox_rules.append(rule_details)
        
        if not inbox_rules:
            return
        
        csv_path = os.path.join(output_dir, 'ryoshi_inbox_rules.csv')
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Timestamp', 'User', 'Operation', 'RuleName', 'RuleCondition',
                'ForwardTo', 'ForwardAsAttachment', 'RedirectTo', 'DeleteMessage',
                'MoveToFolder', 'MarkAsRead', 'ClientIP', 'SessionID', 'FullParameters'
            ])
            
            for rule in sorted(inbox_rules, key=lambda x: x['timestamp'], reverse=True):
                # Clean timestamp
                ts = rule['timestamp']
                if ts.endswith('Z'):
                    ts = ts[:-1]
                if '.' in ts:
                    ts = ts.split('.')[0]
                
                writer.writerow([
                    ts,
                    rule['user'],
                    rule['operation'],
                    rule['rule_name'],
                    rule['rule_condition'],
                    rule['forward_to'],
                    rule['forward_as_attachment'],
                    rule['redirect_to'],
                    rule['delete_message'],
                    rule['move_to_folder'],
                    rule['mark_as_read'],
                    rule['client_ip'],
                    rule['session_id'],
                    rule['full_parameters']
                ])
        
        print(f"[+] Inbox rules CSV saved: {csv_path}")

    def _save_detection_report_csv(self, output_dir, rule_findings):
        """Save unified detection report as CSV.
        
        Generates one row per detection event across all rules and compromised users.
        Columns:
        - Line: Sequential number (1 to n)
        - Timestamp: UTC timestamp of the detection
        - Level: Rule severity (LOW, MEDIUM, HIGH, CRITICAL)
        - User: Affected user
        - Rule: Rule name/title
        - Details: Context-specific information based on rule type
        """
        if not rule_findings:
            return
        
        csv_path = os.path.join(output_dir, 'ryoshi_detections.csv')
        
        # Collect all detection rows
        detection_rows = []
        
        for rule_id, rule_data in rule_findings.items():
            rule_title = rule_data.get('title', rule_id)
            severity = rule_data.get('severity', 'MEDIUM').upper()
            samples = rule_data.get('samples', [])
            
            for match in samples:
                timestamp = match.get('timestamp', '')
                # Clean timestamp
                if timestamp:
                    if timestamp.endswith('Z'):
                        timestamp = timestamp[:-1]
                    if timestamp.endswith(' '):
                        timestamp = timestamp.strip()
                    if '.' in timestamp:
                        timestamp = timestamp.split('.')[0]
                
                user = match.get('user', 'Unknown')
                
                # Build details based on rule type
                details = self._build_detection_details(rule_id, match)
                
                detection_rows.append({
                    'timestamp': timestamp,
                    'level': severity,
                    'user': user,
                    'rule': rule_title,
                    'details': details
                })
        
        # Sort by timestamp (most recent first)
        detection_rows.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Write CSV
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Line', 'Timestamp', 'Level', 'User', 'Rule', 'Details'])
            
            for idx, row in enumerate(detection_rows, 1):
                writer.writerow([
                    idx,
                    row['timestamp'],
                    row['level'],
                    row['user'],
                    row['rule'],
                    row['details']
                ])
        
        print(f"[+] Detection report CSV saved: {csv_path}")

    def _build_detection_details(self, rule_id, match):
        """Build context-specific details string for detection CSV.
        
        Formats details based on rule type:
        - Token theft: Session ID, IPs, subnet count, countries
        - Credential theft: Session count, IP count, event count
        - Inbox rules: Rule name, forward/delete actions
        - Email deletion: Operation details
        - Other rules: IPs and operation info
        """
        details_parts = []
        
        rule_id_lower = rule_id.lower()
        
        # Token compromise / session hijacking
        if 'token-compromise' in rule_id_lower or 'session-hijacking' in rule_id_lower:
            session_id = match.get('session_id', '')
            if session_id:
                details_parts.append(f"SessionID: {session_id}")
            
            unique_ips = match.get('unique_ips', 0)
            unique_subnets = match.get('unique_subnets_24', 0)
            if unique_ips:
                details_parts.append(f"IPs: {unique_ips}")
            if unique_subnets:
                details_parts.append(f"Subnets: {unique_subnets}")
            
            countries = match.get('countries', [])
            if countries:
                details_parts.append(f"Countries: {', '.join(countries)}")
            
            ips = match.get('ips', [])
            if ips and len(ips) <= 5:
                details_parts.append(f"IP List: {', '.join(ips[:5])}")
            elif ips:
                details_parts.append(f"IP List: {', '.join(ips[:5])}... (+{len(ips)-5} more)")
        
        # Credential theft / multiple sessions
        elif 'credential-theft' in rule_id_lower or 'multiple-sessions' in rule_id_lower:
            unique_sessions = match.get('unique_sessions', 0)
            unique_ips = match.get('unique_ips', 0)
            event_count = match.get('event_count', 0)
            
            if unique_sessions:
                details_parts.append(f"Sessions: {unique_sessions}")
            if unique_ips:
                details_parts.append(f"IPs: {unique_ips}")
            if event_count:
                details_parts.append(f"Events: {event_count}")
            
            ips = match.get('ips', [])
            if ips:
                details_parts.append(f"IP List: {', '.join(ips[:5])}")
                if len(ips) > 5:
                    details_parts[-1] += f"... (+{len(ips)-5} more)"
        
        # Failed login then success
        elif 'failed-login' in rule_id_lower or 'brute-force' in rule_id_lower:
            failed_count = match.get('failed_count', 0)
            first_failure = match.get('first_failure', '')
            success_time = match.get('success_time', '')
            
            if failed_count:
                details_parts.append(f"Failed attempts: {failed_count}")
            if first_failure:
                details_parts.append(f"First failure: {first_failure[:19]}")
            if success_time:
                details_parts.append(f"Success: {success_time[:19]}")
        
        # Inbox rule creation
        elif 'inbox-rule' in rule_id_lower:
            # Get details from the match - these might be in different formats
            ips = match.get('ips', [])
            if ips:
                details_parts.append(f"IP: {ips[0] if ips else 'N/A'}")
            
            operation = match.get('operation', '')
            if operation:
                details_parts.append(f"Operation: {operation}")
        
        # Email deletion
        elif 'email-deletion' in rule_id_lower or 'evidence-destruction' in rule_id_lower:
            access_count = match.get('access_count', 0)
            delete_count = match.get('delete_count', 0)
            session_id = match.get('session_id', '')
            
            if session_id:
                details_parts.append(f"SessionID: {session_id}")
            if access_count:
                details_parts.append(f"Accesses: {access_count}")
            if delete_count:
                details_parts.append(f"Deletions: {delete_count}")
        
        # SendAs / BEC
        elif 'sendas' in rule_id_lower or 'bec' in rule_id_lower:
            ips = match.get('ips', [])
            operation = match.get('operation', '')
            
            if operation:
                details_parts.append(f"Operation: {operation}")
            if ips:
                details_parts.append(f"IP: {', '.join(ips[:3])}")
        
        # Data exfiltration rules
        elif 'exfiltration' in rule_id_lower or 'bulk' in rule_id_lower or 'mass' in rule_id_lower:
            event_count = match.get('event_count', match.get('count', 0))
            session_id = match.get('session_id', '')
            
            if session_id:
                details_parts.append(f"SessionID: {session_id}")
            if event_count:
                details_parts.append(f"Events: {event_count}")
            
            ips = match.get('ips', [])
            if ips:
                details_parts.append(f"IP: {', '.join(ips[:3])}")
        
        # Default fallback for other rules
        else:
            operation = match.get('operation', '')
            if operation:
                details_parts.append(f"Operation: {operation}")
            
            ips = match.get('ips', [])
            if ips:
                details_parts.append(f"IPs: {', '.join(ips[:5])}")
            
            event_count = match.get('event_count', 0)
            if event_count:
                details_parts.append(f"Events: {event_count}")
        
        return ' | '.join(details_parts) if details_parts else 'No additional details'

    def _generate_html_report(self, output_dir, report, rule_findings):
        """Generate professional HTML detection report"""
        
        # Count severities
        critical_count = sum(1 for d in self.rule_detections.values() if d['severity'] == 'CRITICAL' and d['count'] > 0)
        high_count = sum(1 for d in self.rule_detections.values() if d['severity'] == 'HIGH' and d['count'] > 0)
        medium_count = sum(1 for d in self.rule_detections.values() if d['severity'] == 'MEDIUM' and d['count'] > 0)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ryoshi Security Detection Report</title>
    <style>
        :root {{
            --primary-dark: #0d1b2a;
            --primary-blue: #1b4965;
            --accent-blue: #3d5a80;
            --light-blue: #5fa8d3;
            --critical-red: #c1121f;
            --warning-orange: #e07b39;
            --success-green: #2a9d8f;
            --background: #f8f9fa;
            --card-bg: #ffffff;
            --text-primary: #1d1d1d;
            --text-secondary: #5c5c5c;
            --border-light: #e0e0e0;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Arial, sans-serif;
            background: var(--background);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .report-header {{
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary-blue) 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 40px;
        }}
        
        .header-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .logo-section {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        
        .logo-icon {{
            width: 56px;
            height: 56px;
            background: rgba(255,255,255,0.15);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
        }}
        
        .report-title {{
            font-size: 28px;
            font-weight: 600;
            letter-spacing: -0.5px;
        }}
        
        .report-subtitle {{
            font-size: 14px;
            opacity: 0.85;
            margin-top: 4px;
        }}
        
        .report-meta {{
            text-align: right;
        }}
        
        .report-date {{
            font-size: 14px;
            opacity: 0.9;
        }}
        
        .report-id {{
            font-size: 12px;
            opacity: 0.7;
            margin-top: 4px;
            font-family: 'Consolas', monospace;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 40px 60px;
        }}
        
        .section {{
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
            padding: 32px;
            margin-bottom: 28px;
        }}
        
        .section-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-light);
        }}
        
        .section-icon {{
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }}
        
        .section-icon.blue {{ background: rgba(59, 130, 246, 0.1); }}
        .section-icon.red {{ background: rgba(193, 18, 31, 0.1); }}
        .section-icon.orange {{ background: rgba(224, 123, 57, 0.1); }}
        .section-icon.green {{ background: rgba(42, 157, 143, 0.1); }}
        
        .section-title {{
            font-size: 20px;
            font-weight: 600;
            color: var(--primary-dark);
            flex: 1;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}
        
        .metric-card {{
            background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%);
            border: 1px solid var(--border-light);
            border-radius: 10px;
            padding: 24px 20px;
            text-align: center;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        
        .metric-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        
        .metric-value {{
            font-size: 32px;
            font-weight: 700;
            color: var(--primary-blue);
            line-height: 1.2;
        }}
        
        .metric-value.critical {{ color: var(--critical-red); }}
        .metric-value.warning {{ color: var(--warning-orange); }}
        .metric-value.success {{ color: var(--success-green); }}
        
        .metric-label {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 8px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .risk-badge {{
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .risk-badge.critical {{
            background: rgba(193, 18, 31, 0.1);
            color: var(--critical-red);
        }}
        
        .risk-badge.high {{
            background: rgba(224, 123, 57, 0.1);
            color: var(--warning-orange);
        }}
        
        .risk-badge.medium {{
            background: rgba(251, 191, 36, 0.1);
            color: #b45309;
        }}
        
        .risk-badge.low {{
            background: rgba(42, 157, 143, 0.1);
            color: var(--success-green);
        }}
        
        .finding-card {{
            background: #ffffff;
            border: 1px solid var(--border-light);
            border-radius: 10px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: box-shadow 0.2s ease;
        }}
        
        .finding-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }}
        
        .finding-card.critical {{
            border-left: 4px solid var(--critical-red);
        }}
        
        .finding-card.warning {{
            border-left: 4px solid var(--warning-orange);
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: #fafafa;
            border-bottom: 1px solid var(--border-light);
        }}
        
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
            color: var(--primary-dark);
        }}
        
        .finding-body {{
            padding: 0;
        }}
        
        .data-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .data-table th {{
            background: var(--primary-blue);
            color: white;
            padding: 14px 16px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
        }}
        
        .data-table td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-light);
            font-size: 14px;
            vertical-align: top;
        }}
        
        .data-table tr:nth-child(even) {{
            background: #f9fafb;
        }}
        
        .data-table tr:hover {{
            background: #f0f4f8;
        }}
        
        .data-table td:first-child {{
            font-weight: 600;
            color: var(--text-secondary);
            width: 180px;
        }}
        
        .ip-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}
        
        .ip-tag {{
            background: #e8f4f8;
            padding: 4px 10px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            color: var(--primary-blue);
        }}
        
        .status-yes {{
            color: var(--critical-red);
            font-weight: 600;
        }}
        
        .status-no {{
            color: var(--success-green);
            font-weight: 600;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 40px 20px;
            color: var(--text-secondary);
        }}
        
        .empty-icon {{
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }}
        
        .empty-text {{
            font-size: 16px;
            color: var(--success-green);
            font-weight: 500;
        }}
        
        .report-footer {{
            text-align: center;
            padding: 32px;
            color: var(--text-secondary);
            font-size: 13px;
            border-top: 1px solid var(--border-light);
            margin-top: 20px;
        }}
        
        .footer-brand {{
            font-weight: 600;
            color: var(--primary-blue);
        }}
        
        .rule-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-light);
        }}
        
        .rule-item:last-child {{
            border-bottom: none;
        }}
        
        .rule-info {{
            flex: 1;
        }}
        
        .rule-title {{
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .rule-count {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 2px;
        }}
        
        /* Tab Navigation */
        .tab-nav {{
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            border-bottom: 2px solid var(--border-light);
            padding-bottom: 0;
        }}
        
        .tab-btn {{
            padding: 12px 24px;
            background: transparent;
            border: none;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-secondary);
            cursor: pointer;
            border-bottom: 3px solid transparent;
            margin-bottom: -2px;
            transition: all 0.2s ease;
        }}
        
        .tab-btn:hover {{
            color: var(--primary-blue);
        }}
        
        .tab-btn.active {{
            color: var(--primary-blue);
            border-bottom-color: var(--primary-blue);
        }}
        
        .tab-content {{
            display: none;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        /* Timeline Table */
        .timeline-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        
        .timeline-table th {{
            background: var(--primary-blue);
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}
        
        .timeline-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-light);
            vertical-align: top;
        }}
        
        .timeline-table tr:nth-child(even) {{
            background: #f9fafb;
        }}
        
        .timeline-table tr:hover {{
            background: #f0f4f8;
        }}
        
        .timeline-user {{
            font-weight: 600;
            color: var(--primary-blue);
        }}
        
        .timeline-op {{
            font-family: 'Consolas', monospace;
            font-size: 12px;
            background: #e8f4f8;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        
        .timeline-filter {{
            margin-bottom: 16px;
            display: flex;
            gap: 16px;
            align-items: center;
        }}
        
        .timeline-filter select {{
            padding: 8px 12px;
            border: 1px solid var(--border-light);
            border-radius: 6px;
            font-size: 14px;
        }}
        
        .timeline-filter input {{
            padding: 8px 12px;
            border: 1px solid var(--border-light);
            border-radius: 6px;
            font-size: 14px;
            width: 300px;
        }}
        
        .timeline-scroll {{
            max-height: 600px;
            overflow-y: auto;
            border: 1px solid var(--border-light);
            border-radius: 8px;
        }}
    </style>
</head>
<body>
    <header class="report-header">
        <div class="header-content">
            <div class="logo-section">
                <div class="logo-icon">&#128737;</div>
                <div>
                    <div class="report-title">Ryoshi Security Report</div>
                    <div class="report-subtitle">M365 eDiscovery Threat Detection Analysis</div>
                </div>
            </div>
            <div class="report-meta">
                <div class="report-date">Generated: {report['generated_at'][:19].replace('T', ' ')}</div>
                <div class="report-id">Report ID: RYO-{report['generated_at'][:10].replace('-', '')}</div>
            </div>
        </div>
    </header>
    
    <main class="container">
        <nav class="tab-nav">
            <button class="tab-btn active" onclick="showTab('detections')">&#128202; Detections</button>
            <button class="tab-btn" onclick="showTab('timeline')">&#128197; Timeline</button>
        </nav>
        
        <div id="detections" class="tab-content active">
        <section class="section">
            <div class="section-header">
                <div class="section-icon blue">&#128202;</div>
                <h2 class="section-title">Executive Summary</h2>
            </div>
            <div class="summary-grid">
                <div class="metric-card">
                    <div class="metric-value">{report['total_events_analyzed']:,}</div>
                    <div class="metric-label">Events Analyzed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{report.get('unique_ips_found', 0)}</div>
                    <div class="metric-label">Unique IPs</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{report['rules_loaded']}</div>
                    <div class="metric-label">Rules Loaded</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value critical">{len(self.compromised_users)}</div>
                    <div class="metric-label">Compromised Users</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value critical">{critical_count}</div>
                    <div class="metric-label">Critical Findings</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value warning">{high_count}</div>
                    <div class="metric-label">High Findings</div>
                </div>
            </div>
        </section>
"""
        
        # Get rule-based credential theft findings
        rule_credential_theft = []
        for rule_id, data in self.rule_detections.items():
            if data['count'] > 0 and 'credential-theft' in rule_id:
                rule_credential_theft.extend(data['matches'])

        # Get failed login -> success findings (suspicious successful logins)
        rule_failed_then_success = []
        for rule_id, data in self.rule_detections.items():
            if data['count'] > 0 and ('failed-then-success' in rule_id or 'failed-login' in rule_id):
                rule_failed_then_success.extend(data['matches'])
        
        # Get rule-based token compromise findings
        rule_token_compromise = []
        for rule_id, data in self.rule_detections.items():
            if data['count'] > 0 and 'token-compromise' in rule_id:
                rule_token_compromise.extend(data['matches'])
        
        # Calculate totals
        total_credential_theft = len(rule_credential_theft) + len(rule_failed_then_success)
        total_token_compromise = len(rule_token_compromise)
        
        html_content += f"""
        <section class="section">
            <div class="section-header">
                <div class="section-icon red">&#128680;</div>
                <h2 class="section-title">Credential Theft Detections</h2>
                <span class="risk-badge critical">{total_credential_theft} Found</span>
            </div>
"""
        
        # Show rule-based credential theft findings first (they have better correlation data)
        if rule_credential_theft:
            for finding in rule_credential_theft:
                ip_list = finding.get('ips', [])
                ip_tags = ''.join([f'<span class="ip-tag">{ip}</span>' for ip in ip_list[:10]])
                if len(ip_list) > 10:
                    ip_tags += f'<span class="ip-tag">+{len(ip_list) - 10} more</span>'

                country_codes = set(finding.get('countries', []))
                credential_ip_rows = ''
                for ip in ip_list[:15]:
                    country_code = self._resolve_ip_country(ip) or 'N/A'
                    if country_code != 'N/A':
                        country_codes.add(country_code)

                    abuse_info = self.ip_reputation.get(ip)
                    if abuse_info is None and self.abuseipdb_key:
                        abuse_info = check_abuseipdb(ip, self.abuseipdb_key)
                        if abuse_info:
                            self.ip_reputation[ip] = abuse_info

                    if abuse_info:
                        abuse_score = abuse_info.get('abuse_confidence', 0)
                        ip_score = f"{abuse_score}%"
                    else:
                        ip_score = 'N/A'

                    credential_ip_rows += f"""
                        <tr>
                            <td><code>{ip}</code></td>
                            <td>{country_code}</td>
                            <td>{ip_score}</td>
                        </tr>"""

                if not credential_ip_rows:
                    credential_ip_rows = """
                        <tr>
                            <td colspan=\"3\">No IP details available</td>
                        </tr>"""

                countries_display = ', '.join(sorted(country_codes)) if country_codes else 'N/A'
                
                unique_sessions = finding.get('unique_sessions', 'N/A')
                unique_ips = finding.get('unique_ips', len(ip_list))
                event_count = finding.get('event_count', 'N/A')
                timestamp = finding.get('timestamp', '')[:19].replace('T', ' ')
                
                html_content += f"""
            <div class="finding-card critical">
                <div class="finding-header">
                    <span class="finding-title">{finding.get('user', 'Unknown')}</span>
                    <span class="risk-badge critical">Critical - Rule Detection</span>
                </div>
                <div class="finding-body">
                    <table class="data-table">
                        <tr><td>Detection Type</td><td><strong>Correlation Analysis</strong></td></tr>
                        <tr><td>Unique Sessions</td><td><strong>{unique_sessions}</strong></td></tr>
                        <tr><td>Unique IPs</td><td><strong>{unique_ips}</strong></td></tr>
                        <tr><td>Countries</td><td><strong>{countries_display}</strong></td></tr>
                        <tr><td>Total Events</td><td>{event_count}</td></tr>
                        <tr><td>First Activity</td><td>{timestamp}</td></tr>
                        <tr><td>IP Addresses</td><td><div class="ip-list">{ip_tags}</div></td></tr>
                    </table>

                    <h4 style="margin: 16px 0 8px 0; color: var(--primary-dark);">IP Country & Reputation</h4>
                    <div style="max-height: 250px; overflow-y: auto;">
                        <table class="data-table" style="font-size: 12px;">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Country</th>
                                    <th>IP Score</th>
                                </tr>
                            </thead>
                            <tbody>
                                {credential_ip_rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
"""

        if rule_failed_then_success:
            for finding in rule_failed_then_success:
                ip_list = finding.get('ips', [])
                ip_tags = ''.join([f'<span class="ip-tag">{ip}</span>' for ip in ip_list[:10]])
                if len(ip_list) > 10:
                    ip_tags += f'<span class="ip-tag">+{len(ip_list) - 10} more</span>'

                failed_count = finding.get('failed_count', 'N/A')
                first_failure = finding.get('first_failure', '')[:19].replace('T', ' ')
                last_failure = finding.get('last_failure', '')[:19].replace('T', ' ')
                success_time_raw = finding.get('success_time', finding.get('timestamp', ''))
                success_timestamp = success_time_raw[:19].replace('T', ' ')
                success_date = finding.get('success_date', success_time_raw[:10])
                success_sessions = finding.get('success_sessions', [])
                success_sessions_html = '<br>'.join([f'<code>{sid}</code>' for sid in success_sessions]) if success_sessions else 'N/A'

                html_content += f"""
            <div class="finding-card warning">
                <div class="finding-header">
                    <span class="finding-title">{finding.get('user', 'Unknown')}</span>
                    <span class="risk-badge high">High - Suspicious Successful Login</span>
                </div>
                <div class="finding-body">
                    <table class="data-table">
                        <tr><td>Detection Type</td><td><strong>Failed Logins Followed by Success</strong></td></tr>
                        <tr><td>Failed Attempts</td><td><strong>{failed_count}</strong></td></tr>
                        <tr><td>First Failure</td><td>{first_failure or 'N/A'}</td></tr>
                        <tr><td>Last Failure</td><td>{last_failure or 'N/A'}</td></tr>
                        <tr><td>Successful Login Date</td><td><strong>{success_date or 'N/A'}</strong></td></tr>
                        <tr><td>Successful Login Timestamp</td><td>{success_timestamp or 'N/A'}</td></tr>
                        <tr><td>Successful Login Session IDs</td><td>{success_sessions_html}</td></tr>
                        <tr><td>Successful Login IPs</td><td><div class="ip-list">{ip_tags}</div></td></tr>
                    </table>
                </div>
            </div>
"""
        
        if not rule_credential_theft and not rule_failed_then_success:
            html_content += """
            <div class="empty-state">
                <div class="empty-icon">&#9989;</div>
                <div class="empty-text">No credential theft detected</div>
            </div>
"""

        html_content += f"""
        </section>

        <section class="section">
            <div class="section-header">
                <div class="section-icon orange">&#9888;</div>
                <h2 class="section-title">Token Compromise Detections</h2>
                <span class="risk-badge high">{total_token_compromise} Found</span>
            </div>
"""

        # Show rule-based token compromise findings with enhanced IP reputation data
        if rule_token_compromise:
            for finding in rule_token_compromise:
                ip_list = finding.get('ips', [])
                ip_details = finding.get('ip_details', [])
                countries = finding.get('countries', [])
                suspicious_ips = finding.get('suspicious_ips', [])
                detection_reasons = finding.get('detection_reasons', [])
                
                session_id = finding.get('session_id', 'Unknown')
                unique_ips = finding.get('unique_ips', len(ip_list))
                unique_subnets = finding.get('unique_subnets_24', 'N/A')
                event_count = finding.get('event_count', 'N/A')
                avg_abuse = finding.get('avg_abuse_score', 0)
                
                # Build IP table with reputation data (skip excluded IPs)
                ip_table_rows = ''
                for ip_info in ip_details[:15]:
                    # Skip excluded country IPs from the table
                    if ip_info.get('excluded'):
                        continue
                    abuse_class = 'status-yes' if ip_info.get('abuse_score', 0) > 25 else ''
                    tor_badge = '<span class="risk-badge critical" style="font-size:10px;">TOR</span>' if ip_info.get('is_tor') else ''
                    proxy_badge = '<span class="risk-badge high" style="font-size:10px;">Proxy</span>' if ip_info.get('is_proxy') else ''
                    country_display = ip_info.get('country', 'N/A') or 'N/A'
                    city_display = ip_info.get('city', '') or ''
                    abuse_score = ip_info.get('abuse_score', 0)
                    abuse_display = f"{abuse_score}%" if abuse_score is not None else 'N/A'
                    ip_table_rows += f"""
                        <tr>
                            <td><code>{ip_info.get('ip', '')}</code></td>
                            <td>{country_display}</td>
                            <td>{city_display}</td>
                            <td class="{abuse_class}">{abuse_display}</td>
                            <td>{tor_badge} {proxy_badge}</td>
                        </tr>"""
                
                # Determine risk level
                risk_level = 'critical' if (len(countries) > 2 or avg_abuse > 30 or len(suspicious_ips) > 3) else 'high'
                risk_text = 'CRITICAL - Multi-Country' if finding.get('multi_country') else 'HIGH - Prefix Diversity'
                
                # Build countries display - handle empty list (excluded countries not shown)
                countries_display = ', '.join(countries) if countries else 'Single Country'
                
                html_content += f"""
            <div class="finding-card {'critical' if risk_level == 'critical' else 'warning'}">
                <div class="finding-header">
                    <span class="finding-title">Session: <code>{session_id}</code></span>
                    <span class="risk-badge {risk_level}">{risk_text}</span>
                </div>
                <div class="finding-body">
                    <table class="data-table">
                        <tr><td>Detection Type</td><td><strong>Hybrid Token Theft Detection</strong></td></tr>
                        <tr><td>Users</td><td><strong>{finding.get('user', 'Unknown')}</strong></td></tr>
                        <tr><td>Unique IPs</td><td><strong>{unique_ips}</strong></td></tr>
                        <tr><td>Unique Network Prefixes</td><td><strong>{unique_subnets}</strong></td></tr>
                        <tr><td>Countries</td><td><strong>{countries_display}</strong></td></tr>
                        <tr><td>Suspicious IPs (AbuseIPDB)</td><td class="{'status-yes' if suspicious_ips else ''}">{len(suspicious_ips)}</td></tr>
                        <tr><td>Avg. Abuse Score</td><td>{avg_abuse:.1f}%</td></tr>
                        <tr><td>Events</td><td>{event_count}</td></tr>
                        <tr><td>Detection Reasons</td><td>{'<br>'.join(detection_reasons)}</td></tr>
                    </table>
                    
                    <h4 style="margin: 16px 0 8px 0; color: var(--primary-dark);">IP Reputation Details</h4>
                    <div style="max-height: 300px; overflow-y: auto;">
                        <table class="data-table" style="font-size: 12px;">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Country</th>
                                    <th>City</th>
                                    <th>Abuse Score</th>
                                    <th>Flags</th>
                                </tr>
                            </thead>
                            <tbody>
                                {ip_table_rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
"""
        
        if not rule_token_compromise:
            html_content += """
            <div class="empty-state">
                <div class="empty-icon">&#9989;</div>
                <div class="empty-text">No token compromise detected</div>
            </div>
"""
        
        html_content += """
        </section>
"""

        # Add YAML Rule Findings section
        if rule_findings:
            html_content += f"""
        <section class="section">
            <div class="section-header">
                <div class="section-icon green">&#128269;</div>
                <h2 class="section-title">YAML Rule Detections</h2>
                <span class="risk-badge medium">{len(rule_findings)} Rules Triggered</span>
            </div>
            <div class="summary-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 24px;">
                <div class="metric-card">
                    <div class="metric-value critical">{critical_count}</div>
                    <div class="metric-label">Critical</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value warning">{high_count}</div>
                    <div class="metric-label">High</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{medium_count}</div>
                    <div class="metric-label">Medium</div>
                </div>
            </div>
"""
            for rule_id, data in rule_findings.items():
                severity = data['severity'].lower()
                badge_class = 'critical' if severity == 'critical' else ('high' if severity == 'high' else 'medium')
                html_content += f"""
            <div class="rule-item">
                <div class="rule-info">
                    <div class="rule-title">{data['title']}</div>
                    <div class="rule-count">{data['count']} matches found</div>
                </div>
                <span class="risk-badge {badge_class}">{data['severity']}</span>
            </div>
"""
            html_content += """
        </section>
"""

        # Close the detections tab div
        html_content += """
        </div>
"""

        # Add Timeline Tab
        html_content += self._generate_timeline_tab_html()

        html_content += """
        <footer class="report-footer">
            <span class="footer-brand">Ryoshi</span> M365 eDiscovery Detection Engine | Enterprise Security Report
            <div style="margin-top: 8px; color: #999;">Confidential - For authorized recipients only</div>
        </footer>
    </main>
    
    <script>
        function showTab(tabId) {{
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(function(content) {{
                content.classList.remove('active');
            }});
            // Deactivate all tab buttons
            document.querySelectorAll('.tab-btn').forEach(function(btn) {{
                btn.classList.remove('active');
            }});
            // Show selected tab content
            document.getElementById(tabId).classList.add('active');
            // Activate clicked button
            event.target.classList.add('active');
        }}
        
        function filterTimeline() {{
            var userFilter = document.getElementById('userFilter').value.toLowerCase();
            var opFilter = document.getElementById('opFilter').value.toLowerCase();
            var rows = document.querySelectorAll('#timelineTable tbody tr');
            
            rows.forEach(function(row) {{
                var user = row.cells[1].textContent.toLowerCase();
                var op = row.cells[2].textContent.toLowerCase();
                var showRow = true;
                
                if (userFilter && !user.includes(userFilter)) showRow = false;
                if (opFilter && !op.includes(opFilter)) showRow = false;
                
                row.style.display = showRow ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>
"""

        html_path = os.path.join(output_dir, 'ryoshi_detection_report.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"[+] HTML report saved: {html_path}")

    def _generate_timeline_tab_html(self):
        """Generate HTML content for the timeline tab"""
        # Combine all timelines
        all_events = []
        for user, timeline in self.timelines.items():
            for event in timeline:
                all_events.append({
                    'user': user,
                    **event
                })
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x.get('timestamp', ''))
        
        # Get unique users and operations for filters
        unique_users = sorted(set(self.timelines.keys()))
        unique_ops = sorted(set(e.get('operation', '') for e in all_events))
        
        # Build user filter options
        user_options = '<option value="">All Users</option>'
        for user in unique_users:
            user_options += f'<option value="{user}">{user}</option>'
        
        # Build operation filter options
        op_options = '<option value="">All Operations</option>'
        for op in unique_ops[:50]:  # Limit to 50 most common
            op_options += f'<option value="{op}">{op}</option>'
        
        timeline_html = f"""
        <div id="timeline" class="tab-content">
            <section class="section">
                <div class="section-header">
                    <div class="section-icon blue">&#128197;</div>
                    <h2 class="section-title">Activity Timeline</h2>
                    <span class="risk-badge medium">{len(all_events)} Events</span>
                </div>
"""
        
        if all_events:
            timeline_html += f"""
                <div class="timeline-filter">
                    <label>Filter by User:</label>
                    <select id="userFilter" onchange="filterTimeline()">
                        {user_options}
                    </select>
                    <label>Filter by Operation:</label>
                    <input type="text" id="opFilter" placeholder="Type to filter operations..." oninput="filterTimeline()">
                </div>
                
                <div class="timeline-scroll">
                    <table class="timeline-table" id="timelineTable">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>User</th>
                                <th>Operation</th>
                                <th>Workload</th>
                                <th>Result</th>
                                <th>IP Addresses</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            # Add rows (limit to first 1000 for performance)
            for event in all_events[:1000]:
                ips = ', '.join(event.get('ips', [])) or '-'
                timestamp = event.get('timestamp', '')[:19].replace('T', ' ')
                result = event.get('result', '') or '-'
                workload = event.get('workload', '') or '-'
                
                timeline_html += f"""
                            <tr>
                                <td>{timestamp}</td>
                                <td class="timeline-user">{event.get('user', '')}</td>
                                <td><span class="timeline-op">{event.get('operation', '')}</span></td>
                                <td>{workload}</td>
                                <td>{result}</td>
                                <td>{ips}</td>
                            </tr>
"""
            
            timeline_html += """
                        </tbody>
                    </table>
                </div>
"""
            if len(all_events) > 1000:
                timeline_html += f"""
                <div style="margin-top: 16px; padding: 12px; background: #fff3cd; border-radius: 8px; color: #856404;">
                    <strong>Note:</strong> Showing first 1,000 of {len(all_events):,} events. Download CSV for complete timeline.
                </div>
"""
        else:
            timeline_html += """
                <div class="empty-state">
                    <div class="empty-icon">&#128197;</div>
                    <div class="empty-text">No timeline data available. Timelines are generated for compromised users.</div>
                </div>
"""
        
        timeline_html += """
            </section>
        </div>
"""
        return timeline_html

    def _generate_markdown_report(self, output_dir, report, rule_findings):
        """Generate Markdown detection report"""
        
        critical_count = sum(1 for d in self.rule_detections.values() if d['severity'] == 'CRITICAL' and d['count'] > 0)
        high_count = sum(1 for d in self.rule_detections.values() if d['severity'] == 'HIGH' and d['count'] > 0)
        medium_count = sum(1 for d in self.rule_detections.values() if d['severity'] == 'MEDIUM' and d['count'] > 0)
        
        md_content = f"""# Ryoshi M365 eDiscovery Detection Report

**Generated**: {report['generated_at']}

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Events Analyzed | {report['total_events_analyzed']:,} |
| Unique IPs Found | {report.get('unique_ips_found', 0)} |
| Rules Loaded | {report['rules_loaded']} |
| Compromised Users | {len(self.compromised_users)} |
| Critical Findings | {report['detections']['critical']} |
| High Findings | {report['detections']['high']} |

## Compromised Users

"""
        if self.compromised_users:
            for user in sorted(self.compromised_users):
                md_content += f"- **{user}**\n"
        else:
            md_content += "No compromised users detected.\n"

        md_content += "\n## Rule Detections\n\n"

        if rule_findings:
            md_content += f"""
| Severity | Count |
|----------|-------|
| Critical | {critical_count} |
| High | {high_count} |
| Medium | {medium_count} |

### Triggered Rules

"""
            for rule_id, data in rule_findings.items():
                md_content += f"- **{data['title']}** ({data['severity']}) - {data['count']} matches\n"
        else:
            md_content += "No rule detections.\n"

        md_content += "\n---\n*Ryoshi M365 eDiscovery Detection Engine (Rule-Based)*\n"

        md_path = os.path.join(output_dir, 'ryoshi_detection_report.md')
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"[+] Markdown report saved: {md_path}")

    def print_summary(self):
        """Print summary of findings"""
        print("\n" + "="*60)
        print("RYOSHI DETECTION SUMMARY")
        print("="*60)
        print(f"Total events analyzed: {len(self.logs)}")
        print(f"Rules loaded: {len(self.rules)}")
        print(f"Compromised users: {len(self.compromised_users)}")
        
        # Summarize rule-based detections by severity
        critical = sum(1 for d in self.rule_detections.values() if d['severity'] == 'CRITICAL' and d['count'] > 0)
        high = sum(1 for d in self.rule_detections.values() if d['severity'] == 'HIGH' and d['count'] > 0)
        medium = sum(1 for d in self.rule_detections.values() if d['severity'] == 'MEDIUM' and d['count'] > 0)
        
        print(f"\nRule Detections by Severity:")
        print(f"  CRITICAL: {critical}")
        print(f"  HIGH: {high}")
        print(f"  MEDIUM: {medium}")
        print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Ryoshi M365 eDiscovery Detection Engine (Rule-Based)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f /path/to/audit_log.csv
  %(prog)s -F /path/to/logs_folder/
  %(prog)s --rules-dir ./rules -f audit.csv
  %(prog)s -f file1.csv -f file2.csv -o /output/dir
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        action='append',
        dest='files',
        metavar='FILE',
        help='Path to a CSV file to analyze (can be used multiple times)'
    )
    
    parser.add_argument(
        '-F', '--folder',
        action='append',
        dest='folders',
        metavar='FOLDER',
        help='Path to a folder containing CSV files (can be used multiple times)'
    )
    
    parser.add_argument(
        '--rules-dir',
        default=None,
        help='Path to rules directory (auto-detected by default)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='/tmp',
        help='Output directory for reports (default: /tmp)'
    )
    
    parser.add_argument(
        '--abuseipdb-key',
        default=None,
        help='AbuseIPDB API key for IP reputation checks (can also use ABUSEIPDB_API_KEY env var)'
    )
    
    parser.add_argument(
        '--exclude-country',
        action='append',
        dest='exclude_countries',
        metavar='COUNTRY',
        help='Exclude IPs from specified countries in token theft detection. Supports comma-separated values. Examples: --exclude-country=ES,FR or --exclude-country="Spain,France"'
    )
    
    args = parser.parse_args()
    
    if not args.files and not args.folders:
        parser.error("You must specify at least one file (-f) or folder (-F)")
    
    print("[+] Ryoshi M365 eDiscovery Detection Engine (Rule-Based)")
    print("="*60)
    
    # Check for AbuseIPDB API key
    abuseipdb_key = args.abuseipdb_key or os.environ.get('ABUSEIPDB_API_KEY', '')
    if abuseipdb_key:
        print("[+] AbuseIPDB integration enabled")
    else:
        print("[*] AbuseIPDB integration disabled (no API key provided)")
        print("    Use --abuseipdb-key or set ABUSEIPDB_API_KEY environment variable")
    
    # Initialize engine with rules directory, API key, and excluded countries
    engine = RyoshiDetectionEngine(rules_dir=args.rules_dir, abuseipdb_key=abuseipdb_key, exclude_countries=args.exclude_countries)
    
    # Display excluded countries after normalization
    if engine.exclude_countries:
        print(f"[+] Excluding countries from token theft detection: {', '.join(sorted(c.upper() for c in engine.exclude_countries))}")
    
    if args.files:
        for filepath in args.files:
            if os.path.isfile(filepath):
                engine.load_csv(filepath)
            else:
                print(f"[!] File not found: {filepath}")
    
    if args.folders:
        for folder in args.folders:
            if os.path.isdir(folder):
                engine.load_folder(folder)
            else:
                print(f"[!] Folder not found: {folder}")
    
    if not engine.logs:
        print("[!] No events loaded. Exiting.")
        return
    
    print(f"\n[+] Total events loaded: {len(engine.logs)}")
    
    # Run all YAML-based rules
    engine.run_all_rules()
    
    # Build timelines for compromised users detected by rules
    print(f"\n[*] Building timelines for {len(engine.compromised_users)} compromised user(s)...")
    for user in engine.compromised_users:
        engine.build_timeline(user)
    
    engine.generate_report(args.output)
    engine.print_summary()


if __name__ == '__main__':
    main()