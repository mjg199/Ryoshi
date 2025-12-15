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
from datetime import datetime, timedelta
from collections import defaultdict
import re

try:
    import yaml
except ImportError:
    print("[!] PyYAML not installed. Run: pip install pyyaml")
    yaml = None


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
    def __init__(self, rules_dir=None):
        self.logs = []
        self.rules = {}
        self.compromises = {
            'credential_theft': [],
            'token_compromise': []
        }
        self.rule_detections = {}  # Detections from dynamic rules
        self.timelines = {}
        
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
        """Extract IP addresses from various fields"""
        ips = set()
        audit = log_entry.get('audit_data', {})
        
        for field in ['ClientIP', 'ClientIPAddress', 'ActorIpAddress']:
            if field in audit and audit[field]:
                ip = audit[field]
                if ':' in ip and not ip.startswith('['):
                    ip = ip.split(':')[0]
                if ip.startswith('['):
                    ip = ip.strip('[]').split(']')[0]
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    ips.add(ip)
        
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

    def detect_credential_theft(self, threshold_hours=24):
        """Detect credential theft: multiple sessions from diverse IPs"""
        print(f"\n[*] Detecting credential theft (timeframe: {threshold_hours}h)...")
        
        user_logins = defaultdict(list)
        
        for log_entry in self.logs:
            if log_entry['operation'] == 'UserLoggedIn':
                audit = log_entry.get('audit_data', {})
                if audit.get('ResultStatus') == 'Success':
                    user = log_entry['user_id']
                    ips = self.extract_ip_addresses(log_entry)
                    sessions = self.extract_session_ids(log_entry)
                    
                    try:
                        ts = log_entry['timestamp'].replace('Z', '+00:00')
                        if '.' not in ts:
                            ts = ts.replace('+00:00', '.000000+00:00')
                        timestamp = datetime.fromisoformat(ts.replace('+00:00', ''))
                    except Exception:
                        continue
                    
                    user_logins[user].append({
                        'timestamp': timestamp,
                        'ips': ips,
                        'sessions': sessions,
                        'kmsi': self.check_kmsi_enabled(log_entry),
                        'raw': log_entry
                    })
        
        for user, logins in user_logins.items():
            if len(logins) < 2:
                continue
            
            logins.sort(key=lambda x: x['timestamp'])
            
            unique_sessions = set()
            unique_ips = set()
            
            for login in logins:
                for sid_type, sid in login['sessions'].items():
                    if sid:
                        unique_sessions.add(sid)
                unique_ips.update(login['ips'])
            
            if len(unique_sessions) >= 2 and len(unique_ips) >= 2:
                time_range = logins[-1]['timestamp'] - logins[0]['timestamp']
                
                self.compromises['credential_theft'].append({
                    'user': user,
                    'unique_sessions': len(unique_sessions),
                    'unique_ips': len(unique_ips),
                    'session_ids': list(unique_sessions),
                    'ip_addresses': list(unique_ips),
                    'first_seen': logins[0]['timestamp'].isoformat(),
                    'last_seen': logins[-1]['timestamp'].isoformat(),
                    'duration_hours': time_range.total_seconds() / 3600,
                    'login_count': len(logins)
                })
                print(f"[!] CREDENTIAL THEFT DETECTED: {user}")
                print(f"    Sessions: {len(unique_sessions)}, IPs: {len(unique_ips)}")

    def detect_token_compromise(self, threshold_hours=168):
        """Detect token compromise: single session from multiple IPs"""
        print(f"\n[*] Detecting token compromise (timeframe: {threshold_hours}h)...")
        
        session_usage = defaultdict(lambda: {
            'ips': set(),
            'users': set(),
            'operations': [],
            'kmsi': False,
            'first_seen': None,
            'last_seen': None
        })
        
        for log_entry in self.logs:
            sessions = self.extract_session_ids(log_entry)
            ips = self.extract_ip_addresses(log_entry)
            user = log_entry['user_id']
            
            try:
                ts = log_entry['timestamp'].replace('Z', '+00:00')
                if '.' not in ts:
                    ts = ts.replace('+00:00', '.000000+00:00')
                timestamp = datetime.fromisoformat(ts.replace('+00:00', ''))
            except Exception:
                continue
            
            for sid_type, sid in sessions.items():
                if sid:
                    session_usage[sid]['ips'].update(ips)
                    session_usage[sid]['users'].add(user)
                    session_usage[sid]['operations'].append({
                        'operation': log_entry['operation'],
                        'timestamp': timestamp
                    })
                    
                    if self.check_kmsi_enabled(log_entry):
                        session_usage[sid]['kmsi'] = True
                    
                    if session_usage[sid]['first_seen'] is None:
                        session_usage[sid]['first_seen'] = timestamp
                    session_usage[sid]['last_seen'] = timestamp
        
        for session_id, data in session_usage.items():
            if len(data['ips']) >= 2:
                duration = (data['last_seen'] - data['first_seen']).total_seconds() / 3600
                
                self.compromises['token_compromise'].append({
                    'session_id': session_id,
                    'users': list(data['users']),
                    'unique_ips': len(data['ips']),
                    'ip_addresses': list(data['ips']),
                    'operation_count': len(data['operations']),
                    'kmsi_enabled': data['kmsi'],
                    'first_seen': data['first_seen'].isoformat(),
                    'last_seen': data['last_seen'].isoformat(),
                    'duration_hours': duration
                })
                
                user_str = ', '.join(data['users'])
                print(f"[!] TOKEN COMPROMISE DETECTED: {session_id[:36]}...")
                print(f"    User: {user_str}, IPs: {len(data['ips'])}, KMSI: {data['kmsi']}")

    def detect_bulk_email_access(self, threshold=500, timeframe_hours=1):
        """Detect bulk email access - potential data exfiltration"""
        print(f"\n[*] Detecting bulk email access ({threshold}+ in {timeframe_hours}h)...")
        
        session_email_access = defaultdict(list)
        
        for log_entry in self.logs:
            if log_entry['operation'] == 'MailItemsAccessed':
                sessions = self.extract_session_ids(log_entry)
                
                try:
                    ts = log_entry['timestamp'].replace('Z', '+00:00')
                    if '.' not in ts:
                        ts = ts.replace('+00:00', '.000000+00:00')
                    timestamp = datetime.fromisoformat(ts.replace('+00:00', ''))
                except Exception:
                    continue
                
                for sid_type, sid in sessions.items():
                    if sid:
                        session_email_access[sid].append(timestamp)
        
        for session_id, timestamps in session_email_access.items():
            if len(timestamps) >= threshold:
                print(f"[!] BULK EMAIL ACCESS DETECTED: {session_id[:36]}...")
                print(f"    Emails Accessed: {len(timestamps)}")

    def detect_sendas_operations(self):
        """Detect SendAs operations - potential BEC attacks"""
        print(f"\n[*] Detecting SendAs/Impersonation operations...")
        
        sendas_count = 0
        for log_entry in self.logs:
            if log_entry['operation'] in ['SendAs', 'SendOnBehalf']:
                sendas_count += 1
                if sendas_count <= 5:  # Print first 5
                    print(f"[!] SENDAS DETECTED: {log_entry['user_id']} - {log_entry['timestamp']}")
        
        if sendas_count > 0:
            print(f"[+] Total SendAs operations found: {sendas_count}")

    def detect_email_deletions(self):
        """Detect email deletion patterns"""
        print(f"\n[*] Detecting email deletions (SoftDelete, HardDelete, MoveToDeletedItems)...")
        
        deletion_ops = ['SoftDelete', 'HardDelete', 'MoveToDeletedItems']
        deletion_count = 0
        
        for log_entry in self.logs:
            if log_entry['operation'] in deletion_ops:
                deletion_count += 1
        
        print(f"[+] Total deletion operations found: {deletion_count}")

    def detect_inbox_rules(self):
        """Detect inbox rule creation"""
        print(f"\n[*] Detecting inbox rule operations...")
        
        rule_ops = ['New-InboxRule', 'Set-InboxRule', 'Enable-InboxRule']
        rule_count = 0
        
        for log_entry in self.logs:
            if log_entry['operation'] in rule_ops:
                rule_count += 1
                if rule_count <= 3:  # Print first 3
                    print(f"[!] INBOX RULE: {log_entry['user_id']} - {log_entry['operation']}")
        
        if rule_count > 0:
            print(f"[+] Total inbox rule operations: {rule_count}")

    def detect_failed_logins(self):
        """Detect failed login patterns"""
        print(f"\n[*] Detecting failed login attempts...")
        
        failed_count = 0
        for log_entry in self.logs:
            if log_entry['operation'] == 'UserLoginFailed':
                failed_count += 1
        
        if failed_count > 0:
            print(f"[+] Total failed login attempts: {failed_count}")

    def detect_file_downloads(self, threshold=50, timeframe_hours=1):
        """Detect mass file downloads"""
        print(f"\n[*] Detecting mass file downloads ({threshold}+ in {timeframe_hours}h)...")
        
        download_ops = ['FileDownloaded', 'FileSyncDownloadedFull']
        session_downloads = defaultdict(int)
        
        for log_entry in self.logs:
            if log_entry['operation'] in download_ops:
                sessions = self.extract_session_ids(log_entry)
                for sid_type, sid in sessions.items():
                    if sid:
                        session_downloads[sid] += 1
        
        high_downloads = [s for s, c in session_downloads.items() if c >= threshold]
        if high_downloads:
            print(f"[!] MASS FILE DOWNLOAD DETECTED: {len(high_downloads)} sessions")
            for sid in high_downloads[:3]:
                print(f"    Session {sid[:36]}... : {session_downloads[sid]} downloads")

    def run_all_rules(self):
        """Execute all loaded YAML rules against the logs"""
        if not self.rules:
            print("[*] No YAML rules loaded. Skipping dynamic rule execution.")
            return
        
        print(f"\n[*] Executing {len(self.rules)} YAML rules...")
        print("-" * 50)
        
        for rule_id, rule in self.rules.items():
            self._execute_rule(rule_id, rule)
    
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
        user_data = defaultdict(lambda: {'sessions': set(), 'ips': set(), 'events': []})
        
        for log_entry in self.logs:
            if self._matches_selection(log_entry, selection, ops_to_match):
                # Check result status if required
                audit = log_entry.get('audit_data', {})
                if required_result and audit.get('ResultStatus') != required_result:
                    continue
                
                user = log_entry['user_id']
                ips = self.extract_ip_addresses(log_entry)
                sessions = self.extract_session_ids(log_entry)
                
                user_data[user]['ips'].update(ips)
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
        
        matches = []
        for user, data in user_data.items():
            if len(data['sessions']) >= min_sessions and len(data['ips']) >= min_ips:
                matches.append({
                    'timestamp': data['events'][0]['timestamp'] if data['events'] else '',
                    'user': user,
                    'operation': 'Correlation Match',
                    'ips': list(data['ips']),
                    'unique_sessions': len(data['sessions']),
                    'unique_ips': len(data['ips']),
                    'event_count': len(data['events'])
                })
        
        self.rule_detections[rule_id]['matches'] = matches[:10]
        self.rule_detections[rule_id]['count'] = len(matches)
        
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Users Affected: {len(matches)}")
            for m in matches[:2]:
                print(f"    - {m['user']}: {m['unique_sessions']} sessions, {m['unique_ips']} IPs")
    
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
                    'raw_ts': log_entry['timestamp']
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
                    matches.append({
                        'timestamp': success['raw_ts'],
                        'user': user,
                        'operation': 'Failed->Success Sequence',
                        'ips': success['ips'],
                        'failed_count': len(failures_before),
                        'first_failure': failures_before[0]['raw_ts'] if failures_before else '',
                        'success_time': success['raw_ts']
                    })
                    break  # One match per user
        
        self.rule_detections[rule_id]['matches'] = matches[:10]
        self.rule_detections[rule_id]['count'] = len(matches)
        
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Users Affected: {len(matches)}")
            for m in matches[:2]:
                print(f"    - {m['user']}: {m['failed_count']} failures before success")
    
    def _execute_session_rule(self, rule_id, rule):
        """Execute session correlation rule - detect same session from multiple IPs"""
        rule_title = rule.get('title', rule_id)
        severity = rule.get('severity', 'MEDIUM').upper()
        detection = rule.get('detection', {})
        correlation = detection.get('correlation', {})
        
        requirements = correlation.get('requirements', {})
        min_ips = self._parse_requirement(requirements.get('unique_ips', '>=2'))
        
        # Group by session ID
        session_data = defaultdict(lambda: {'ips': set(), 'users': set(), 'events': []})
        
        for log_entry in self.logs:
            sessions = self.extract_session_ids(log_entry)
            ips = self.extract_ip_addresses(log_entry)
            user = log_entry['user_id']
            
            for sid_type, sid in sessions.items():
                if sid:
                    session_data[sid]['ips'].update(ips)
                    session_data[sid]['users'].add(user)
                    session_data[sid]['events'].append({
                        'timestamp': log_entry['timestamp'],
                        'operation': log_entry['operation'],
                        'ips': list(ips)
                    })
        
        matches = []
        for session_id, data in session_data.items():
            if len(data['ips']) >= min_ips:
                matches.append({
                    'timestamp': data['events'][0]['timestamp'] if data['events'] else '',
                    'user': ', '.join(data['users']),
                    'operation': 'Session Multi-IP',
                    'ips': list(data['ips']),
                    'session_id': session_id,
                    'unique_ips': len(data['ips']),
                    'event_count': len(data['events'])
                })
        
        self.rule_detections[rule_id]['matches'] = matches[:10]
        self.rule_detections[rule_id]['count'] = len(matches)
        
        if matches:
            print(f"\n[!] {rule_title}")
            print(f"    Severity: {severity} | Sessions Affected: {len(matches)}")
            for m in matches[:2]:
                print(f"    - Session {m['session_id'][:20]}...: {m['unique_ips']} IPs")
    
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
        """Build activity timeline for a compromised user"""
        print(f"\n[*] Building activity timeline for {user}...")
        
        events = []
        for log_entry in self.logs:
            if log_entry['user_id'] == user:
                ips = self.extract_ip_addresses(log_entry)
                sessions = self.extract_session_ids(log_entry)
                
                events.append({
                    'timestamp': log_entry['timestamp'],
                    'operation': log_entry['operation'],
                    'ips': list(ips),
                    'sessions': sessions,
                    'workload': log_entry['audit_data'].get('Workload', ''),
                    'result': log_entry['audit_data'].get('ResultStatus', '')
                })
        
        events.sort(key=lambda x: x['timestamp'])
        self.timelines[user] = events
        print(f"[+] Found {len(events)} events for {user}")
        return events

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
        
        # Calculate totals
        total_unique_ips = set()
        for finding in self.compromises['credential_theft']:
            total_unique_ips.update(finding.get('ip_addresses', []))
        for finding in self.compromises['token_compromise']:
            total_unique_ips.update(finding.get('ip_addresses', []))
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_events_analyzed': len(self.logs),
            'unique_ips_found': len(total_unique_ips),
            'rules_loaded': len(self.rules),
            'detections': {
                'credential_theft': len(self.compromises['credential_theft']),
                'token_compromise': len(self.compromises['token_compromise']),
                'rule_based_findings': len(rule_findings)
            },
            'builtin_findings': self.compromises,
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
    
    def _save_timeline_csv(self, output_dir, user, safe_user, timeline):
        """Save individual user timeline as CSV"""
        csv_path = os.path.join(output_dir, f'ryoshi_timeline_{safe_user}.csv')
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(['Timestamp', 'User', 'Operation', 'Workload', 'Result', 'IP Addresses', 'Session IDs'])
            
            # Write data rows
            for event in timeline:
                ips = '; '.join(event.get('ips', []))
                sessions = '; '.join([f"{k}:{v}" for k, v in event.get('sessions', {}).items() if v])
                writer.writerow([
                    event.get('timestamp', ''),
                    user,
                    event.get('operation', ''),
                    event.get('workload', ''),
                    event.get('result', ''),
                    ips,
                    sessions
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
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x.get('timestamp', ''))
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'User', 'Operation', 'Workload', 'Result', 'IP Addresses', 'Session IDs'])
            
            for event in all_events:
                ips = '; '.join(event.get('ips', []))
                sessions = '; '.join([f"{k}:{v}" for k, v in event.get('sessions', {}).items() if v])
                writer.writerow([
                    event.get('timestamp', ''),
                    event.get('user', ''),
                    event.get('operation', ''),
                    event.get('workload', ''),
                    event.get('result', ''),
                    ips,
                    sessions
                ])
        print(f"[+] Combined timeline CSV saved: {csv_path}")

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
                    <div class="metric-value critical">{report['detections']['credential_theft']}</div>
                    <div class="metric-label">Credential Theft</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value warning">{report['detections']['token_compromise']}</div>
                    <div class="metric-label">Token Compromise</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value critical">{critical_count}</div>
                    <div class="metric-label">Critical Rules</div>
                </div>
            </div>
        </section>

        <section class="section">
            <div class="section-header">
                <div class="section-icon red">&#128680;</div>
                <h2 class="section-title">Credential Theft Detections</h2>
                <span class="risk-badge critical">{report['detections']['credential_theft']} Found</span>
            </div>
"""
        
        if self.compromises['credential_theft']:
            for finding in self.compromises['credential_theft']:
                ip_tags = ''.join([f'<span class="ip-tag">{ip}</span>' for ip in finding['ip_addresses'][:10]])
                if len(finding['ip_addresses']) > 10:
                    ip_tags += f'<span class="ip-tag">+{len(finding["ip_addresses"]) - 10} more</span>'
                html_content += f"""
            <div class="finding-card critical">
                <div class="finding-header">
                    <span class="finding-title">{finding['user']}</span>
                    <span class="risk-badge critical">Critical</span>
                </div>
                <div class="finding-body">
                    <table class="data-table">
                        <tr><td>Duration</td><td>{finding['duration_hours']:.2f} hours</td></tr>
                        <tr><td>Unique Sessions</td><td><strong>{finding['unique_sessions']}</strong></td></tr>
                        <tr><td>Unique IPs</td><td><strong>{finding['unique_ips']}</strong></td></tr>
                        <tr><td>Login Count</td><td>{finding['login_count']}</td></tr>
                        <tr><td>First Seen</td><td>{finding['first_seen'][:19].replace('T', ' ')}</td></tr>
                        <tr><td>Last Seen</td><td>{finding['last_seen'][:19].replace('T', ' ')}</td></tr>
                        <tr><td>IP Addresses</td><td><div class="ip-list">{ip_tags}</div></td></tr>
                    </table>
                </div>
            </div>
"""
        else:
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
                <span class="risk-badge high">{report['detections']['token_compromise']} Found</span>
            </div>
"""
        
        if self.compromises['token_compromise']:
            for finding in self.compromises['token_compromise']:
                users = ', '.join(finding['users']) if finding['users'] else 'Unknown'
                kmsi_status = '<span class="status-yes">Yes</span>' if finding['kmsi_enabled'] else '<span class="status-no">No</span>'
                ip_tags = ''.join([f'<span class="ip-tag">{ip}</span>' for ip in finding['ip_addresses'][:8]])
                if len(finding['ip_addresses']) > 8:
                    ip_tags += f'<span class="ip-tag">+{len(finding["ip_addresses"]) - 8} more</span>'
                html_content += f"""
            <div class="finding-card warning">
                <div class="finding-header">
                    <span class="finding-title">Session: {finding['session_id'][:36]}...</span>
                    <span class="risk-badge high">High Risk</span>
                </div>
                <div class="finding-body">
                    <table class="data-table">
                        <tr><td>Users</td><td><strong>{users}</strong></td></tr>
                        <tr><td>Unique IPs</td><td><strong>{finding['unique_ips']}</strong></td></tr>
                        <tr><td>Operations</td><td>{finding['operation_count']:,}</td></tr>
                        <tr><td>KMSI Enabled</td><td>{kmsi_status}</td></tr>
                        <tr><td>Duration</td><td>{finding['duration_hours']:.2f} hours</td></tr>
                        <tr><td>First Seen</td><td>{finding['first_seen'][:19].replace('T', ' ')}</td></tr>
                        <tr><td>Last Seen</td><td>{finding['last_seen'][:19].replace('T', ' ')}</td></tr>
                        <tr><td>IP Addresses</td><td><div class="ip-list">{ip_tags}</div></td></tr>
                    </table>
                </div>
            </div>
"""
        else:
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
| Credential Theft Incidents | {report['detections']['credential_theft']} |
| Token Compromise Incidents | {report['detections']['token_compromise']} |
| Rule-Based Findings | {report['detections']['rule_based_findings']} |

## Credential Theft Detections

"""
        if self.compromises['credential_theft']:
            for finding in self.compromises['credential_theft']:
                md_content += f"""
### {finding['user']}

| Field | Value |
|-------|-------|
| Duration | {finding['duration_hours']:.2f} hours |
| Unique Sessions | {finding['unique_sessions']} |
| Unique IPs | {finding['unique_ips']} |
| Login Count | {finding['login_count']} |
| First Seen | {finding['first_seen']} |
| Last Seen | {finding['last_seen']} |
| IP Addresses | {', '.join(finding['ip_addresses'][:10])} |

"""
        else:
            md_content += "No credential theft detected.\n"

        md_content += "\n## Token Compromise Detections\n\n"
        
        if self.compromises['token_compromise']:
            for finding in self.compromises['token_compromise']:
                users = ', '.join(finding['users']) if finding['users'] else 'Unknown'
                md_content += f"""
### Session: {finding['session_id'][:36]}...

| Field | Value |
|-------|-------|
| Users | {users} |
| Unique IPs | {finding['unique_ips']} |
| Operations | {finding['operation_count']:,} |
| KMSI Enabled | {'Yes' if finding['kmsi_enabled'] else 'No'} |
| Duration | {finding['duration_hours']:.2f} hours |
| First Seen | {finding['first_seen']} |
| Last Seen | {finding['last_seen']} |

"""
        else:
            md_content += "No token compromise detected.\n"

        if rule_findings:
            md_content += f"""
## YAML Rule Detections

| Severity | Count |
|----------|-------|
| Critical | {critical_count} |
| High | {high_count} |
| Medium | {medium_count} |

### Triggered Rules

"""
            for rule_id, data in rule_findings.items():
                md_content += f"- **{data['title']}** ({data['severity']}) - {data['count']} matches\n"

        md_content += "\n---\n*Ryoshi M365 eDiscovery Detection Engine*\n"

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
        print(f"\nBuilt-in Detections:")
        print(f"  Credential theft incidents: {len(self.compromises['credential_theft'])}")
        print(f"  Token compromise incidents: {len(self.compromises['token_compromise'])}")
        
        # Summarize rule-based detections by severity
        critical = sum(1 for d in self.rule_detections.values() if d['severity'] == 'CRITICAL' and d['count'] > 0)
        high = sum(1 for d in self.rule_detections.values() if d['severity'] == 'HIGH' and d['count'] > 0)
        medium = sum(1 for d in self.rule_detections.values() if d['severity'] == 'MEDIUM' and d['count'] > 0)
        
        if self.rules:
            print(f"\nYAML Rule Detections (by severity):")
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
  %(prog)s -f file1.csv -f file2.csv --no-builtin
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
        '--no-builtin',
        action='store_true',
        help='Disable built-in detections (credential theft, token compromise)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='/tmp',
        help='Output directory for reports (default: /tmp)'
    )
    
    args = parser.parse_args()
    
    if not args.files and not args.folders:
        parser.error("You must specify at least one file (-f) or folder (-F)")
    
    print("[+] Ryoshi M365 eDiscovery Detection Engine (Rule-Based)")
    print("="*60)
    
    # Initialize engine with rules directory
    engine = RyoshiDetectionEngine(rules_dir=args.rules_dir)
    
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
    
    # Run built-in detections (unless disabled)
    if not args.no_builtin:
        engine.detect_credential_theft()
        engine.detect_token_compromise()
    
    # Run all YAML-based rules dynamically
    engine.run_all_rules()
    
    # Build timelines for compromised users
    compromised_users = set()
    for finding in engine.compromises['credential_theft']:
        compromised_users.add(finding['user'])
    
    for user in compromised_users:
        engine.build_timeline(user)
    
    engine.generate_report(args.output)
    engine.print_summary()


if __name__ == '__main__':
    main()
