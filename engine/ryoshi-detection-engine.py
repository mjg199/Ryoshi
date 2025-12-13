#!/usr/bin/env python3
"""
Ryoshi M365 eDiscovery Detection Engine
Detects credential theft and token compromise in M365 audit logs

Usage:
  python3 ryoshi-detection-engine.py -f /path/to/file.csv
  python3 ryoshi-detection-engine.py -F /path/to/folder/
  python3 ryoshi-detection-engine.py -f file1.csv -f file2.csv -F /folder/
"""

import csv
import json
import argparse
import os
import glob
from datetime import datetime, timedelta
from collections import defaultdict
import re


class RyoshiDetectionEngine:
    def __init__(self):
        self.logs = []
        self.compromises = {
            'credential_theft': [],
            'token_compromise': []
        }
        self.timelines = {}

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
                            'user_id': row.get('UserIds', ''),
                            'operation': row.get('Operations', ''),
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
        """Generate detection and timeline reports"""
        print(f"\n[*] Generating reports to {output_dir}...")
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_events_analyzed': len(self.logs),
            'detections': {
                'credential_theft': len(self.compromises['credential_theft']),
                'token_compromise': len(self.compromises['token_compromise'])
            },
            'findings': self.compromises
        }
        
        report_path = os.path.join(output_dir, 'ryoshi_detection_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Detection report saved: {report_path}")
        
        for user, timeline in self.timelines.items():
            safe_user = user.replace('@', '_').replace('.', '_')
            timeline_path = os.path.join(output_dir, f'ryoshi_timeline_{safe_user}.json')
            with open(timeline_path, 'w') as f:
                json.dump({
                    'user': user,
                    'event_count': len(timeline),
                    'timeline': timeline
                }, f, indent=2, default=str)
            print(f"[+] Timeline saved: {timeline_path}")

    def print_summary(self):
        """Print summary of findings"""
        print("\n" + "="*60)
        print("RYOSHI DETECTION SUMMARY")
        print("="*60)
        print(f"Total events analyzed: {len(self.logs)}")
        print(f"Credential theft incidents: {len(self.compromises['credential_theft'])}")
        print(f"Token compromise incidents: {len(self.compromises['token_compromise'])}")
        print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Ryoshi M365 eDiscovery Detection Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f /path/to/audit_log.csv
  %(prog)s -F /path/to/logs_folder/
  %(prog)s -f file1.csv -f file2.csv
  %(prog)s -F /folder1 -F /folder2 -f extra_file.csv
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
        '-o', '--output',
        default='/tmp',
        help='Output directory for reports (default: /tmp)'
    )
    
    args = parser.parse_args()
    
    if not args.files and not args.folders:
        parser.error("You must specify at least one file (-f) or folder (-F)")
    
    print("[+] Ryoshi M365 eDiscovery Detection Engine")
    print("="*50)
    
    engine = RyoshiDetectionEngine()
    
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
    
    engine.detect_credential_theft()
    engine.detect_token_compromise()
    engine.detect_bulk_email_access(threshold=500)
    engine.detect_sendas_operations()
    engine.detect_email_deletions()
    engine.detect_inbox_rules()
    engine.detect_failed_logins()
    engine.detect_file_downloads(threshold=50)
    
    compromised_users = set()
    for finding in engine.compromises['credential_theft']:
        compromised_users.add(finding['user'])
    
    for user in compromised_users:
        engine.build_timeline(user)
    
    engine.generate_report(args.output)
    engine.print_summary()


if __name__ == '__main__':
    main()
