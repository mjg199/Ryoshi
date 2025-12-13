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
import time

# Optional: AbuseIPDB integration
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class AbuseIPDBClient:
    """Client for querying AbuseIPDB threat intelligence API"""
    
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.results = {}
        self.rate_limit_delay = 1  # seconds between requests
    
    def check_ip(self, ip_address, max_age_days=90):
        """Query AbuseIPDB for a single IP address"""
        if not REQUESTS_AVAILABLE:
            print("[!] requests module not installed. Run: pip install requests")
            return None
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": ""
        }
        
        try:
            response = requests.get(self.ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    self.results[ip_address] = data['data']
                    return data['data']
            elif response.status_code == 401:
                print("[!] AbuseIPDB: Invalid API key")
            elif response.status_code == 429:
                print("[!] AbuseIPDB: Rate limit exceeded")
            else:
                print(f"[!] AbuseIPDB error: HTTP {response.status_code}")
        except requests.exceptions.Timeout:
            print(f"[!] AbuseIPDB timeout for {ip_address}")
        except Exception as e:
            print(f"[!] AbuseIPDB error for {ip_address}: {e}")
        
        return None
    
    def check_multiple_ips(self, ip_list, max_ips=50):
        """Query AbuseIPDB for multiple IP addresses with rate limiting"""
        if not REQUESTS_AVAILABLE:
            print("[!] requests module not installed. Run: pip install requests")
            return {}
        
        ips_to_check = list(set(ip_list))[:max_ips]
        print(f"[*] Querying AbuseIPDB for {len(ips_to_check)} IPs...")
        
        for i, ip in enumerate(ips_to_check):
            try:
                result = self.check_ip(ip)
                if result:
                    score = result.get('abuseConfidenceScore', 0)
                    reports = result.get('totalReports', 0)
                    if score > 0 or reports > 0:
                        print(f"    [!] {ip}: Score={score}%, Reports={reports}")
                    else:
                        print(f"    [+] {ip}: Clean")
            except KeyboardInterrupt:
                print(f"\n[*] AbuseIPDB queries interrupted by user. Processed {i} IPs.")
                break
            except Exception as e:
                print(f"    [!] {ip}: {str(e)}")
            
            if i < len(ips_to_check) - 1:
                time.sleep(self.rate_limit_delay)
        
        return self.results
    
    def get_malicious_ips(self, threshold=25):
        """Return IPs with abuse confidence score above threshold"""
        return {
            ip: data for ip, data in self.results.items()
            if data.get('abuseConfidenceScore', 0) >= threshold
        }
    
    def get_summary(self):
        """Generate summary of AbuseIPDB results"""
        if not self.results:
            return None
        
        total = len(self.results)
        malicious = len([r for r in self.results.values() if r.get('abuseConfidenceScore', 0) > 0])
        high_risk = len([r for r in self.results.values() if r.get('abuseConfidenceScore', 0) >= 75])
        
        return {
            'total_checked': total,
            'with_reports': malicious,
            'high_risk': high_risk,
            'results': self.results
        }


class RyoshiDetectionEngine:
    def __init__(self, abuseipdb_key=None):
        self.logs = []
        self.compromises = {
            'credential_theft': [],
            'token_compromise': []
        }
        self.timelines = {}
        self.abuseipdb_client = AbuseIPDBClient(abuseipdb_key) if abuseipdb_key else None
        self.ip_intelligence = {}

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

    def get_malicious_ips_from_detections(self):
        """Extract only malicious IPs from credential theft and token compromise detections"""
        malicious_ips = set()
        
        # Extract IPs from credential theft detections
        for finding in self.compromises['credential_theft']:
            malicious_ips.update(finding.get('ip_addresses', []))
        
        # Extract IPs from token compromise detections
        for finding in self.compromises['token_compromise']:
            malicious_ips.update(finding.get('ip_addresses', []))
        
        return list(malicious_ips)

    def get_all_unique_ips(self):
        """Extract all unique IP addresses from loaded logs"""
        all_ips = set()
        for log_entry in self.logs:
            ips = self.extract_ip_addresses(log_entry)
            all_ips.update(ips)
        return list(all_ips)

    def analyze_ips_with_abuseipdb(self, max_ips=50):
        """Analyze ONLY malicious IPs from detections using AbuseIPDB threat intelligence"""
        if not self.abuseipdb_client:
            print("[!] AbuseIPDB not configured. Use --abuseipdb-key to enable.")
            return
        
        if not REQUESTS_AVAILABLE:
            print("[!] requests module required for AbuseIPDB. Run: pip install requests")
            return
        
        # Get only IPs from malicious detections
        malicious_ips = self.get_malicious_ips_from_detections()
        
        if not malicious_ips:
            print("\n[*] No malicious IPs found in detections. Skipping AbuseIPDB analysis.")
            return
        
        print(f"\n[*] Analyzing {len(malicious_ips)} malicious IPs with AbuseIPDB...")
        
        # Query AbuseIPDB only for malicious IPs
        self.abuseipdb_client.check_multiple_ips(malicious_ips, max_ips=max_ips)
        self.ip_intelligence = self.abuseipdb_client.get_summary()
        
        if self.ip_intelligence:
            print(f"\n[+] AbuseIPDB Analysis Complete:")
            print(f"    Malicious IPs checked: {self.ip_intelligence['total_checked']}")
            print(f"    IPs with abuse reports: {self.ip_intelligence['with_reports']}")
            print(f"    High risk IPs (>75%): {self.ip_intelligence['high_risk']}")

    def analyze_ips_with_abuseipdb_old(self, max_ips=50):
        """OLD: Analyze ALL IPs from detections using AbuseIPDB threat intelligence"""
        if not self.abuseipdb_client:
            print("[!] AbuseIPDB not configured. Use --abuseipdb-key to enable.")
            return
        
        if not REQUESTS_AVAILABLE:
            print("[!] requests module required for AbuseIPDB. Run: pip install requests")
            return
        
        all_ips = self.get_all_unique_ips()
        print(f"\n[*] Found {len(all_ips)} unique IPs in logs")
        
        if not all_ips:
            print("[!] No IPs found to analyze")
            return
        
        # Query AbuseIPDB
        self.abuseipdb_client.check_multiple_ips(all_ips, max_ips=max_ips)
        self.ip_intelligence = self.abuseipdb_client.get_summary()
        
        if self.ip_intelligence:
            print(f"\n[+] AbuseIPDB Analysis Complete:")
            print(f"    IPs checked: {self.ip_intelligence['total_checked']}")
            print(f"    IPs with reports: {self.ip_intelligence['with_reports']}")
            print(f"    High risk IPs (>75%): {self.ip_intelligence['high_risk']}")

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
        """Generate detection and timeline reports (JSON, Markdown, HTML)"""
        print(f"\n[*] Generating reports to {output_dir}...")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_events_analyzed': len(self.logs),
            'unique_ips_found': len(self.get_all_unique_ips()),
            'malicious_ips_found': len(self.get_malicious_ips_from_detections()),
            'detections': {
                'credential_theft': len(self.compromises['credential_theft']),
                'token_compromise': len(self.compromises['token_compromise'])
            },
            'findings': self.compromises,
            'ip_intelligence': self.ip_intelligence if self.ip_intelligence else None
        }
        
        # Save JSON report
        report_path = os.path.join(output_dir, 'ryoshi_detection_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Detection report saved: {report_path}")
        
        # Generate Markdown report
        self._generate_markdown_report(output_dir, report)
        
        # Generate HTML report
        self._generate_html_report(output_dir, report)
        
        # Save timelines (JSON and Markdown)
        for user, timeline in self.timelines.items():
            safe_user = user.replace('@', '_').replace('.', '_')
            
            # JSON timeline
            timeline_path = os.path.join(output_dir, f'ryoshi_timeline_{safe_user}.json')
            with open(timeline_path, 'w') as f:
                json.dump({
                    'user': user,
                    'event_count': len(timeline),
                    'timeline': timeline
                }, f, indent=2, default=str)
            print(f"[+] Timeline saved: {timeline_path}")

    def _generate_markdown_report(self, output_dir, report):
        """Generate Markdown detection report"""
        md_content = f"""# Ryoshi M365 eDiscovery Detection Report

**Generated**: {report['generated_at']}

## Executive Summary

- **Total Events Analyzed**: {report['total_events_analyzed']:,}
- **Unique IPs Found**: {report['unique_ips_found']}
- **Malicious IPs Identified**: {report['malicious_ips_found']}
- **Credential Theft Incidents**: {report['detections']['credential_theft']}
- **Token Compromise Incidents**: {report['detections']['token_compromise']}

## Detection Results

### Credential Theft Detections

"""
        if report['findings']['credential_theft']:
            for finding in report['findings']['credential_theft']:
                md_content += f"""
#### {finding['user']}
- **Duration**: {finding['duration_hours']:.2f} hours
- **Unique Sessions**: {finding['unique_sessions']}
- **Unique IPs**: {finding['unique_ips']}
- **Login Count**: {finding['login_count']}
- **First Seen**: {finding['first_seen']}
- **Last Seen**: {finding['last_seen']}
- **IP Addresses**: {', '.join(finding['ip_addresses'])}

"""
        else:
            md_content += "\nNo credential theft detected.\n"

        md_content += "\n### Token Compromise Detections\n\n"
        
        if report['findings']['token_compromise']:
            for finding in report['findings']['token_compromise']:
                users = ', '.join(finding['users']) if finding['users'] else 'Unknown'
                md_content += f"""
#### Session: {finding['session_id']}
- **Users**: {users}
- **Unique IPs**: {finding['unique_ips']}
- **Operations**: {finding['operation_count']}
- **KMSI Enabled**: {finding['kmsi_enabled']}
- **Duration**: {finding['duration_hours']:.2f} hours
- **First Seen**: {finding['first_seen']}
- **Last Seen**: {finding['last_seen']}
- **IP Addresses**: {', '.join(finding['ip_addresses'])}

"""
        else:
            md_content += "\nNo token compromise detected.\n"

        # Add IP Intelligence section
        if report['ip_intelligence']:
            md_content += f"""
## IP Threat Intelligence (AbuseIPDB)

- **IPs Analyzed**: {report['ip_intelligence']['total_checked']}
- **IPs with Abuse Reports**: {report['ip_intelligence']['with_reports']}
- **High Risk IPs (>75%)**: {report['ip_intelligence']['high_risk']}

"""

        md_path = os.path.join(output_dir, 'ryoshi_detection_report.md')
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"[+] Markdown report saved: {md_path}")

    def _generate_html_report(self, output_dir, report):
        """Generate HTML detection report"""
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ryoshi Detection Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d32f2f;
            border-bottom: 3px solid #d32f2f;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #1976d2;
            margin-top: 30px;
            border-left: 4px solid #1976d2;
            padding-left: 10px;
        }}
        h3 {{
            color: #388e3c;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: #f9f9f9;
            border: 1px solid #ddd;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            color: #d32f2f;
        }}
        .summary-card .label {{
            color: #666;
            margin-top: 10px;
        }}
        .finding {{
            background: #fff9c4;
            border-left: 4px solid #fbc02d;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        .finding.critical {{
            background: #ffebee;
            border-left-color: #d32f2f;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        table th {{
            background: #1976d2;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
        }}
        table tr:hover {{
            background: #f5f5f5;
        }}
        .threat {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .clean {{
            color: #388e3c;
            font-weight: bold;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Ryoshi M365 eDiscovery Detection Report</h1>
        <p><strong>Generated:</strong> {report['generated_at']}</p>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <div class="number">{report['total_events_analyzed']:,}</div>
                <div class="label">Events Analyzed</div>
            </div>
            <div class="summary-card">
                <div class="number">{report['unique_ips_found']}</div>
                <div class="label">Unique IPs</div>
            </div>
            <div class="summary-card">
                <div class="number threat">{report['malicious_ips_found']}</div>
                <div class="label">Malicious IPs</div>
            </div>
            <div class="summary-card">
                <div class="number threat">{report['detections']['credential_theft']}</div>
                <div class="label">Credential Theft</div>
            </div>
            <div class="summary-card">
                <div class="number threat">{report['detections']['token_compromise']}</div>
                <div class="label">Token Compromise</div>
            </div>
        </div>

        <h2>🚨 Credential Theft Detections</h2>
"""
        
        if report['findings']['credential_theft']:
            for finding in report['findings']['credential_theft']:
                html_content += f"""
        <div class="finding critical">
            <h3>{finding['user']}</h3>
            <table>
                <tr><td><strong>Duration</strong></td><td>{finding['duration_hours']:.2f} hours</td></tr>
                <tr><td><strong>Unique Sessions</strong></td><td>{finding['unique_sessions']}</td></tr>
                <tr><td><strong>Unique IPs</strong></td><td>{finding['unique_ips']}</td></tr>
                <tr><td><strong>Login Count</strong></td><td>{finding['login_count']}</td></tr>
                <tr><td><strong>First Seen</strong></td><td>{finding['first_seen']}</td></tr>
                <tr><td><strong>Last Seen</strong></td><td>{finding['last_seen']}</td></tr>
                <tr><td><strong>IP Addresses</strong></td><td><code>{', '.join(finding['ip_addresses'])}</code></td></tr>
            </table>
        </div>
"""
        else:
            html_content += "<p>✓ No credential theft detected.</p>"

        html_content += f"""
        <h2>⚠️ Token Compromise Detections</h2>
"""
        
        if report['findings']['token_compromise']:
            for finding in report['findings']['token_compromise']:
                users = ', '.join(finding['users']) if finding['users'] else 'Unknown'
                html_content += f"""
        <div class="finding">
            <h3>Session: {finding['session_id'][:36]}...</h3>
            <table>
                <tr><td><strong>Users</strong></td><td>{users}</td></tr>
                <tr><td><strong>Unique IPs</strong></td><td>{finding['unique_ips']}</td></tr>
                <tr><td><strong>Operations</strong></td><td>{finding['operation_count']}</td></tr>
                <tr><td><strong>KMSI Enabled</strong></td><td>{'Yes' if finding['kmsi_enabled'] else 'No'}</td></tr>
                <tr><td><strong>Duration</strong></td><td>{finding['duration_hours']:.2f} hours</td></tr>
                <tr><td><strong>First Seen</strong></td><td>{finding['first_seen']}</td></tr>
                <tr><td><strong>Last Seen</strong></td><td>{finding['last_seen']}</td></tr>
                <tr><td><strong>IP Addresses</strong></td><td><code>{', '.join(finding['ip_addresses'])}</code></td></tr>
            </table>
        </div>
"""
        else:
            html_content += "<p>✓ No token compromise detected.</p>"

        # Add IP Intelligence section
        if report['ip_intelligence']:
            html_content += f"""
        <h2>🔍 IP Threat Intelligence (AbuseIPDB)</h2>
        <div class="summary">
            <div class="summary-card">
                <div class="number">{report['ip_intelligence']['total_checked']}</div>
                <div class="label">IPs Analyzed</div>
            </div>
            <div class="summary-card">
                <div class="number threat">{report['ip_intelligence']['with_reports']}</div>
                <div class="label">With Abuse Reports</div>
            </div>
            <div class="summary-card">
                <div class="number threat">{report['ip_intelligence']['high_risk']}</div>
                <div class="label">High Risk (>75%)</div>
            </div>
        </div>
"""

        html_content += """
        <div class="footer">
            <p>Ryoshi M365 eDiscovery Detection Engine | Security Report</p>
        </div>
    </div>
</body>
</html>
"""

        html_path = os.path.join(output_dir, 'ryoshi_detection_report.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"[+] HTML report saved: {html_path}")


    def print_summary(self):
        """Print summary of findings"""
        print("\n" + "="*60)
        print("RYOSHI DETECTION SUMMARY")
        print("="*60)
        print(f"Total events analyzed: {len(self.logs)}")
        print(f"Unique IPs found: {len(self.get_all_unique_ips())}")
        print(f"Credential theft incidents: {len(self.compromises['credential_theft'])}")
        print(f"Token compromise incidents: {len(self.compromises['token_compromise'])}")
        
        if self.ip_intelligence:
            print("-"*60)
            print("ABUSEIPDB THREAT INTELLIGENCE")
            print(f"IPs analyzed: {self.ip_intelligence['total_checked']}")
            print(f"IPs with abuse reports: {self.ip_intelligence['with_reports']}")
            print(f"High risk IPs (>75% score): {self.ip_intelligence['high_risk']}")
        
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
    
    parser.add_argument(
        '--abuseipdb-key',
        dest='abuseipdb_key',
        metavar='API_KEY',
        help='AbuseIPDB API key for IP threat intelligence'
    )
    
    parser.add_argument(
        '--max-ips',
        dest='max_ips',
        type=int,
        default=50,
        metavar='N',
        help='Maximum number of IPs to query on AbuseIPDB (default: 50)'
    )
    
    args = parser.parse_args()
    
    if not args.files and not args.folders:
        parser.error("You must specify at least one file (-f) or folder (-F)")
    
    print("[+] Ryoshi M365 eDiscovery Detection Engine")
    print("="*50)
    
    engine = RyoshiDetectionEngine(abuseipdb_key=args.abuseipdb_key)
    
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
    
    # AbuseIPDB threat intelligence analysis
    if args.abuseipdb_key:
        engine.analyze_ips_with_abuseipdb(max_ips=args.max_ips)
    
    compromised_users = set()
    for finding in engine.compromises['credential_theft']:
        compromised_users.add(finding['user'])
    
    for user in compromised_users:
        engine.build_timeline(user)
    
    engine.generate_report(args.output)
    engine.print_summary()


if __name__ == '__main__':
    main()
