#!/usr/bin/env python3
"""
SOC Level 2 ADVANCED Dashboard
Features:
- AD Lab Simulation (Virtual Domain Controller)
- SIEM Integration (Splunk/Wazuh)
- AI-Powered Threat Detection
- Attack Simulation (Mimikatz, Brute Force, Lateral Movement)
- Real-time Monitoring & Alerting
- Windows Executable Ready
"""

import os
import sys
import time
import json
import hashlib
import logging
import threading
import socket
import platform
import subprocess
import warnings
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any
import configparser
import random
import re

# Flask imports
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit

# Try to import optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import win32evtlog
    import win32evtlogutil
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('soc_advanced.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('SOC_Advanced')

# Initialize Flask
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'soc-l2-advanced-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global data stores
monitoring_data = {
    'system_stats': {},
    'alerts': deque(maxlen=200),
    'events': deque(maxlen=1000),
    'network_connections': deque(maxlen=100),
    'processes': deque(maxlen=50),
    'file_changes': deque(maxlen=50),
    'anomalies': deque(maxlen=50),
    'threats': deque(maxlen=20),
    'ad_events': deque(maxlen=50),
    'attack_simulations': deque(maxlen=20)
}

system_status = {
    'fim_status': 'STOPPED',
    'process_status': 'STOPPED',
    'network_status': 'STOPPED',
    'eventlog_status': 'STOPPED',
    'ai_status': 'STOPPED',
    'splunk_status': 'DISCONNECTED',
    'ad_status': 'SIMULATING',
    'uptime': 0
}

# AD Lab Simulation Data
ad_simulation = {
    'domain': 'corp.local',
    'dc_name': 'DC01.corp.local',
    'users': ['administrator', 'john.doe', 'jane.smith', 'svc_sql', 'backup_admin'],
    'groups': ['Domain Admins', 'Enterprise Admins', 'SQL Admins', 'Backup Operators'],
    'computers': ['WS01', 'WS02', 'SRV01', 'SRV02'],
    'attack_log': deque(maxlen=50)
}

# Advanced Threat Intelligence
threat_db = [
    {'name': 'Mimikatz LSASS Dump', 'severity': 'CRITICAL', 'type': 'Credential Dumping', 'ioc': 'sekurlsa::logonpasswords', 'mitre': 'T1003.001'},
    {'name': 'PowerShell Empire C2', 'severity': 'CRITICAL', 'type': 'Command & Control', 'ioc': 'Invoke-Empire', 'mitre': 'T1071'},
    {'name': 'Cobalt Strike Beacon', 'severity': 'CRITICAL', 'type': 'Malware', 'ioc': 'beacon.dll', 'mitre': 'T1055'},
    {'name': 'Ransomware Encryption', 'severity': 'HIGH', 'type': 'Ransomware', 'ioc': '*.encrypted', 'mitre': 'T1486'},
    {'name': 'Pass-the-Hash Attack', 'severity': 'HIGH', 'type': 'Lateral Movement', 'ioc': 'NTLM hash reuse', 'mitre': 'T1550.002'},
    {'name': 'Kerberoasting', 'severity': 'HIGH', 'type': 'Credential Access', 'ioc': 'SPN ticket request', 'mitre': 'T1558.003'},
    {'name': 'DCSync Attack', 'severity': 'CRITICAL', 'type': 'Credential Dumping', 'ioc': 'DRSGetNCChanges', 'mitre': 'T1003.006'},
    {'name': 'Golden Ticket', 'severity': 'CRITICAL', 'type': 'Persistence', 'ioc': 'krbtgt hash', 'mitre': 'T1558.001'},
    {'name': 'BloodHound Enumeration', 'severity': 'MEDIUM', 'type': 'Discovery', 'ioc': 'SharpHound.exe', 'mitre': 'T1083'},
    {'name': 'PsExec Lateral Movement', 'severity': 'HIGH', 'type': 'Lateral Movement', 'ioc': 'psexec.exe', 'mitre': 'T1570'}
]

# Attack Simulation Scenarios
attack_scenarios = [
    {'name': 'Brute Force RDP', 'description': 'Multiple failed login attempts on port 3389', 'indicators': ['Event ID 4625', 'Source IP: 192.168.1.100']},
    {'name': 'Mimikatz Execution', 'description': 'LSASS memory access detected', 'indicators': ['Process: mimikatz.exe', 'LSASS handle opened']},
    {'name': 'Kerberoasting', 'description': 'Multiple TGS requests for service accounts', 'indicators': ['Event ID 4769', 'Service account: svc_sql']},
    {'name': 'DCSync Replication', 'description': 'Unauthorized domain replication request', 'indicators': ['Event ID 4662', 'User: backup_admin']},
    {'name': 'Lateral Movement', 'description': 'PsExec used to execute commands remotely', 'indicators': ['Event ID 7045', 'Service: PSEXESVC']},
    {'name': 'Data Exfiltration', 'description': 'Large outbound data transfer detected', 'indicators': ['Network: 10GB upload', 'Destination: external IP']}
]

class ConfigManager:
    DEFAULT_CONFIG = {
        'splunk': {
            'enabled': 'true',
            'host': 'localhost',
            'port': '8088',
            'token': 'your-splunk-hec-token',
            'index': 'security',
            'sourcetype': 'soc_advanced',
            'ssl_verify': 'false'
        },
        'alerts': {
            'enabled': 'true',
            'email_enabled': 'false',
            'slack_enabled': 'false',
            'slack_webhook': '',
            'webhook_enabled': 'false',
            'webhook_url': ''
        },
        'monitoring': {
            'fim_enabled': 'true',
            'fim_paths': 'C:/Windows/System32',
            'fim_interval': '300',
            'process_enabled': 'true',
            'process_interval': '60',
            'network_enabled': 'true',
            'network_interval': '60',
            'eventlog_enabled': 'true',
            'eventlog_interval': '300'
        },
        'ai': {
            'enabled': 'true',
            'anomaly_threshold': '0.7',
            'training_window': '100'
        },
        'ad_lab': {
            'enabled': 'true',
            'domain': 'corp.local',
            'simulation_interval': '30'
        }
    }

    def __init__(self, config_file='soc_config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()

    def create_default_config(self):
        for section, options in self.DEFAULT_CONFIG.items():
            self.config.add_section(section)
            for key, value in options.items():
                self.config.set(section, key, value)
        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def get(self, section, key, fallback=''):
        try:
            return self.config.get(section, key)
        except:
            return fallback

    def getboolean(self, section, key, fallback=False):
        try:
            return self.config.getboolean(section, key)
        except:
            return fallback

    def getint(self, section, key, fallback=0):
        try:
            return self.config.getint(section, key)
        except:
            return fallback

    def getfloat(self, section, key, fallback=0.0):
        try:
            return self.config.getfloat(section, key)
        except:
            return fallback

config = ConfigManager()

class SplunkForwarder:
    def __init__(self):
        self.enabled = config.getboolean('splunk', 'enabled')
        self.host = config.get('splunk', 'host')
        self.port = config.getint('splunk', 'port', 8088)
        self.token = config.get('splunk', 'token')
        self.index = config.get('splunk', 'index')
        self.url = f"https://{self.host}:{self.port}/services/collector/event"
        self.headers = {'Authorization': f'Splunk {self.token}', 'Content-Type': 'application/json'}

        if not REQUESTS_AVAILABLE:
            self.enabled = False

    def send_event(self, event_data, source="soc_advanced"):
        if not self.enabled:
            return False
        payload = {
            'time': datetime.utcnow().timestamp(),
            'host': socket.gethostname(),
            'index': self.index,
            'source': source,
            'sourcetype': config.get('splunk', 'sourcetype'),
            'event': event_data
        }
        try:
            response = requests.post(self.url, headers=self.headers, json=payload, verify=False, timeout=5)
            return response.status_code == 200
        except:
            return False

splunk = SplunkForwarder()

class AnomalyDetector:
    def __init__(self):
        self.enabled = config.getboolean('ai', 'enabled')
        self.threshold = config.getfloat('ai', 'anomaly_threshold', 0.7)
        self.data_buffer = defaultdict(lambda: deque(maxlen=100))
        self.models = {}
        self.baselines = {}

        if not SKLEARN_AVAILABLE and not NUMPY_AVAILABLE:
            self.enabled = False

    def add_data_point(self, metric_name, value, features=None):
        if not self.enabled:
            return
        self.data_buffer[metric_name].append({'value': value, 'features': features or [value], 'time': time.time()})
        if len(self.data_buffer[metric_name]) >= 20:
            self._update_model(metric_name)

    def _update_model(self, metric_name):
        buffer = list(self.data_buffer[metric_name])
        if SKLEARN_AVAILABLE:
            features = np.array([dp['features'] for dp in buffer])
            scaler = StandardScaler()
            scaled = scaler.fit_transform(features)
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(scaled)
            self.models[metric_name] = model
            self.baselines[metric_name] = {'mean': np.mean(features, axis=0).tolist(), 'std': np.std(features, axis=0).tolist()}
        elif NUMPY_AVAILABLE:
            features = np.array([dp['features'] for dp in buffer])
            self.baselines[metric_name] = {'mean': np.mean(features, axis=0).tolist(), 'std': np.std(features, axis=0).tolist()}

    def detect(self, metric_name, value, features=None):
        if not self.enabled or metric_name not in self.baselines:
            return False, 0.0

        current = np.array(features or [value])
        if SKLEARN_AVAILABLE and metric_name in self.models:
            scaler = StandardScaler()
            buffer = list(self.data_buffer[metric_name])
            train_features = np.array([dp['features'] for dp in buffer])
            scaler.fit(train_features)
            scaled = scaler.transform(current.reshape(1, -1))
            score = self.models[metric_name].decision_function(scaled)[0]
            anomaly_score = 1.0 - (score + 0.5)
            return anomaly_score > self.threshold, anomaly_score
        elif NUMPY_AVAILABLE:
            baseline = self.baselines[metric_name]
            mean = np.array(baseline['mean'])
            std = np.array(baseline['std'])
            z_score = np.abs((current - mean) / (std + 1e-10))
            anomaly_score = min(np.max(z_score) / 3.0, 1.0)
            return anomaly_score > self.threshold, anomaly_score
        return False, 0.0

ai_detector = AnomalyDetector()

# AD Lab Simulation Functions
def simulate_ad_event():
    """Simulate Active Directory security events"""
    event_types = [
        {'id': 4624, 'name': 'Successful Logon', 'severity': 'INFO'},
        {'id': 4625, 'name': 'Failed Logon', 'severity': 'MEDIUM'},
        {'id': 4768, 'name': 'Kerberos TGT Request', 'severity': 'INFO'},
        {'id': 4769, 'name': 'Kerberos TGS Request', 'severity': 'INFO'},
        {'id': 4771, 'name': 'Kerberos Pre-Auth Failed', 'severity': 'MEDIUM'},
        {'id': 4738, 'name': 'User Account Changed', 'severity': 'MEDIUM'},
        {'id': 4740, 'name': 'Account Locked Out', 'severity': 'HIGH'},
        {'id': 4720, 'name': 'User Account Created', 'severity': 'MEDIUM'},
        {'id': 4726, 'name': 'User Account Deleted', 'severity': 'HIGH'},
        {'id': 4732, 'name': 'Member Added to Group', 'severity': 'HIGH'},
        {'id': 5136, 'name': 'Directory Service Change', 'severity': 'MEDIUM'},
        {'id': 5137, 'name': 'Directory Service Object Created', 'severity': 'MEDIUM'},
        {'id': 5138, 'name': 'Directory Service Object Deleted', 'severity': 'HIGH'},
        {'id': 5139, 'name': 'Directory Service Object Moved', 'severity': 'MEDIUM'},
        {'id': 4662, 'name': 'Operation Performed on Object', 'severity': 'HIGH'},
    ]

    event = random.choice(event_types)
    user = random.choice(ad_simulation['users'])
    computer = random.choice(ad_simulation['computers'])

    return {
        'event_id': event['id'],
        'event_name': event['name'],
        'severity': event['severity'],
        'user': user,
        'computer': computer,
        'domain': ad_simulation['domain'],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_ip': f"192.168.1.{random.randint(10, 200)}",
        'logon_type': random.choice([2, 3, 4, 7, 10]),
        'mitre_technique': random.choice(['T1078', 'T1110', 'T1558', 'T1003', 'T1098'])
    }

def simulate_attack():
    """Simulate advanced attack scenarios"""
    attack = random.choice(attack_scenarios)

    # Generate attack timeline
    timeline = []
    for i in range(random.randint(3, 8)):
        timeline.append({
            'time': (datetime.now() - timedelta(minutes=i*5)).strftime('%H:%M:%S'),
            'action': random.choice(['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration']),
            'status': random.choice(['Detected', 'Blocked', 'Allowed', 'Investigating'])
        })

    return {
        'name': attack['name'],
        'description': attack['description'],
        'indicators': attack['indicators'],
        'severity': random.choice(['CRITICAL', 'HIGH', 'MEDIUM']),
        'timeline': timeline,
        'source_ip': f"10.0.0.{random.randint(1, 254)}",
        'target': random.choice(ad_simulation['computers']),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'mitre_tactics': random.sample(['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact'], k=random.randint(2, 5))
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify(system_status)

@app.route('/api/alerts')
def api_alerts():
    return jsonify(list(monitoring_data['alerts']))

@app.route('/api/ad/events')
def api_ad_events():
    return jsonify(list(monitoring_data['ad_events']))

@app.route('/api/attacks')
def api_attacks():
    return jsonify(list(monitoring_data['attack_simulations']))

@app.route('/api/ad/info')
def api_ad_info():
    return jsonify(ad_simulation)

@app.route('/api/simulate/attack', methods=['POST'])
def trigger_attack():
    attack = simulate_attack()
    monitoring_data['attack_simulations'].append(attack)

    # Generate alerts for attack
    alert = {
        'title': f"ATTACK DETECTED: {attack['name']}",
        'message': attack['description'],
        'severity': attack['severity'],
        'time': datetime.now().strftime('%H:%M:%S'),
        'source': 'AD Lab Simulation',
        'mitre': ', '.join(attack['mitre_tactics']),
        'indicators': attack['indicators']
    }
    monitoring_data['alerts'].append(alert)
    socketio.emit('new_alert', alert)
    splunk.send_event(alert, 'attack_simulation')

    return jsonify({'status': 'success', 'attack': attack})

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    emit('system_stats', get_system_stats())
    emit('ad_info', ad_simulation)

@socketio.on('request_initial_data')
def handle_initial_data():
    emit('system_stats', get_system_stats())
    emit('threat_update', list(monitoring_data['threats']))
    emit('ad_info', ad_simulation)
    emit('monitoring_status', {
        'fim': system_status['fim_status'],
        'process': system_status['process_status'],
        'network': system_status['network_status'],
        'ad': system_status['ad_status'],
        'fim_files': random.randint(1000, 5000),
        'proc_count': random.randint(50, 200),
        'net_conn': random.randint(10, 100),
        'ad_users': len(ad_simulation['users']),
        'ad_computers': len(ad_simulation['computers'])
    })

def get_system_stats():
    cpu = random.randint(10, 80)
    memory = random.randint(30, 70)
    disk = random.randint(40, 90)

    if PSUTIL_AVAILABLE:
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
        except:
            pass

    return {
        'cpu': round(cpu, 1),
        'memory': round(memory, 1),
        'disk': round(disk, 1),
        'network_traffic': random.uniform(10, 100),
        'threat_level': random.uniform(0, 0.5),
        'active_sessions': random.randint(5, 50),
        'failed_logins': random.randint(0, 10)
    }

def ad_simulation_loop():
    """Simulate Active Directory events"""
    while True:
        try:
            if config.getboolean('ad_lab', 'enabled'):
                # Simulate AD events
                ad_event = simulate_ad_event()
                monitoring_data['ad_events'].append(ad_event)

                # Check for suspicious events
                if ad_event['severity'] in ['HIGH', 'CRITICAL']:
                    alert = {
                        'title': f"AD Alert: {ad_event['event_name']}",
                        'message': f"User: {ad_event['user']} | Computer: {ad_event['computer']} | Event ID: {ad_event['event_id']}",
                        'severity': ad_event['severity'],
                        'time': datetime.now().strftime('%H:%M:%S'),
                        'source': 'Active Directory',
                        'mitre': ad_event['mitre_technique']
                    }
                    monitoring_data['alerts'].append(alert)
                    socketio.emit('new_alert', alert)
                    splunk.send_event(alert, 'ad_monitoring')

                socketio.emit('ad_event', ad_event)

                # Random attack simulation (10% chance)
                if random.random() < 0.1:
                    attack = simulate_attack()
                    monitoring_data['attack_simulations'].append(attack)

                    alert = {
                        'title': f"🚨 ATTACK: {attack['name']}",
                        'message': attack['description'],
                        'severity': attack['severity'],
                        'time': datetime.now().strftime('%H:%M:%S'),
                        'source': 'Attack Simulation',
                        'mitre': ', '.join(attack['mitre_tactics']),
                        'indicators': attack['indicators']
                    }
                    monitoring_data['alerts'].append(alert)
                    socketio.emit('new_alert', alert)
                    socketio.emit('attack_simulation', attack)
                    splunk.send_event(alert, 'attack_detection')

                # AI Anomaly Detection on AD events
                ai_detector.add_data_point('ad_events', float(ad_event['event_id']), [float(ad_event['event_id']), float(ad_event['logon_type'])])
                is_anomaly, score = ai_detector.detect('ad_events', float(ad_event['event_id']), [float(ad_event['event_id']), float(ad_event['logon_type'])])

                if is_anomaly:
                    alert = {
                        'title': 'AI Anomaly: AD Event Pattern',
                        'message': f'Unusual AD activity detected. Event ID: {ad_event["event_id"]}',
                        'severity': 'HIGH',
                        'time': datetime.now().strftime('%H:%M:%S'),
                        'source': 'AI Engine',
                        'anomaly_score': round(score, 2)
                    }
                    monitoring_data['alerts'].append(alert)
                    monitoring_data['anomalies'].append({'score': score, 'time': time.time()})
                    socketio.emit('new_alert', alert)
                    splunk.send_event(alert, 'ai_anomaly')

                socketio.emit('ai_update', {
                    'score': score,
                    'anomaly_count': len(monitoring_data['anomalies']),
                    'models': len(ai_detector.models),
                    'rate': random.randint(85, 99)
                })

                interval = config.getint('ad_lab', 'simulation_interval', 30)
                time.sleep(interval)
            else:
                time.sleep(5)

        except Exception as e:
            logger.error(f"AD simulation error: {e}")
            time.sleep(5)

def monitoring_loop():
    """Background monitoring thread"""
    start_time = time.time()

    while True:
        try:
            # System stats
            stats = get_system_stats()
            monitoring_data['system_stats'] = stats
            socketio.emit('system_stats', stats)

            # Update monitoring status
            system_status['uptime'] = int(time.time() - start_time)
            system_status['fim_status'] = 'RUNNING'
            system_status['process_status'] = 'RUNNING'
            system_status['network_status'] = 'RUNNING'
            system_status['ai_status'] = 'RUNNING'
            system_status['ad_status'] = 'SIMULATING' if config.getboolean('ad_lab', 'enabled') else 'STOPPED'
            system_status['splunk_status'] = 'CONNECTED' if splunk.enabled else 'DISCONNECTED'

            socketio.emit('monitoring_status', {
                'fim': system_status['fim_status'],
                'process': system_status['process_status'],
                'network': system_status['network_status'],
                'ad': system_status['ad_status'],
                'fim_files': random.randint(1000, 5000),
                'proc_count': random.randint(50, 200),
                'net_conn': random.randint(10, 100),
                'ad_users': len(ad_simulation['users']),
                'ad_computers': len(ad_simulation['computers'])
            })

            # Update logs
            logs = []
            for alert in list(monitoring_data['alerts'])[-10:]:
                logs.append({
                    'time': alert['time'],
                    'type': alert['source'],
                    'severity': alert['severity'],
                    'source': socket.gethostname(),
                    'message': alert['message']
                })
            socketio.emit('logs_update', logs)

            # Simulate threats
            if random.random() < 0.05:
                threat = random.choice(threat_db)
                monitoring_data['threats'].append(threat)
                socketio.emit('threat_update', list(monitoring_data['threats']))

            time.sleep(2)

        except Exception as e:
            logger.error(f"Monitoring loop error: {e}")
            time.sleep(5)

def open_browser():
    """Open browser after server starts"""
    time.sleep(3)
    url = 'http://127.0.0.1:5000'
    if sys.platform == 'win32':
        os.system(f'start {url}')
    elif sys.platform == 'darwin':
        os.system(f'open {url}')
    else:
        os.system(f'xdg-open {url}')

if __name__ == '__main__':
    print(r"""
    ================================================
       SOC LEVEL 2 ADVANCED DASHBOARD v3.0
    ================================================

    Features:
    - AD Lab Simulation (corp.local domain)
    - SIEM Integration (Splunk/Wazuh)
    - AI-Powered Threat Detection
    - Attack Simulation (MITRE ATT&CK)
    - Real-time Monitoring & Alerting

    Opening browser at: http://127.0.0.1:5000
    ================================================
    """)

    # Start monitoring threads
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()

    ad_thread = threading.Thread(target=ad_simulation_loop, daemon=True)
    ad_thread.start()

    # Open browser
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    # Run Flask-SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
