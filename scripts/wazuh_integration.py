import json
import os
from scripts.email_alerter import SmartEmailAlerter
from datetime import datetime
from pathlib import Path
from scripts.threat_intel import ThreatIntelligence

class WazuhIntegration:
    def __init__(self, base_path='/home/sharvesh/neural_ids'):
        self.base_path = Path(base_path)
        self.alert_log = self.base_path / 'logs' / 'neural_alerts.json'
        self.alert_log.parent.mkdir(parents=True, exist_ok=True)
        try:
         self.email_alerter = SmartEmailAlerter()
        except Exception as e:
         print(f"⚠️ Email alerter initialization failed: {e}")
         self.email_alerter = None
        try:
         self.threat_intel = ThreatIntelligence()
        except Exception as e:
         print(f"Threat intel init failed: {e}")
         self.threat_intel = None
        print("✅ Wazuh Integration Ready")
    def send_to_wazuh_socket(self, alert):
     """Send alert directly to Wazuh socket"""
     try:
         import socket
         import json
        
         # Wazuh socket path
         wazuh_socket = '/var/ossec/queue/sockets/queue'
        
         # Format alert for Wazuh
         wazuh_alert = {
             'timestamp': alert['timestamp'],
             'rule': {
                 'level': self._get_wazuh_level(alert['severity']),
                 'description': f"Neural IDS: {alert['predicted_attack']}"
             },
             'data': {
                 'neural_ids': alert
             }
         }
        
         # Send to socket
         sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
         sock.sendto(json.dumps(wazuh_alert).encode(), wazuh_socket)
         sock.close()
         
         return True
     except Exception as e:
         print(f"Failed to send to Wazuh socket: {e}")
         return False 
    def send_alert(self, detection_result, source_ip='unknown', dest_ip='unknown'):
        if detection_result is None or not detection_result['is_threat']:
            return False
        whitelist = [
          '127.0.0.1',
          '192.168.80.1',
          '192.168.80.2',
          '192.168.80.128',
          '192.168.80.254',
          '192.168.80.255'
           ]
    
        if source_ip in whitelist:
         # Silently ignore whitelisted IPs
         return False
        detection_result['source_ip'] = source_ip
        detection_result['dest_ip'] = dest_ip
        if self.threat_intel:
         detection_result = self.threat_intel.enrich_alert(detection_result, source_ip)
        alert = {
            'timestamp': detection_result['timestamp'],
            'rule': {
                'id': self._get_rule_id(detection_result['severity']),
                'description': f"Neural IDS: {detection_result['predicted_attack']} detected",
                'level': self._get_wazuh_level(detection_result['severity'])
            },
            'neural_ids': detection_result
        }
        self.send_to_wazuh_socket(detection_result)
        # Write to log
        with open(self.alert_log, 'a') as f:
            f.write(json.dumps(alert) + '\n')
        
        # Print alert
        self._print_alert(detection_result)
        
        return True
    def send_alert(self, detection_result, source_ip='unknown', dest_ip='unknown'):
     if detection_result is None or not detection_result['is_threat']:
         return False
    
     detection_result['source_ip'] = source_ip
     detection_result['dest_ip'] = dest_ip
    
     # Write to JSON log (for our records)
     alert = {
         'timestamp': detection_result['timestamp'],
         'rule': {
             'id': self._get_rule_id(detection_result['severity']),
             'description': f"Neural IDS: {detection_result['predicted_attack']} detected",
             'level': self._get_wazuh_level(detection_result['severity'])
         },
         'neural_ids': detection_result
     }
    
     with open(self.alert_log, 'a') as f:
         f.write(json.dumps(alert) + '\n')
    
     # Send to syslog (STANDARD METHOD - Wazuh already monitors this)
     import subprocess
    
     syslog_msg = (
         f"NEURAL_IDS_ALERT: "
         f"severity={detection_result['severity']} "
         f"attack={detection_result['predicted_attack']} "
         f"confidence={detection_result['confidence']}% "
         f"src_ip={source_ip} "
         f"dst_ip={dest_ip} "
         f"anomaly={detection_result['is_anomaly']}"
     )
    
     # Use logger command to send to syslog
     subprocess.run(['logger', '-t', 'neural-ids', '-p', 'local0.alert', syslog_msg])
        
     if self.email_alerter:
        self.email_alerter.send_email(detection_result)

    # Print to console
     self._print_alert(detection_result)
     
     return True
    def _print_alert(self, alert):
        colors = {
            'SEVERE': '\033[91m',
            'HIGH': '\033[93m',
            'MEDIUM': '\033[94m',
            'NONE': '\033[0m'
        }
        color = colors.get(alert['severity'], '\033[0m')
        reset = '\033[0m'
        
        print(f"\n{color}{'='*60}")
        print(f"🚨 NEURAL IDS ALERT - {alert['severity']}")
        print(f"{'='*60}")
        print(f"Attack Type : {alert['predicted_attack']}")
        print(f"Confidence  : {alert['confidence']}%")
        print(f"Severity    : {alert['severity']}")
        print(f"Source IP   : {alert.get('source_ip', 'unknown')}")
        print(f"Target IP   : {alert.get('dest_ip', 'unknown')}")
        print(f"Timestamp   : {alert['timestamp']}")
        print(f"Anomaly     : {'YES' if alert['is_anomaly'] else 'NO'}")
        print(f"{'='*60}{reset}\n")
    
    def _get_rule_id(self, severity):
        ids = {'SEVERE': 100001, 'HIGH': 100002, 'MEDIUM': 100003, 'LOW': 100004}
        return ids.get(severity, 100000)
    
    def _get_wazuh_level(self, severity):
        levels = {'SEVERE': 15, 'HIGH': 12, 'MEDIUM': 8, 'LOW': 5}
        return levels.get(severity, 5)

if __name__ == "__main__":
    integration = WazuhIntegration()
    
    # Test alert
    test_alert = {
        'timestamp': datetime.now().isoformat(),
        'predicted_attack': 'DDoS',
        'confidence': 95.5,
        'severity': 'SEVERE',
        'is_anomaly': True,
        'is_threat': True
    }
    
    integration.send_alert(test_alert, '192.168.80.200', '192.168.80.128')
