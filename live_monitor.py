
#!/usr/bin/env python3
"""
Live Network Traffic Monitor
Captures real traffic and analyzes with Neural Network IDS
"""
import sys
import os
import time
import json
import logging
import numpy as np
import threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from scripts.infrastructure_filter import InfrastructureFilter

BASE_PATH = Path('/home/sharvesh/neural_ids')
sys.path.insert(0, str(BASE_PATH))

from scripts.neural_analyzer import NeuralAnalyzer
from scripts.wazuh_integration import WazuhIntegration
import warnings
warnings.filterwarnings('ignore')
# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(BASE_PATH / 'logs/live_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class LiveMonitor:
    def __init__(self):
        self.config = self._load_config()
        self.analyzer = NeuralAnalyzer()
        self.wazuh = WazuhIntegration()
        self.flows = defaultdict(lambda: {
            'start_time': None,
            'fwd_packets': [],
            'bwd_packets': [],
            'fwd_iat': [],
            'bwd_iat': [],
            'last_fwd_time': None,
            'last_bwd_time': None,
            'src_ip': None,
            'dst_ip': None
        })
        self.flow_lock = threading.Lock()
        self.stats = {
            'total_flows': 0,
            'threats_detected': 0,
            'ips_blocked': set()
        }
        
        self.interface = self.config['network']['monitor_interface']
        self.target_ip = self.config['network']['target_ip']
        
        print("="*70)
        print("  Neural Network IDS - Live Monitor")
        print("="*70)
        print(f"Interface : {self.interface}")
        print(f"Target IP : {self.target_ip}")
        print(f"Ubuntu IP : {self.config['network']['ubuntu_ip']}")
        print("="*70)
        self._print_startup_summary()
        self.infra_filter = InfrastructureFilter()
        print(f"Infrastructure filter: {len(self.infra_filter.infrastructure_ips)} IPs excluded")
        print(f"Excluded IPs: {', '.join(sorted(self.infra_filter.infrastructure_ips))}")
    def _print_startup_summary(self):
     """Print detailed startup information"""
     print("\n" + "="*70)
     print("  NEURAL NETWORK IDS - SYSTEM STATUS")
     print("="*70)
    
     # Network configuration
     print("\n📡 NETWORK CONFIGURATION")
     print(f"   Interface     : {self.interface}")
     print(f"   Target IP     : {self.target_ip}")
     print(f"   SIEM IP       : {self.config['network']['ubuntu_ip']}")
    
     # Infrastructure filter
     if hasattr(self, 'infra_filter'):
         print(f"\n  INFRASTRUCTURE FILTER")
         print(f"   Excluded IPs  : {len(self.infra_filter.infrastructure_ips)}")
         for ip in sorted(self.infra_filter.infrastructure_ips):
             print(f"      • {ip}")
    
     # Threat intelligence
     if hasattr(self.analyzer, 'threat_intel') and self.analyzer.threat_intel:
         intel_stats = self.analyzer.threat_intel.get_stats()
         print(f"\n THREAT INTELLIGENCE")
         print(f"   Malicious IPs : {intel_stats.get('malicious_ips', 0)}")
         print(f"   Suspicious IPs: {intel_stats.get('suspicious_ips', 0)}")
    
     # Email alerting
     if self.wazuh.email_alerter:
         print(f"\n EMAIL ALERTING")
         print(f"   Status        : Enabled")
         print(f"   Rate Limit    : {self.wazuh.email_alerter.max_per_hour} emails/hour")
         print(f"   Cooldown      : {self.wazuh.email_alerter.cooldown_minutes} minutes")
    
     # Auto-blocking
     auto_block = self.config.get('auto_block', {})
     if auto_block.get('enabled'):
         print(f"\n AUTO-BLOCKING")
         print(f"   Status        : Enabled")
         print(f"   Block Severity: {', '.join(auto_block.get('block_severity', []))}")
         print(f"   Whitelisted   : {len(auto_block.get('whitelist', []))}")
    
     print("\n" + "="*70)
     print("  System Ready - Monitoring Started")
     print("="*70 + "\n")
    def _load_config(self):
        with open(BASE_PATH / 'config/ids_config.json', 'r') as f:
            return json.load(f)
    
    def extract_features(self, flow_data):
        try:
            fwd_pkts = flow_data['fwd_packets']
            bwd_pkts = flow_data['bwd_packets']
            fwd_iat = flow_data['fwd_iat']
            bwd_iat = flow_data['bwd_iat']
            all_iat = fwd_iat + bwd_iat
            
            fwd_lengths = [p['length'] for p in fwd_pkts]
            bwd_lengths = [p['length'] for p in bwd_pkts]
            duration = flow_data.get('duration', 0.001)
            
            features = {
                'Flow Duration': float(duration * 1000000),
                'Total Fwd Packets': float(len(fwd_pkts)),
                'Total Backward Packets': float(len(bwd_pkts)),
                'Total Length of Fwd Packets': float(sum(fwd_lengths)),
                'Total Length of Bwd Packets': float(sum(bwd_lengths)),
                'Fwd Packet Length Max': float(max(fwd_lengths)) if fwd_lengths else 0.0,
                'Fwd Packet Length Min': float(min(fwd_lengths)) if fwd_lengths else 0.0,
                'Fwd Packet Length Mean': float(np.mean(fwd_lengths)) if fwd_lengths else 0.0,
                'Fwd Packet Length Std': float(np.std(fwd_lengths)) if len(fwd_lengths) > 1 else 0.0,
                'Bwd Packet Length Max': float(max(bwd_lengths)) if bwd_lengths else 0.0,
                'Bwd Packet Length Min': float(min(bwd_lengths)) if bwd_lengths else 0.0,
                'Bwd Packet Length Mean': float(np.mean(bwd_lengths)) if bwd_lengths else 0.0,
                'Bwd Packet Length Std': float(np.std(bwd_lengths)) if len(bwd_lengths) > 1 else 0.0,
                'Flow Bytes/s': float(sum(fwd_lengths + bwd_lengths) / duration) if duration > 0 else 0.0,
                'Flow Packets/s': float((len(fwd_pkts) + len(bwd_pkts)) / duration) if duration > 0 else 0.0,
                'Flow IAT Mean': float(np.mean(all_iat) * 1000000) if all_iat else 0.0,
                'Flow IAT Std': float(np.std(all_iat) * 1000000) if len(all_iat) > 1 else 0.0,
                'Flow IAT Max': float(max(all_iat) * 1000000) if all_iat else 0.0
            }
            return features
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return None
    
    def process_packet(self, packet):
        try:
            from scapy.all import IP, TCP, UDP
            
            if IP not in packet:
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # FILTER INFRASTRUCTURE IPS
            infrastructure_ips = {
             '127.0.0.1',
             '192.168.80.1',
             '192.168.80.2',
             '192.168.80.254',
             '192.168.80.255'
             }
            if not self.infra_filter.should_analyze(src_ip, dst_ip):
              return 
        # Skip if either source or dest is infrastructure
            if src_ip in infrastructure_ips or dst_ip in infrastructure_ips:
             return
         
            if TCP in packet:
                proto = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                proto = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                return
            
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            current_time = time.time()
            
            with self.flow_lock:
                flow = self.flows[flow_key]
                
                if flow['start_time'] is None:
                    flow['start_time'] = current_time
                    flow['src_ip'] = src_ip
                    flow['dst_ip'] = dst_ip
                
                # Forward or backward packet
                if dst_ip == self.target_ip:
                    if flow['last_fwd_time']:
                        flow['fwd_iat'].append(current_time - flow['last_fwd_time'])
                    flow['fwd_packets'].append({'time': current_time, 'length': len(packet)})
                    flow['last_fwd_time'] = current_time
                else:
                    if flow['last_bwd_time']:
                        flow['bwd_iat'].append(current_time - flow['last_bwd_time'])
                    flow['bwd_packets'].append({'time': current_time, 'length': len(packet)})
                    flow['last_bwd_time'] = current_time
                
                flow['duration'] = current_time - flow['start_time']
        
        except Exception as e:
            logger.error(f"Packet processing error: {e}")
    
    def analyze_completed_flows(self):
        """Analyze flows that have been inactive"""
        while True:
            try:
                current_time = time.time()
                completed_flows = []
                
                with self.flow_lock:
                    expired_keys = []
                    for flow_key, flow_data in self.flows.items():
                        if flow_data['start_time'] is None:
                            continue
                        
                        last_activity = max(
                            flow_data.get('last_fwd_time') or 0,
                            flow_data.get('last_bwd_time') or 0,
                            flow_data['start_time']
                        )
                        
                        # Flow inactive for 5 seconds
                        if current_time - last_activity > 5:
                            if len(flow_data['fwd_packets']) > 0 or len(flow_data['bwd_packets']) > 0:
                                completed_flows.append((flow_key, dict(flow_data)))
                            expired_keys.append(flow_key)
                    
                    for key in expired_keys:
                        del self.flows[key]
                
                # Analyze completed flows
                for flow_key, flow_data in completed_flows:
                    features = self.extract_features(flow_data)
                    if features:
                        result = self.analyzer.analyze_flow(features)
                        if result:
                            self.stats['total_flows'] += 1
                            
                            if result['is_threat']:
                                self.stats['threats_detected'] += 1
                                self.wazuh.send_alert(
                                    result,
                                    flow_data.get('src_ip', 'unknown'),
                                    flow_data.get('dst_ip', 'unknown')
                                )
                                
                                # Auto block severe threats
                                if result['severity'] == 'SEVERE':
                                    src_ip = flow_data.get('src_ip', '')
                                    if src_ip and src_ip not in self.stats['ips_blocked']:
                                        self.block_ip(src_ip, result['predicted_attack'])
                
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Flow analysis error: {e}")
                time.sleep(5)
    
    def block_ip(self, ip, reason):
        """Block malicious IP"""
        whitelist = ['127.0.0.1', '192.168.80.1', '192.168.80.128']
        if ip in whitelist:
            return
        
        try:
            import subprocess
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                         check=True, capture_output=True)
            self.stats['ips_blocked'].add(ip)
            logger.warning(f" BLOCKED IP: {ip} - Reason: {reason}")
            
            # Log block
            with open(BASE_PATH / 'logs/blocked_ips.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - BLOCKED: {ip} - {reason}\n")
        except Exception as e:
            logger.error(f"Block failed for {ip}: {e}")
    
    def print_stats(self):
        """Print monitoring statistics"""
        while True:
            time.sleep(30)
            print(f"\n Monitor Stats [{datetime.now().strftime('%H:%M:%S')}]")
            print(f"  Total Flows Analyzed: {self.stats['total_flows']}")
            print(f"  Threats Detected: {self.stats['threats_detected']}")
            print(f"  IPs Blocked: {len(self.stats['ips_blocked'])}")
            if self.stats['ips_blocked']:
                for ip in self.stats['ips_blocked']:
                    print(f"   {ip}")
    
    def start(self):
        """Start live monitoring"""
        try:
            from scapy.all import sniff
            
            # Start flow analyzer thread
            analyzer_thread = threading.Thread(target=self.analyze_completed_flows, daemon=True)
            analyzer_thread.start()
            
            # Start stats thread
            stats_thread = threading.Thread(target=self.print_stats, daemon=True)
            stats_thread.start()
            
            logger.info(f" Live monitoring started on {self.interface}")
            logger.info(f" Monitoring traffic to/from {self.target_ip}")
            logger.info("Press Ctrl+C to stop\n")
            
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                filter=f"host {self.target_ip}",
                store=False
            )
            
        except PermissionError:
            logger.error(" Permission denied - run with sudo!")
            logger.info("Try: sudo python live_monitor.py")
        except KeyboardInterrupt:
            logger.info("\n Monitoring stopped by user")
            logger.info(f"Final Stats:")
            logger.info(f"  Total Flows: {self.stats['total_flows']}")
            logger.info(f"  Threats Detected: {self.stats['threats_detected']}")
            logger.info(f"  IPs Blocked: {len(self.stats['ips_blocked'])}")

def main():
    monitor = LiveMonitor()
    monitor.start()

if __name__ == "__main__":
    main()
