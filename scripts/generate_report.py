#!/usr/bin/env python3
"""
Generate comprehensive system report
"""
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter

BASE_PATH = Path('/home/sharvesh/neural_ids')

def generate_report():
    print("="*70)
    print("  NEURAL NETWORK IDS - SYSTEM REPORT")
    print("="*70)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Load model metadata
    with open(BASE_PATH / 'models/model_metadata.json', 'r') as f:
        metadata = json.load(f)
    
    print("📊 MODEL INFORMATION")
    print("-" * 70)
    print(f"Input Features: {metadata['input_dim']}")
    print(f"Attack Classes: {metadata['num_classes']}")
    print(f"Anomaly Threshold: {metadata['anomaly_threshold']:.6f}")
    print(f"\nAttack Types Detected:")
    for i, cls in enumerate(metadata['classes'], 1):
        print(f"  {i:2d}. {cls}")
    
    # Analyze alert logs
    print(f"\n📈 DETECTION STATISTICS")
    print("-" * 70)
    
    alerts_file = BASE_PATH / 'logs/neural_alerts.json'
    
    if alerts_file.exists():
        with open(alerts_file, 'r') as f:
            alerts = [json.loads(line) for line in f if line.strip()]
        
        total_alerts = len(alerts)
        
        # Count by severity
        severities = Counter(a['neural_ids']['severity'] for a in alerts)
        
        # Count by attack type
        attacks = Counter(a['neural_ids']['predicted_attack'] for a in alerts)
        
        # Count unique source IPs
        source_ips = set(a['neural_ids'].get('source_ip', 'unknown') for a in alerts)
        
        # Anomalies
        anomalies = sum(1 for a in alerts if a['neural_ids'].get('is_anomaly', False))
        
        print(f"Total Alerts Generated: {total_alerts}")
        print(f"Unique Attacker IPs: {len(source_ips)}")
        print(f"Anomalies Detected: {anomalies} ({anomalies/total_alerts*100:.1f}%)")
        
        print(f"\nAlerts by Severity:")
        for severity, count in severities.most_common():
            percentage = count/total_alerts*100
            print(f"  {severity:8s}: {count:4d} ({percentage:5.1f}%)")
        
        print(f"\nTop 10 Attack Types:")
        for attack, count in attacks.most_common(10):
            percentage = count/total_alerts*100
            print(f"  {attack:30s}: {count:4d} ({percentage:5.1f}%)")
        
        print(f"\nTop Attacker IPs:")
        ip_counts = Counter(a['neural_ids'].get('source_ip', 'unknown') for a in alerts)
        for ip, count in ip_counts.most_common(5):
            print(f"  {ip:20s}: {count:4d} attacks")
        
        # Average confidence
        confidences = [a['neural_ids']['confidence'] for a in alerts]
        avg_conf = sum(confidences) / len(confidences)
        print(f"\nAverage Detection Confidence: {avg_conf:.2f}%")
    
    else:
        print("No alerts logged yet")
    
    # Check blocked IPs
    blocked_file = BASE_PATH / 'logs/blocked_ips.log'
    if blocked_file.exists():
        with open(blocked_file, 'r') as f:
            blocked = f.readlines()
        
        print(f"\n🚫 BLOCKED IPS")
        print("-" * 70)
        print(f"Total IPs Blocked: {len(blocked)}")
        if blocked:
            print("\nRecent Blocks:")
            for line in blocked[-10:]:
                print(f"  {line.strip()}")
    
    # System capabilities
    print(f"\n⚙️  SYSTEM CAPABILITIES")
    print("-" * 70)
    print("✅ Real-time traffic monitoring")
    print("✅ Neural network classification (2-stage)")
    print("✅ Anomaly detection with autoencoder")
    print("✅ Wazuh SIEM integration")
    print("✅ Email alert notifications")
    print("✅ Threat intelligence enrichment")
    print("✅ Automatic IP blocking")
    print("✅ Multi-severity classification")
    print("✅ Rate-limited alerting")
    
    print("\n" + "="*70)
    print("  Report Complete")
    print("="*70)

if __name__ == "__main__":
    generate_report()
