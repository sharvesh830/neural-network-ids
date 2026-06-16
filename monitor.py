#!/usr/bin/env python3
import time
from scripts.neural_analyzer import NeuralAnalyzer
from scripts.wazuh_integration import WazuhIntegration

print("="*70)
print("  Neural Network IDS - Real-time Monitor")
print("="*70)

# Initialize
analyzer = NeuralAnalyzer()
wazuh = WazuhIntegration()

print("\n🔍 Monitoring started... (Press Ctrl+C to stop)\n")

# Simulate traffic analysis
test_scenarios = [
    {'name': 'Normal Traffic', 'Flow Duration': 1000, 'Total Fwd Packets': 10},
    {'name': 'DDoS Attack', 'Flow Duration': 50000, 'Total Fwd Packets': 10000, 'Flow Packets/s': 5000},
    {'name': 'Port Scan', 'Flow Duration': 100, 'Total Fwd Packets': 1, 'Total Backward Packets': 0},
]

for scenario in test_scenarios:
    print(f"\n📊 Testing: {scenario['name']}")
    
    # Create full feature vector
    features = {feat: 0.0 for feat in analyzer.features}
    features.update(scenario)
    
    # Analyze
    result = analyzer.analyze_flow(features)
    
    # Send to Wazuh
    wazuh.send_alert(result, '192.168.80.200', '192.168.80.128')
    
    time.sleep(2)

print("\n✅ Test complete!")
