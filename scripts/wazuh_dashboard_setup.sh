#!/bin/bash
# Wazuh Dashboard Setup Helper

echo " Neural Network IDS - Wazuh Dashboard Setup"
echo "=============================================="

# Variables
WAZUH_IP="192.168.80.128"
WAZUH_USER="admin"
WAZUH_PASS="Zt1DiK5v?zG591UJWeO0vdNu1SFFUw6J"

echo ""
echo " Dashboard Access:"
echo "   URL: https://$WAZUH_IP"
echo "   Username: $WAZUH_USER"
echo "   Password: $WAZUH_PASS"

echo ""
echo " Steps to create custom dashboard:"
echo "   1. Login to Wazuh dashboard"
echo "   2. Go to: Visualize Library"
echo "   3. Create visualizations listed above"
echo "   4. Go to: Dashboard"
echo "   5. Create new dashboard"
echo "   6. Add all visualizations"
echo "   7. Save as: 'Neural Network IDS - Security Overview'"

echo ""
echo " Index pattern: wazuh-alerts-*"
echo " Time field: timestamp"
echo "  Filter: rule.groups contains 'neural_ids'"

echo ""
echo " Test by running attacks from Kali VM:"
echo "   nmap -sS 192.168.80.130"
echo "   sudo hping3 -S --flood -p 80 192.168.80.130"

echo ""
echo "=============================================="
