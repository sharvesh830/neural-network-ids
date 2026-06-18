"""
Threat Intelligence Integration
Aggregates data from multiple threat intel sources
"""
import requests
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import hashlib


class ThreatIntelligence:
    """
    Threat Intelligence aggregator from multiple sources
    """
    def __init__(self, config_path='/home/sharvesh/neural_ids/config/ids_config.json'):
        self.base_path = Path('/home/sharvesh/neural_ids')
        self.cache_path = self.base_path / 'data' / 'threat_intel'
        self.cache_path.mkdir(parents=True, exist_ok=True)
        
        # Load config
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.config = config.get('threat_intel', {})
        except:
            self.config = {'enabled': False}
        
        self.enabled = self.config.get('enabled', False)
        
        # Threat databases
        self.malicious_ips = set()
        self.suspicious_ips = set()
        self.known_attacks = defaultdict(list)
        self.ip_reputation = {}
        
        # Cache settings
        self.cache_duration = 3600  # 1 hour
        self.last_update = {}
        
        if self.enabled:
            self._load_threat_feeds()
            print(" Threat Intelligence initialized")
            print(f"   Malicious IPs: {len(self.malicious_ips)}")
            print(f"   Suspicious IPs: {len(self.suspicious_ips)}")
        else:
            print(" Threat Intelligence disabled in config")
    
    def _load_threat_feeds(self):
        """Load threat intelligence from multiple sources"""
        
        # Load from local cache first
        self._load_from_cache()
        
        # Update from sources if cache is old
        sources = self.config.get('sources', [])
        for source in sources:
            if source.get('enabled', False):
                self._fetch_feed(source)
        
        # Load custom blacklist
        self._load_custom_lists()
    
    def _fetch_feed(self, source):
        """Fetch threat feed from external source"""
        source_name = source.get('name', 'unknown')
        url = source.get('url', '')
        feed_type = source.get('type', 'ip_list')
        
        cache_file = self.cache_path / f"{source_name}.json"
        
        # Check cache age
        if cache_file.exists():
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age < self.cache_duration:
                print(f"Using cached feed: {source_name}")
                return
        
        try:
            print(f"Fetching threat feed: {source_name}...")
            
            # Fetch with timeout
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                if feed_type == 'ip_list':
                    self._process_ip_list(response.text, source_name)
                elif feed_type == 'json':
                    self._process_json_feed(response.json(), source_name)
                
                # Cache the feed
                with open(cache_file, 'w') as f:
                    json.dump({
                        'timestamp': time.time(),
                        'data': response.text
                    }, f)
                
                print(f" Updated feed: {source_name}")
            else:
                print(f" Failed to fetch {source_name}: HTTP {response.status_code}")
        
        except requests.exceptions.Timeout:
            print(f" Timeout fetching {source_name}")
        except Exception as e:
            print(f" Error fetching {source_name}: {e}")
    
    def _process_ip_list(self, content, source_name):
        """Process plain text IP list"""
        count = 0
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Extract IP (handle various formats)
            ip = line.split()[0] if ' ' in line else line
            
            # Validate IP format
            if self._is_valid_ip(ip):
                self.malicious_ips.add(ip)
                self.ip_reputation[ip] = {
                    'source': source_name,
                    'threat_level': 'HIGH',
                    'first_seen': datetime.now().isoformat()
                }
                count += 1
        
        print(f"   Loaded {count} IPs from {source_name}")
    
    def _process_json_feed(self, data, source_name):
        """Process JSON threat feed"""
        # Handle different JSON formats
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ip = item.get('ip') or item.get('address')
                    if ip and self._is_valid_ip(ip):
                        self.malicious_ips.add(ip)
                        self.ip_reputation[ip] = {
                            'source': source_name,
                            'threat_level': item.get('severity', 'MEDIUM'),
                            'category': item.get('category', 'unknown')
                        }
    
    def _load_from_cache(self):
        """Load threat data from cache"""
        for cache_file in self.cache_path.glob('*.json'):
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                    
                # Check if cache is still valid
                cache_age = time.time() - cached.get('timestamp', 0)
                if cache_age < self.cache_duration:
                    source_name = cache_file.stem
                    self._process_ip_list(cached.get('data', ''), source_name)
            except:
                pass
    
    def _load_custom_lists(self):
        """Load custom blacklist/whitelist"""
        blacklist_file = self.base_path / 'config' / 'ip_blacklist.txt'
        
        if blacklist_file.exists():
            with open(blacklist_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.malicious_ips.add(ip)
                        self.ip_reputation[ip] = {
                            'source': 'custom_blacklist',
                            'threat_level': 'SEVERE'
                        }
    
    def _is_valid_ip(self, ip):
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def check_ip(self, ip):
        """
        Check if IP is in threat intelligence database
        Returns dict with threat info or None
        """
        if not self.enabled:
            return None
        
        if ip in self.malicious_ips:
            return {
                'is_malicious': True,
                'threat_level': self.ip_reputation.get(ip, {}).get('threat_level', 'HIGH'),
                'source': self.ip_reputation.get(ip, {}).get('source', 'unknown'),
                'reputation_score': 0,  # 0 = bad, 100 = good
                'category': self.ip_reputation.get(ip, {}).get('category', 'malicious_ip')
            }
        
        if ip in self.suspicious_ips:
            return {
                'is_malicious': False,
                'threat_level': 'MEDIUM',
                'source': 'threat_intel',
                'reputation_score': 30,
                'category': 'suspicious'
            }
        
        # Not in threat feeds - likely benign
        return {
            'is_malicious': False,
            'threat_level': 'NONE',
            'reputation_score': 80,
            'category': 'unknown'
        }
    
    def enrich_alert(self, alert, source_ip):
        """
        Enrich alert with threat intelligence data
        """
        if not self.enabled:
            return alert
        
        threat_info = self.check_ip(source_ip)
        
        if threat_info:
            alert['threat_intel'] = threat_info
            
            # Increase severity if IP is known malicious
            if threat_info['is_malicious']:
                if alert.get('severity') != 'SEVERE':
                    alert['severity_boosted'] = True
                    alert['original_severity'] = alert.get('severity')
                    alert['severity'] = 'SEVERE'
                    alert['boost_reason'] = f"IP in threat database: {threat_info['source']}"
        
        return alert
    
    def get_stats(self):
        """Get threat intelligence statistics"""
        return {
            'enabled': self.enabled,
            'malicious_ips': len(self.malicious_ips),
            'suspicious_ips': len(self.suspicious_ips),
            'sources': len(self.config.get('sources', [])),
            'last_update': datetime.now().isoformat()
        }


if __name__ == "__main__":
    # Test
    intel = ThreatIntelligence()
    
    # Test IP check
    test_ips = [
        '192.168.80.132',  # Kali
        '8.8.8.8',         # Google DNS
        '1.2.3.4'          # Random
    ]
    
    for ip in test_ips:
        result = intel.check_ip(ip)
        print(f"\nIP: {ip}")
        print(f"Result: {result}")
    
    # Test alert enrichment
    test_alert = {
        'timestamp': datetime.now().isoformat(),
        'predicted_attack': 'DDoS',
        'confidence': 95.5,
        'severity': 'HIGH',
        'source_ip': '192.168.80.132'
    }
    
    enriched = intel.enrich_alert(test_alert, '192.168.80.132')
    print(f"\nEnriched alert:")
    print(json.dumps(enriched, indent=2))
