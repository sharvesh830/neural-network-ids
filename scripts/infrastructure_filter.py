"""
Infrastructure Traffic Filter
Prevents false positives from network infrastructure
"""

class InfrastructureFilter:
    """
    Filter to exclude known infrastructure IPs
    """
    def __init__(self):
        # VMware NAT Network Infrastructure
        self.infrastructure_ips = {
            '127.0.0.1',        # Localhost
            '192.168.80.1',     # VMware virtual adapter
            '192.168.80.2',     # VMware NAT gateway
            '192.168.80.128',   # Ubuntu SIEM (self)
            '192.168.80.254',   # VMware DHCP server
            '192.168.80.255'    # Broadcast address
        }
        
        # Well-known safe services
        self.safe_services = {
            '8.8.8.8',          # Google DNS
            '8.8.4.4',          # Google DNS secondary
            '1.1.1.1'           # Cloudflare DNS
        }
        
    def is_infrastructure(self, ip):
        """Check if IP is infrastructure"""
        return ip in self.infrastructure_ips
    
    def is_safe_service(self, ip):
        """Check if IP is known safe service"""
        return ip in self.safe_services
    
    def should_analyze(self, src_ip, dst_ip):
        """
        Determine if traffic should be analyzed
        Returns True if should analyze, False if should skip
        """
        # Skip if either end is infrastructure
        if self.is_infrastructure(src_ip) or self.is_infrastructure(dst_ip):
            return False
        
        # Skip if either end is known safe service
        if self.is_safe_service(src_ip) or self.is_safe_service(dst_ip):
            return False
        
        # Analyze everything else
        return True
    
    def get_infrastructure_list(self):
        """Get list of all infrastructure IPs"""
        return list(self.infrastructure_ips)


if __name__ == "__main__":
    # Test
    filter = InfrastructureFilter()
    
    test_cases = [
        ('192.168.80.132', '192.168.80.130', True),   # Kali -> Win10 (analyze)
        ('192.168.80.254', '192.168.80.130', False),  # DHCP -> Win10 (skip)
        ('192.168.80.2', '8.8.8.8', False),           # Gateway -> DNS (skip)
        ('192.168.80.128', '192.168.80.130', False),  # Self -> Win10 (skip)
    ]
    
    for src, dst, expected in test_cases:
        result = filter.should_analyze(src, dst)
        status = "" if result == expected else ""
        print(f"{status} {src} → {dst}: Analyze={result} (Expected={expected})")
