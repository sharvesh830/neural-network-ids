import smtplib
import json
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from collections import defaultdict

class SmartEmailAlerter:
    """
    Intelligent email alerting with rate limiting and aggregation
    """
    def __init__(self, config_path='/home/sharvesh/neural_ids/config/ids_config.json'):
        with open(config_path, 'r') as f:
            self.config = json.load(f)['email']
        
        self.enabled = self.config.get('enabled', False)
        
        if not self.enabled:
            print("📧 Email alerts disabled in config")
            return
        
        # Rate limiting
        self.max_per_hour = self.config['rate_limit']['max_emails_per_hour']
        self.cooldown_minutes = self.config['rate_limit']['cooldown_minutes']
        self.aggregate_window = self.config['rate_limit']['aggregate_window_minutes']
        
        # Tracking
        self.email_history = []  # List of timestamps
        self.last_alert_time = defaultdict(lambda: datetime.min)  # Per attack type
        self.pending_alerts = []  # For aggregation
        self.last_aggregate_time = datetime.now()
        
        print(f"✅ Email alerter initialized")
        print(f"   Rate limit: {self.max_per_hour} emails/hour")
        print(f"   Cooldown: {self.cooldown_minutes} minutes per attack type")
        print(f"   Aggregation window: {self.aggregate_window} minutes")
    
    def should_send_alert(self, alert):
        """
        Determine if alert should trigger email based on rules
        """
        if not self.enabled:
            return False
        
        # Check severity threshold
        severity_levels = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'SEVERE']
        min_severity = self.config.get('min_severity', 'HIGH')
        
        alert_level = severity_levels.index(alert['severity']) if alert['severity'] in severity_levels else 0
        min_level = severity_levels.index(min_severity) if min_severity in severity_levels else 3
        
        if alert_level < min_level:
            return False
        
        # Check hourly rate limit
        now = datetime.now()
        one_hour_ago = now - timedelta(hours=1)
        
        # Clean old history
        self.email_history = [ts for ts in self.email_history if ts > one_hour_ago]
        
        if len(self.email_history) >= self.max_per_hour:
            print(f"⚠️ Email rate limit reached ({self.max_per_hour}/hour)")
            return False
        
        # Check cooldown for this attack type
        attack_type = alert['predicted_attack']
        last_sent = self.last_alert_time[attack_type]
        cooldown_period = now - timedelta(minutes=self.cooldown_minutes)
        
        if last_sent > cooldown_period:
            minutes_ago = (now - last_sent).total_seconds() / 60
            print(f"⚠️ {attack_type} in cooldown ({minutes_ago:.1f} min ago)")
            return False
        
        return True
    
    def aggregate_alerts(self, alert):
        """
        Add alert to pending list for aggregation
        """
        self.pending_alerts.append(alert)
        
        # Check if aggregation window expired
        now = datetime.now()
        window_expired = (now - self.last_aggregate_time).total_seconds() > (self.aggregate_window * 60)
        
        # Send if severe alert or window expired with pending alerts
        if alert['severity'] == 'SEVERE' or (window_expired and len(self.pending_alerts) > 0):
            self.send_aggregated_email()
            self.pending_alerts = []
            self.last_aggregate_time = now
    
    def send_email(self, alert):
        """
        Send individual email alert
        """
        if not self.should_send_alert(alert):
            return False
        
        # Add to aggregation instead
        self.aggregate_alerts(alert)
        return True
    
    def send_aggregated_email(self):
        """
        Send email with aggregated alerts
        """
        if len(self.pending_alerts) == 0:
            return False
        
        try:
            # Count alerts by severity
            severe = [a for a in self.pending_alerts if a['severity'] == 'SEVERE']
            high = [a for a in self.pending_alerts if a['severity'] == 'HIGH']
            
            # Unique attack types
            attack_types = set(a['predicted_attack'] for a in self.pending_alerts)
            
            # Create email
            msg = MIMEMultipart('alternative')
            
            # Subject
            if len(severe) > 0:
                msg['Subject'] = f"🚨 {len(severe)} SEVERE THREATS Detected - Neural IDS"
            else:
                msg['Subject'] = f"⚠️ {len(high)} HIGH Threats Detected - Neural IDS"
            
            msg['From'] = self.config['sender_email']
            msg['To'] = self.config['recipient_email']
            
            # HTML body
            html_body = self._create_html_email(self.pending_alerts)
            
            # Text body
            text_body = self._create_text_email(self.pending_alerts)
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['sender_email'], self.config['sender_password'])
                server.send_message(msg)
            
            # Update tracking
            now = datetime.now()
            self.email_history.append(now)
            
            for alert in self.pending_alerts:
                self.last_alert_time[alert['predicted_attack']] = now
            
            print(f"📧 Email sent: {len(self.pending_alerts)} alerts aggregated")
            print(f"   SEVERE: {len(severe)}, HIGH: {len(high)}")
            
            return True
            
        except Exception as e:
            print(f"❌ Email failed: {e}")
            return False
    
    def _create_html_email(self, alerts):
        """Create HTML email body"""
        
        # Count by severity
        severe = [a for a in alerts if a['severity'] == 'SEVERE']
        high = [a for a in alerts if a['severity'] == 'HIGH']
        
        # Unique IPs
        source_ips = set(a.get('source_ip', 'unknown') for a in alerts)
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #d32f2f; color: white; padding: 20px; text-align: center; }}
                .summary {{ background-color: #fff3e0; padding: 15px; margin: 10px 0; }}
                .alert {{ border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; background: #ffebee; }}
                .severe {{ border-left-color: #d32f2f; background: #ffcdd2; }}
                .high {{ border-left-color: #ff6f00; background: #ffe0b2; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🚨 Neural Network IDS - Threat Alert</h2>
                <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h3>Alert Summary</h3>
                <table>
                    <tr><th>Total Alerts</th><td>{len(alerts)}</td></tr>
                    <tr><th>SEVERE</th><td style="color: #d32f2f; font-weight: bold;">{len(severe)}</td></tr>
                    <tr><th>HIGH</th><td style="color: #ff6f00; font-weight: bold;">{len(high)}</td></tr>
                    <tr><th>Attacker IPs</th><td>{', '.join(source_ips)}</td></tr>
                </table>
            </div>
            
            <h3>Detected Threats</h3>
        """
        
        # Add individual alerts (max 10)
        for alert in alerts[:10]:
            severity_class = 'severe' if alert['severity'] == 'SEVERE' else 'high'
            html += f"""
            <div class="alert {severity_class}">
                <table>
                    <tr><th>Attack Type</th><td>{alert['predicted_attack']}</td></tr>
                    <tr><th>Severity</th><td>{alert['severity']}</td></tr>
                    <tr><th>Confidence</th><td>{alert['confidence']}%</td></tr>
                    <tr><th>Source IP</th><td>{alert.get('source_ip', 'unknown')}</td></tr>
                    <tr><th>Target IP</th><td>{alert.get('dest_ip', 'unknown')}</td></tr>
                    <tr><th>Timestamp</th><td>{alert['timestamp']}</td></tr>
                    <tr><th>Anomaly</th><td>{'YES' if alert.get('is_anomaly') else 'NO'}</td></tr>
                </table>
            </div>
            """
        
        if len(alerts) > 10:
            html += f"<p><em>... and {len(alerts) - 10} more alerts</em></p>"
        
        html += """
            <div style="margin-top: 20px; padding: 15px; background: #e3f2fd;">
                <p><strong>Action Required:</strong></p>
                <ul>
                    <li>Review alerts in Wazuh dashboard: https://192.168.80.128</li>
                    <li>Check blocked IPs and firewall rules</li>
                    <li>Investigate source of attacks</li>
                    <li>Update security policies if needed</li>
                </ul>
            </div>
            
            <div style="margin-top: 20px; text-align: center; color: #666; font-size: 12px;">
                <p>This alert was generated by Neural Network IDS</p>
                <p>Ubuntu SIEM: 192.168.80.128</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_text_email(self, alerts):
        """Create plain text email body"""
        
        severe = len([a for a in alerts if a['severity'] == 'SEVERE'])
        high = len([a for a in alerts if a['severity'] == 'HIGH'])
        
        text = f"""
NEURAL NETWORK IDS - THREAT ALERT
================================
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
-------
Total Alerts: {len(alerts)}
SEVERE: {severe}
HIGH: {high}

DETECTED THREATS
----------------
"""
        
        for i, alert in enumerate(alerts[:10], 1):
            text += f"""
Alert #{i}:
  Attack Type: {alert['predicted_attack']}
  Severity: {alert['severity']}
  Confidence: {alert['confidence']}%
  Source IP: {alert.get('source_ip', 'unknown')}
  Target IP: {alert.get('dest_ip', 'unknown')}
  Timestamp: {alert['timestamp']}
  Anomaly: {'YES' if alert.get('is_anomaly') else 'NO'}

"""
        
        if len(alerts) > 10:
            text += f"... and {len(alerts) - 10} more alerts\n\n"
        
        text += """
ACTION REQUIRED
---------------
- Review alerts in Wazuh dashboard: https://192.168.80.128
- Check blocked IPs and firewall rules
- Investigate source of attacks

---
Neural Network IDS - Ubuntu SIEM: 192.168.80.128
"""
        
        return text

if __name__ == "__main__":
    # Test
    alerter = SmartEmailAlerter()
    
    test_alert = {
        'timestamp': datetime.now().isoformat(),
        'predicted_attack': 'DDoS',
        'confidence': 98.5,
        'severity': 'SEVERE',
        'is_anomaly': True,
        'is_threat': True,
        'source_ip': '192.168.80.132',
        'dest_ip': '192.168.80.130'
    }
    
    print("\n🧪 Sending test email...")
    alerter.send_email(test_alert)
