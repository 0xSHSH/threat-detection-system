import smtplib
import json
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Any
import requests
import yaml
import os

class AlertManager:
    def __init__(self, config_path: str = None):
        """Initialize the AlertManager with configuration."""
        self.config = self._load_config(config_path)
        self.setup_logging()
        
    def _load_config(self, config_path: str = None) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'config',
                'config.yml'
            )
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def setup_logging(self):
        """Set up logging configuration."""
        import os
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"alerting_{datetime.now().strftime('%Y%m%d')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def generate_alert(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an alert based on threat detection results."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': self._determine_severity(threat_data),
            'type': self._determine_threat_type(threat_data),
            'details': threat_data,
            'recommended_actions': self._generate_recommendations(threat_data)
        }
        
        self.logger.info(f"Generated alert: {json.dumps(alert, indent=2)}")
        return alert

    def _determine_severity(self, threat_data: Dict[str, Any]) -> str:
        """Determine the severity level of the threat."""
        # Implementation depends on your threat scoring criteria
        if 'threat_scores' in threat_data:
            max_score = max(threat_data['threat_scores'].values())
            if max_score > 0.8:
                return 'CRITICAL'
            elif max_score > 0.6:
                return 'HIGH'
            elif max_score > 0.4:
                return 'MEDIUM'
            else:
                return 'LOW'
        return 'UNKNOWN'

    def _determine_threat_type(self, threat_data: Dict[str, Any]) -> str:
        """Determine the type of threat based on detection results."""
        if 'threats_detected' in threat_data and threat_data['threats_detected']:
            return 'KNOWN_THREAT'
        elif 'anomalies' in threat_data and threat_data['anomalies']:
            return 'ANOMALY'
        elif 'behavioral_clusters' in threat_data:
            return 'BEHAVIORAL'
        return 'UNKNOWN'

    def _generate_recommendations(self, threat_data: Dict[str, Any]) -> List[str]:
        """Generate recommended actions based on the threat type and severity."""
        recommendations = []
        threat_type = self._determine_threat_type(threat_data)
        severity = self._determine_severity(threat_data)
        
        if threat_type == 'KNOWN_THREAT':
            recommendations.extend([
                "Block malicious IPs immediately",
                "Update firewall rules",
                "Scan affected systems for malware"
            ])
        elif threat_type == 'ANOMALY':
            recommendations.extend([
                "Investigate unusual network patterns",
                "Review system logs for suspicious activity",
                "Monitor affected endpoints closely"
            ])
        elif threat_type == 'BEHAVIORAL':
            recommendations.extend([
                "Review user activity logs",
                "Verify user authentication",
                "Check for unauthorized access attempts"
            ])
            
        if severity in ['CRITICAL', 'HIGH']:
            recommendations.extend([
                "Escalate to security team immediately",
                "Consider isolating affected systems",
                "Prepare incident response plan"
            ])
            
        return recommendations

    def send_email_alert(self, alert: Dict[str, Any]) -> None:
        """Send an email alert to configured recipients."""
        try:
            msg = MIMEMultipart()
            msg['Subject'] = f"Security Alert: {alert['type']} - {alert['severity']}"
            msg['From'] = self.config['email']['sender']
            msg['To'] = ", ".join(self.config['email']['recipients'])
            
            # Create the email body
            body = self._format_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send the email
            with smtplib.SMTP(self.config['email']['smtp_server'], self.config['email']['smtp_port']) as server:
                server.starttls()
                server.login(self.config['email']['username'], self.config['email']['password'])
                server.send_message(msg)
                
            self.logger.info(f"Email alert sent successfully to {msg['To']}")
            
        except Exception as e:
            self.logger.error(f"Error sending email alert: {str(e)}")
            raise

    def _format_email_body(self, alert: Dict[str, Any]) -> str:
        """Format the alert information into an HTML email body."""
        return f"""
        <html>
            <body>
                <h2>Security Alert</h2>
                <p><strong>Time:</strong> {alert['timestamp']}</p>
                <p><strong>Severity:</strong> {alert['severity']}</p>
                <p><strong>Type:</strong> {alert['type']}</p>
                
                <h3>Details:</h3>
                <pre>{json.dumps(alert['details'], indent=2)}</pre>
                
                <h3>Recommended Actions:</h3>
                <ul>
                    {''.join(f'<li>{action}</li>' for action in alert['recommended_actions'])}
                </ul>
            </body>
        </html>
        """

    def send_webhook_alert(self, alert: Dict[str, Any]) -> None:
        """Send an alert to configured webhook endpoints (e.g., Slack, Teams)."""
        try:
            for webhook in self.config['webhooks']:
                response = requests.post(
                    webhook['url'],
                    json=self._format_webhook_payload(alert, webhook['type']),
                    headers={'Content-Type': 'application/json'}
                )
                response.raise_for_status()
                self.logger.info(f"Webhook alert sent successfully to {webhook['type']}")
                
        except Exception as e:
            self.logger.error(f"Error sending webhook alert: {str(e)}")
            raise

    def _format_webhook_payload(self, alert: Dict[str, Any], webhook_type: str) -> Dict[str, Any]:
        """Format the alert for different webhook types (Slack, Teams, etc.)."""
        if webhook_type.lower() == 'slack':
            return {
                'text': f"Security Alert: {alert['type']} - {alert['severity']}",
                'blocks': [
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f"*Security Alert*\nType: {alert['type']}\nSeverity: {alert['severity']}"
                        }
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f"*Recommended Actions:*\n" + "\n".join(f"• {action}" for action in alert['recommended_actions'])
                        }
                    }
                ]
            }
        elif webhook_type.lower() == 'teams':
            return {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'summary': f"Security Alert: {alert['type']}",
                'themeColor': self._get_severity_color(alert['severity']),
                'sections': [
                    {
                        'activityTitle': f"Security Alert: {alert['type']}",
                        'facts': [
                            {'name': 'Severity', 'value': alert['severity']},
                            {'name': 'Time', 'value': alert['timestamp']},
                            {'name': 'Recommended Actions', 'value': "\n".join(alert['recommended_actions'])}
                        ]
                    }
                ]
            }
        return alert  # Default format

    def _get_severity_color(self, severity: str) -> str:
        """Get the color code for severity level."""
        colors = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FFA500',
            'MEDIUM': '#FFFF00',
            'LOW': '#00FF00',
            'UNKNOWN': '#808080'
        }
        return colors.get(severity, '#808080')

if __name__ == "__main__":
    # Example usage
    alert_manager = AlertManager()
    
    # Example threat data
    threat_data = {
        'threats_detected': ['192.168.1.100'],
        'threat_scores': {'supervised': 0.85},
        'anomalies': ['unusual_traffic_pattern'],
        'behavioral_clusters': {
            'cluster_1': {'size': 5, 'samples': ['user1', 'user2']}
        }
    }
    
    # Generate and send alert
    alert = alert_manager.generate_alert(threat_data)
    alert_manager.send_email_alert(alert)
    alert_manager.send_webhook_alert(alert)
