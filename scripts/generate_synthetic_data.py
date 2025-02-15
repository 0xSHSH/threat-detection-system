import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
from typing import Dict, List, Any
import yaml
import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

def generate_normal_traffic(num_samples: int) -> pd.DataFrame:
    """Generate normal network traffic patterns"""
    now = datetime.now()
    data = []
    
    protocols = ['TCP', 'UDP', 'ICMP']
    ports = [80, 443, 22, 53, 3389] + random.sample(range(1024, 65535), 10)
    
    for i in range(num_samples):
        timestamp = now + timedelta(seconds=i)
        data.append({
            'timestamp': timestamp,
            'source_ip': f'192.168.1.{random.randint(2, 254)}',
            'dest_ip': f'10.0.0.{random.randint(2, 254)}',
            'protocol': random.choice(protocols),
            'source_port': random.choice(ports),
            'dest_port': random.choice(ports),
            'bytes': int(np.random.lognormal(9, 1)),
            'packets': random.randint(1, 100),
            'duration': random.uniform(0.1, 2.0)
        })
    
    return pd.DataFrame(data)

def generate_attack_traffic(num_samples: int, attack_type: str) -> pd.DataFrame:
    """Generate synthetic attack traffic"""
    normal_traffic = generate_normal_traffic(num_samples)
    
    if attack_type == 'ddos':
        # Simulate DDoS attack
        normal_traffic['bytes'] *= 10
        normal_traffic['packets'] *= 5
        normal_traffic['dest_ip'] = random.choice([f'10.0.0.{i}' for i in range(2, 10)])
        
    elif attack_type == 'port_scan':
        # Simulate port scanning
        normal_traffic['dest_port'] = [random.randint(1, 65535) for _ in range(num_samples)]
        normal_traffic['bytes'] = normal_traffic['bytes'].apply(lambda x: int(x * 0.1))
        normal_traffic['packets'] = 1
        
    elif attack_type == 'data_exfiltration':
        # Simulate data exfiltration
        normal_traffic['bytes'] = normal_traffic['bytes'].apply(lambda x: int(x * 5))
        normal_traffic['dest_ip'] = random.choice([f'external{i}.com' for i in range(1, 5)])
        
    return normal_traffic

def generate_user_activity(num_users: int, days: int) -> pd.DataFrame:
    """Generate synthetic user activity logs"""
    now = datetime.now()
    data = []
    
    activities = ['login', 'logout', 'file_access', 'network_access', 'admin_action']
    
    for day in range(days):
        for user in range(num_users):
            num_activities = random.randint(5, 15)
            for _ in range(num_activities):
                hour = random.randint(9, 17)  # Business hours
                minute = random.randint(0, 59)
                timestamp = now - timedelta(days=day, hours=24-hour, minutes=minute)
                
                data.append({
                    'timestamp': timestamp,
                    'user_id': f'user_{user}',
                    'activity': random.choice(activities),
                    'resource': f'resource_{random.randint(1, 10)}',
                    'status': 'success' if random.random() > 0.1 else 'failed'
                })
    
    return pd.DataFrame(data)

def generate_system_logs(num_samples: int) -> pd.DataFrame:
    """Generate synthetic system logs"""
    now = datetime.now()
    data = []
    
    log_levels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
    components = ['firewall', 'ids', 'authentication', 'database', 'web_server']
    
    for i in range(num_samples):
        timestamp = now - timedelta(minutes=random.randint(0, 60))
        level = random.choice(log_levels)
        
        data.append({
            'timestamp': timestamp,
            'level': level,
            'component': random.choice(components),
            'message': f'Sample log message for {level}',
            'source_ip': f'192.168.1.{random.randint(2, 254)}' if random.random() > 0.5 else None
        })
    
    return pd.DataFrame(data)

def main():
    # Load configuration
    with open(project_root / 'config' / 'config.yml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Create data directory if it doesn't exist
    data_dir = project_root / 'data'
    data_dir.mkdir(exist_ok=True)
    
    # Generate datasets
    print("Generating normal traffic data...")
    normal_traffic = generate_normal_traffic(1000)
    normal_traffic.to_csv(data_dir / 'normal_traffic.csv', index=False)
    
    print("Generating attack traffic data...")
    for attack_type in ['ddos', 'port_scan', 'data_exfiltration']:
        attack_traffic = generate_attack_traffic(200, attack_type)
        attack_traffic.to_csv(data_dir / f'{attack_type}_traffic.csv', index=False)
    
    print("Generating user activity logs...")
    user_activity = generate_user_activity(10, 7)  # 10 users, 7 days
    user_activity.to_csv(data_dir / 'user_activity.csv', index=False)
    
    print("Generating system logs...")
    system_logs = generate_system_logs(500)
    system_logs.to_csv(data_dir / 'system_logs.csv', index=False)
    
    print("Data generation complete!")

if __name__ == "__main__":
    main()
