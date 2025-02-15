import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Any, Tuple
import logging
from datetime import datetime, timedelta

class BehavioralAnalytics:
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.scaler = StandardScaler()
        self.dbscan = DBSCAN(eps=0.3, min_samples=5)
        self.user_profiles = {}
        self.activity_history = {}
        
    def extract_behavioral_features(self, network_data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract behavioral features from network data
        """
        features = pd.DataFrame()
        
        # Time-based features
        features['hour_of_day'] = pd.to_datetime(network_data['timestamp']).dt.hour
        features['is_weekend'] = pd.to_datetime(network_data['timestamp']).dt.weekday >= 5
        
        # Traffic volume features
        features['bytes_sent'] = network_data['bytes_sent']
        features['bytes_received'] = network_data['bytes_received']
        features['packets_per_second'] = network_data.groupby('source_ip')['packets'].transform('count')
        
        # Protocol distribution
        protocol_dist = pd.get_dummies(network_data['protocol'], prefix='protocol')
        features = pd.concat([features, protocol_dist], axis=1)
        
        # Port usage patterns
        features['distinct_ports'] = network_data.groupby('source_ip')['dest_port'].transform('nunique')
        features['high_port_ratio'] = (network_data['dest_port'] > 1024).astype(int)
        
        return features
        
    def update_user_profile(self, user_id: str, current_behavior: pd.Series):
        """
        Update user behavioral profile
        """
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                'avg_bytes_sent': current_behavior['bytes_sent'],
                'avg_bytes_received': current_behavior['bytes_received'],
                'common_hours': [current_behavior['hour_of_day']],
                'typical_protocols': set(current_behavior.filter(like='protocol_').index),
                'update_count': 1
            }
        else:
            profile = self.user_profiles[user_id]
            n = profile['update_count']
            
            # Update moving averages
            profile['avg_bytes_sent'] = (profile['avg_bytes_sent'] * n + current_behavior['bytes_sent']) / (n + 1)
            profile['avg_bytes_received'] = (profile['avg_bytes_received'] * n + current_behavior['bytes_received']) / (n + 1)
            
            # Update common hours
            if current_behavior['hour_of_day'] not in profile['common_hours']:
                profile['common_hours'].append(current_behavior['hour_of_day'])
            
            # Update protocol preferences
            current_protocols = set(current_behavior.filter(like='protocol_').index)
            profile['typical_protocols'].update(current_protocols)
            
            profile['update_count'] += 1
    
    def detect_anomalies(self, user_id: str, current_behavior: pd.Series) -> Dict[str, Any]:
        """
        Detect behavioral anomalies for a user
        """
        if user_id not in self.user_profiles:
            return {'is_anomaly': False, 'reason': 'Insufficient history'}
            
        profile = self.user_profiles[user_id]
        anomalies = []
        
        # Check for unusual traffic volume
        if (current_behavior['bytes_sent'] > profile['avg_bytes_sent'] * 3 or
            current_behavior['bytes_received'] > profile['avg_bytes_received'] * 3):
            anomalies.append('Unusual traffic volume')
            
        # Check for unusual hour of activity
        if current_behavior['hour_of_day'] not in profile['common_hours']:
            anomalies.append('Unusual time of activity')
            
        # Check for unusual protocols
        current_protocols = set(current_behavior.filter(like='protocol_').index)
        unusual_protocols = current_protocols - profile['typical_protocols']
        if unusual_protocols:
            anomalies.append(f'Unusual protocols: {unusual_protocols}')
            
        return {
            'is_anomaly': len(anomalies) > 0,
            'anomalies': anomalies,
            'confidence': min(len(anomalies) / 3, 1.0)
        }
        
    def analyze_behavior_patterns(self, network_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze network behavior patterns and detect anomalies
        """
        features = self.extract_behavioral_features(network_data)
        scaled_features = self.scaler.fit_transform(features)
        
        # Cluster behaviors
        clusters = self.dbscan.fit_predict(scaled_features)
        
        # Analyze each user's behavior
        results = []
        for user_id in network_data['source_ip'].unique():
            user_data = features[network_data['source_ip'] == user_id].iloc[0]
            
            # Update user profile
            self.update_user_profile(user_id, user_data)
            
            # Detect anomalies
            anomaly_results = self.detect_anomalies(user_id, user_data)
            
            results.append({
                'user_id': user_id,
                'cluster': clusters[network_data['source_ip'] == user_id].iloc[0],
                'anomaly_detection': anomaly_results
            })
            
        return {
            'behavior_clusters': len(set(clusters)) - (1 if -1 in clusters else 0),
            'anomalous_users': sum(1 for r in results if r['anomaly_detection']['is_anomaly']),
            'user_results': results
        }
        
    def generate_behavioral_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate a detailed behavioral analysis report
        """
        report = []
        report.append("# Network Behavior Analysis Report")
        report.append(f"\n## Overview")
        report.append(f"- Number of behavior clusters: {analysis_results['behavior_clusters']}")
        report.append(f"- Number of anomalous users: {analysis_results['anomalous_users']}")
        
        report.append("\n## Detailed User Analysis")
        for result in analysis_results['user_results']:
            report.append(f"\n### User: {result['user_id']}")
            report.append(f"- Behavior Cluster: {result['cluster']}")
            if result['anomaly_detection']['is_anomaly']:
                report.append("- Anomalies Detected:")
                for anomaly in result['anomaly_detection']['anomalies']:
                    report.append(f"  * {anomaly}")
                report.append(f"- Confidence: {result['anomaly_detection']['confidence']:.2f}")
                
        return "\n".join(report)
