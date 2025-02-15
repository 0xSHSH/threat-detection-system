import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from typing import Dict, Any, List
import logging
from pathlib import Path
from datetime import datetime

class ThreatVisualizer:
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.output_dir = Path(config.get('visualization', {}).get('output_dir', 'visualizations'))
        self.output_dir.mkdir(exist_ok=True)
        
    def plot_traffic_flow(self, data: pd.DataFrame, save: bool = True) -> None:
        """
        Plot network traffic flow patterns
        """
        plt.figure(figsize=(12, 6))
        sns.lineplot(data=data, x='timestamp', y='bytes', hue='protocol')
        plt.title('Network Traffic Flow Over Time')
        plt.xlabel('Time')
        plt.ylabel('Bytes')
        
        if save:
            plt.savefig(self.output_dir / 'traffic_flow_plot.png')
        plt.close()
        
    def plot_threat_distribution(self, threats: pd.DataFrame, save: bool = True) -> None:
        """
        Plot distribution of detected threats
        """
        plt.figure(figsize=(10, 6))
        sns.countplot(data=threats, x='threat_type')
        plt.title('Distribution of Detected Threats')
        plt.xticks(rotation=45)
        
        if save:
            plt.savefig(self.output_dir / 'threat_distribution.png')
        plt.close()
        
    def plot_anomaly_scores(self, scores: np.ndarray, threshold: float, save: bool = True) -> None:
        """
        Plot anomaly scores with threshold
        """
        plt.figure(figsize=(12, 6))
        plt.plot(scores, label='Anomaly Score')
        plt.axhline(y=threshold, color='r', linestyle='--', label='Threshold')
        plt.title('Anomaly Scores Over Time')
        plt.xlabel('Sample')
        plt.ylabel('Score')
        plt.legend()
        
        if save:
            plt.savefig(self.output_dir / 'anomaly_scores.png')
        plt.close()
        
    def create_protocol_heatmap(self, protocol_matrix: pd.DataFrame, save: bool = True) -> None:
        """
        Create heatmap of protocol interactions
        """
        plt.figure(figsize=(12, 10))
        sns.heatmap(protocol_matrix, annot=True, cmap='YlOrRd')
        plt.title('Protocol Interaction Heatmap')
        
        if save:
            plt.savefig(self.output_dir / 'protocol_heatmap.png')
        plt.close()
        
    def plot_feature_importance(self, features: List[str], importance: np.ndarray, save: bool = True) -> None:
        """
        Plot feature importance from the model
        """
        plt.figure(figsize=(12, 6))
        importance_df = pd.DataFrame({'feature': features, 'importance': importance})
        importance_df = importance_df.sort_values('importance', ascending=True)
        
        plt.barh(importance_df['feature'], importance_df['importance'])
        plt.title('Feature Importance')
        plt.xlabel('Importance')
        
        if save:
            plt.savefig(self.output_dir / 'feature_importance.png')
        plt.close()
        
    def create_threat_timeline(self, threats: pd.DataFrame, save: bool = True) -> None:
        """
        Create timeline visualization of threats
        """
        plt.figure(figsize=(15, 6))
        
        # Create scatter plot of threats
        plt.scatter(threats['timestamp'], threats['severity'], 
                   c=threats['severity'], cmap='YlOrRd', 
                   s=100, alpha=0.6)
        
        plt.title('Threat Timeline')
        plt.xlabel('Time')
        plt.ylabel('Severity')
        plt.colorbar(label='Severity')
        
        if save:
            plt.savefig(self.output_dir / 'threat_timeline.png')
        plt.close()
        
    def create_dashboard(self, data: Dict[str, Any]) -> None:
        """
        Create a comprehensive dashboard with multiple plots
        """
        plt.style.use('seaborn')
        fig = plt.figure(figsize=(20, 15))
        
        # Traffic flow
        ax1 = plt.subplot(3, 2, 1)
        sns.lineplot(data=data['traffic'], x='timestamp', y='bytes', ax=ax1)
        ax1.set_title('Network Traffic')
        
        # Threat distribution
        ax2 = plt.subplot(3, 2, 2)
        sns.countplot(data=data['threats'], x='threat_type', ax=ax2)
        ax2.set_title('Threat Distribution')
        ax2.tick_params(axis='x', rotation=45)
        
        # Anomaly scores
        ax3 = plt.subplot(3, 2, 3)
        ax3.plot(data['anomaly_scores'])
        ax3.set_title('Anomaly Scores')
        
        # Protocol distribution
        ax4 = plt.subplot(3, 2, 4)
        sns.heatmap(data['protocol_matrix'], annot=True, cmap='YlOrRd', ax=ax4)
        ax4.set_title('Protocol Distribution')
        
        # Feature importance
        ax5 = plt.subplot(3, 2, (5, 6))
        feature_importance = pd.DataFrame({
            'feature': data['features'],
            'importance': data['importance']
        }).sort_values('importance', ascending=True)
        ax5.barh(feature_importance['feature'], feature_importance['importance'])
        ax5.set_title('Feature Importance')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'dashboard.png')
        plt.close()
        
    def generate_html_report(self, data: Dict[str, Any], output_file: str) -> None:
        """
        Generate an HTML report with all visualizations
        """
        # Create all visualizations
        self.plot_traffic_flow(data['traffic'])
        self.plot_threat_distribution(data['threats'])
        self.plot_anomaly_scores(data['anomaly_scores'], data['threshold'])
        self.create_protocol_heatmap(data['protocol_matrix'])
        self.plot_feature_importance(data['features'], data['importance'])
        self.create_threat_timeline(data['threats'])
        self.create_dashboard(data)
        
        # Generate HTML
        html_content = f"""
        <html>
        <head>
            <title>Threat Detection Report - {datetime.now().strftime('%Y-%m-%d')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .visualization {{ margin: 20px 0; text-align: center; }}
                img {{ max-width: 100%; }}
            </style>
        </head>
        <body>
            <h1>Threat Detection Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="visualization">
                <h2>Dashboard Overview</h2>
                <img src="dashboard.png" alt="Dashboard">
            </div>
            
            <div class="visualization">
                <h2>Network Traffic Flow</h2>
                <img src="traffic_flow_plot.png" alt="Traffic Flow">
            </div>
            
            <div class="visualization">
                <h2>Threat Distribution</h2>
                <img src="threat_distribution.png" alt="Threat Distribution">
            </div>
            
            <div class="visualization">
                <h2>Anomaly Scores</h2>
                <img src="anomaly_scores.png" alt="Anomaly Scores">
            </div>
            
            <div class="visualization">
                <h2>Protocol Interaction Heatmap</h2>
                <img src="protocol_heatmap.png" alt="Protocol Heatmap">
            </div>
            
            <div class="visualization">
                <h2>Feature Importance</h2>
                <img src="feature_importance.png" alt="Feature Importance">
            </div>
            
            <div class="visualization">
                <h2>Threat Timeline</h2>
                <img src="threat_timeline.png" alt="Threat Timeline">
            </div>
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html_content)
