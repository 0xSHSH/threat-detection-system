import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from sklearn.cluster import DBSCAN
from sklearn.model_selection import GridSearchCV
import logging
from typing import Dict, Any, Tuple
import json

class ThreatDetector:
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the ThreatDetector with hybrid ML approach.
        
        Args:
            config: Configuration dictionary containing model parameters
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Initialize supervised model (Random Forest)
        self.rf_model = self._init_random_forest()
        
        # Initialize unsupervised models
        self.autoencoder = self._init_autoencoder()
        self.dbscan = DBSCAN(eps=0.3, min_samples=10)
        
        # Initialize the scaler
        self.scaler = StandardScaler()
        
        # Simple threat patterns
        self.threat_patterns = {
            'ddos': {
                'threshold': 1000,  # packets per second
                'window': '1min'
            },
            'port_scan': {
                'threshold': 50,    # unique ports
                'window': '30s'
            }
        }

    def _init_random_forest(self) -> RandomForestClassifier:
        """Initialize and optimize Random Forest model"""
        rf = RandomForestClassifier(random_state=42)
        param_grid = {
            'n_estimators': [100, 200],
            'max_depth': [10, 20],
            'min_samples_split': [2, 5]
        }
        return GridSearchCV(rf, param_grid, cv=5)
        
    def _init_autoencoder(self) -> tf.keras.Model:
        """Initialize autoencoder for anomaly detection"""
        input_dim = self.config.get('feature_dim', 30)
        
        encoder = tf.keras.Sequential([
            tf.keras.layers.Dense(input_dim, activation="relu"),
            tf.keras.layers.Dense(16, activation="relu"),
            tf.keras.layers.Dense(8, activation="relu")
        ])
        
        decoder = tf.keras.Sequential([
            tf.keras.layers.Dense(16, activation="relu"),
            tf.keras.layers.Dense(input_dim, activation="sigmoid")
        ])
        
        autoencoder = tf.keras.Sequential([encoder, decoder])
        autoencoder.compile(optimizer='adam', loss='mse')
        return autoencoder

    def train_model(self, X: pd.DataFrame, y: np.ndarray) -> None:
        """
        Train the threat detection model.
        
        Args:
            X: Feature matrix
            y: Target labels (0 for normal, 1 for threat)
        """
        try:
            # Scale the features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the Random Forest model
            self.rf_model.fit(X_scaled, y)
            
            # Train the autoencoder
            self.autoencoder.fit(X_scaled, X_scaled, epochs=50, batch_size=32, verbose=0)
            
            self.logger.info("Model trained successfully")
            
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            raise

    def detect_threats(self, data: pd.DataFrame) -> Dict[str, Any]:
        """
        Detect threats in network traffic data.
        
        Args:
            data: Network traffic data
            
        Returns:
            Dictionary containing detection results
        """
        try:
            # Scale the features
            X_scaled = self.scaler.transform(data)
            
            # Get threat probabilities from Random Forest
            threat_probs_rf = self.rf_model.predict_proba(X_scaled)[:, 1]
            
            # Get reconstruction error from autoencoder
            recon_error = np.mean((X_scaled - self.autoencoder.predict(X_scaled)) ** 2, axis=1)
            
            # Detect threats based on probability threshold
            threats_detected_rf = threat_probs_rf > 0.5
            
            # Detect anomalies using DBSCAN
            self.dbscan.fit(X_scaled)
            threats_detected_dbscan = self.dbscan.labels_ == -1
            
            # Combine detection results
            threats_detected = np.logical_or(threats_detected_rf, threats_detected_dbscan)
            
            # Check for specific patterns
            patterns = self._check_patterns(data)
            
            return {
                'threats_detected': threats_detected,
                'threat_probabilities_rf': threat_probs_rf,
                'reconstruction_error': recon_error,
                'patterns_detected': patterns
            }
            
        except Exception as e:
            self.logger.error(f"Error detecting threats: {str(e)}")
            raise

    def _check_patterns(self, data: pd.DataFrame) -> Dict[str, bool]:
        """
        Check for specific threat patterns in the data.
        
        Args:
            data: Network traffic data
            
        Returns:
            Dictionary of detected patterns
        """
        patterns = {}
        
        try:
            # Check for DDoS
            if 'packets_per_second' in data.columns:
                patterns['ddos'] = any(
                    data['packets_per_second'] > self.threat_patterns['ddos']['threshold']
                )
            
            # Check for port scan
            if 'dst_port' in data.columns:
                patterns['port_scan'] = (
                    data['dst_port'].nunique() > self.threat_patterns['port_scan']['threshold']
                )
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error checking patterns: {str(e)}")
            return {}

if __name__ == "__main__":
    # Example usage
    detector = ThreatDetector({
        'random_forest': {
            'n_estimators': 100,
            'max_depth': 10,
            'random_state': 42
        },
        'feature_dim': 30
    })
    
    # Load training data
    X_train = pd.read_csv("../data/processed/network_traffic_processed.csv")
    y_train = pd.read_csv("../data/processed/network_traffic_labels.csv")
    
    # Train model
    detector.train_model(X_train, y_train)
    
    # Detect threats in new data
    new_data = pd.read_csv("../data/processed/new_traffic.csv")
    results = detector.detect_threats(new_data)
