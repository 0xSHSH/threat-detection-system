import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import pandas as pd
import numpy as np
import yaml
import tempfile
from src.threat_detection import ThreatDetector
from src.preprocessing import DataPreprocessor

@pytest.fixture
def config_file():
    """Create a temporary config file for testing."""
    config = {
        'network': {
            'interface': 'eth0',
            'capture_duration': 3600,
            'packet_limit': 10000
        },
        'models': {
            'supervised': {
                'model_type': 'random_forest',
                'n_estimators': 100,
                'max_depth': 10,
                'random_state': 42
            }
        },
        'logging': {
            'level': 'INFO',
            'file_path': 'logs/',
            'max_size': '10MB',
            'backup_count': 5
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(config, f)
        config_path = f.name
    
    yield config_path
    
    # Cleanup
    os.unlink(config_path)

@pytest.fixture
def sample_data():
    """Create sample data for testing."""
    np.random.seed(42)
    n_samples = 1000
    
    data = pd.DataFrame({
        'length': np.random.normal(500, 100, n_samples),
        'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
        'src_port': np.random.randint(1024, 65535, n_samples),
        'dst_port': np.random.randint(1024, 65535, n_samples),
        'timestamp': pd.date_range(start='2025-01-01', periods=n_samples, freq='1min')
    })
    
    # Add some anomalies
    anomaly_idx = np.random.choice(n_samples, 50, replace=False)
    data.loc[anomaly_idx, 'length'] = np.random.normal(2000, 200, 50)
    
    return data

@pytest.fixture
def preprocessor():
    """Create DataPreprocessor instance."""
    return DataPreprocessor()

@pytest.fixture
def detector(config_file):
    """Create ThreatDetector instance with config."""
    return ThreatDetector(config_path=config_file)

def test_preprocessing(sample_data, preprocessor):
    """Test data preprocessing functionality."""
    processed_data = preprocessor.preprocess_network_traffic(sample_data)
    
    assert not processed_data.isnull().any().any(), "Processed data contains null values"
    assert 'protocol' in processed_data.columns, "Protocol column is missing"
    assert processed_data.shape[0] == sample_data.shape[0], "Number of samples changed during preprocessing"

def test_threat_detection(sample_data, preprocessor, detector):
    """Test threat detection functionality."""
    processed_data = preprocessor.preprocess_network_traffic(sample_data)
    
    # Train models
    detector.train_supervised_model(processed_data, np.random.randint(0, 2, len(processed_data)))
    detector.train_unsupervised_model(processed_data)
    detector.train_behavioral_model(processed_data)
    
    # Detect threats
    results = detector.detect_threats(processed_data)
    
    assert isinstance(results, dict), "Results should be a dictionary"
    assert 'threats_detected' in results, "No threats_detected key in results"
    assert 'threat_scores' in results, "No threat_scores key in results"

def test_anomaly_detection(sample_data, preprocessor, detector):
    """Test anomaly detection functionality."""
    processed_data = preprocessor.preprocess_network_traffic(sample_data)
    
    detector.train_unsupervised_model(processed_data)
    results = detector.detect_threats(processed_data)
    
    assert 'anomalies' in results, "No anomalies key in results"
    assert len(results['anomalies']) > 0, "No anomalies detected in sample data with known anomalies"

if __name__ == "__main__":
    pytest.main([__file__])
