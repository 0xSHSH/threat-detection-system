# Advanced Network Threat Detection System

A comprehensive machine learning system for real-time network security and anomaly detection, leveraging hybrid threat detection techniques.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Detailed Installation Guide](#detailed-installation-guide)
- [Testing the System](#testing-the-system)
- [Project Structure](#project-structure)
- [Understanding the Data](#understanding-the-data)
- [Configuration Options](#configuration-options)
- [Running Your Own Tests](#running-your-own-tests)
- [Visualization Guide](#visualization-guide)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Features

- **Hybrid Detection Model**
  - Random Forest for supervised learning
  - Autoencoder for unsupervised anomaly detection
  - DBSCAN for clustering-based detection
  
- **Real-time Analysis**
  - Process live network traffic
  - Batch processing capabilities
  - Configurable processing windows
  
- **Explainable AI**
  - Feature importance visualization
  - SHAP (SHapley Additive exPlanations) values
  - Decision path analysis
  
- **Multi-class Detection**
  - DDoS attacks
  - Port scanning
  - Data exfiltration
  - Extensible to new attack types

## Prerequisites

### System Requirements
- CPU: 2+ cores recommended
- RAM: 4GB minimum, 8GB recommended
- Storage: 1GB free space
- Operating System: Windows/Linux/MacOS

### Software Requirements
- Python 3.8 or higher
- pip (Python package installer)
- Git
- Virtual environment tool (venv/conda)

### Network Requirements
- Internet connection for installation
- Network interface card for live capture

## Detailed Installation Guide

### 1. Python Installation
```bash
# Check if Python is installed
python --version  # Should be 3.8 or higher

# If not installed, download from:
# Windows: https://www.python.org/downloads/
# Linux: sudo apt-get install python3
# MacOS: brew install python3
```

### 2. Git Installation
```bash
# Check if Git is installed
git --version

# If not installed:
# Windows: https://git-scm.com/download/win
# Linux: sudo apt-get install git
# MacOS: brew install git
```

### 3. Repository Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/threat-detection-system.git
cd threat-detection-system

# Create virtual environment
## Windows
python -m venv venv
.\venv\Scripts\activate

## Linux/MacOS
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "import numpy; import pandas; import tensorflow; import sklearn; print('Installation successful!')"
```

## Testing the System

### 1. Quick Test
```bash
# Run the demo script
python scripts/demo_advanced.py

# Expected output:
# - Loading data...
# - Training models...
# - Generating visualizations...
# - Displaying results...
```

### 2. Sample Data Test
```python
# In Python interactive shell
from src.advanced_ml import HybridThreatDetector
import pandas as pd

# Load sample data
normal = pd.read_csv('data/normal_traffic.csv')
attack = pd.read_csv('data/ddos_traffic.csv')

# Initialize detector
config = {
    'feature_names': ['bytes', 'packets', 'duration'],
    'reconstruction_error_std_multiplier': 2.0,
    'display_plots': True
}
detector = HybridThreatDetector(config)

# Train and test
detector.train_models(normal[['bytes', 'packets', 'duration']], [0] * len(normal))
results = detector.predict(attack[['bytes', 'packets', 'duration']])
print(f"Detected threats: {sum(results['is_threat'])}")
```

## Understanding the Data

### Data Format
Your input data should be in CSV format with these columns:
```csv
bytes,packets,duration
1024,5,2.5
2048,10,3.0
```

### Feature Descriptions
1. **bytes**: Total bytes transferred (integer)
   - Range: 0 to 1,000,000,000
   - Example: 1024

2. **packets**: Number of packets (integer)
   - Range: 0 to 1,000,000
   - Example: 5

3. **duration**: Connection duration in seconds (float)
   - Range: 0.0 to 3600.0
   - Example: 2.5

### Sample Data Generation
```python
# Generate synthetic normal traffic
import numpy as np
import pandas as pd

n_samples = 1000
normal_data = pd.DataFrame({
    'bytes': np.random.normal(1000, 200, n_samples),
    'packets': np.random.normal(10, 2, n_samples),
    'duration': np.random.normal(2, 0.5, n_samples)
})
normal_data.to_csv('my_normal_traffic.csv', index=False)
```

## Configuration Options

### Basic Configuration
```python
config = {
    'feature_names': ['bytes', 'packets', 'duration'],
    'reconstruction_error_std_multiplier': 2.0,
    'display_plots': False,
    'dbscan_eps': 0.3,
    'dbscan_min_samples': 5
}
```

### Advanced Configuration
```python
advanced_config = {
    # Feature settings
    'feature_names': ['bytes', 'packets', 'duration'],
    'feature_scaling': 'standard',  # or 'minmax'
    
    # Random Forest settings
    'rf_n_estimators': 100,
    'rf_max_depth': 10,
    
    # Autoencoder settings
    'ae_encoding_dim': 2,
    'ae_epochs': 50,
    'ae_batch_size': 32,
    
    # DBSCAN settings
    'dbscan_eps': 0.3,
    'dbscan_min_samples': 5,
    
    # Visualization settings
    'display_plots': True,
    'plot_style': 'seaborn',
    
    # Threshold settings
    'reconstruction_error_std_multiplier': 2.0,
    'probability_threshold': 0.7
}
```

## Running Your Own Tests

### 1. Prepare Your Data
```bash
# Create data directory
mkdir -p my_test_data

# Place your CSV files
cp /path/to/your/normal.csv my_test_data/normal_traffic.csv
cp /path/to/your/attack.csv my_test_data/attack_traffic.csv
```

### 2. Modify Test Script
```python
# my_test_script.py
from src.advanced_ml import HybridThreatDetector
import pandas as pd

# Load your data
normal_data = pd.read_csv('my_test_data/normal_traffic.csv')
attack_data = pd.read_csv('my_test_data/attack_traffic.csv')

# Configure detector
config = {
    'feature_names': ['bytes', 'packets', 'duration'],
    'reconstruction_error_std_multiplier': 2.0,
    'display_plots': True
}

# Initialize and train
detector = HybridThreatDetector(config)
detector.train_models(
    normal_data[config['feature_names']],
    [0] * len(normal_data)
)

# Test
results = detector.predict(attack_data[config['feature_names']])

# Print results
print(f"Total samples: {len(attack_data)}")
print(f"Detected threats: {sum(results['is_threat'])}")
print(f"Detection rate: {sum(results['is_threat'])/len(attack_data)*100:.2f}%")
```

### 3. Run Tests
```bash
python my_test_script.py
```

## Visualization Guide

### 1. Feature Importance Plot
- Location: `visualizations/feature_importance.png`
- Interpretation:
  - Longer bars = More important features
  - Color intensity = Feature value impact

### 2. SHAP Summary Plot
- Location: `visualizations/shap_summary.png`
- Interpretation:
  - Red = High feature values
  - Blue = Low feature values
  - Position = Impact on prediction

### Custom Visualization
```python
# Generate custom plots
detector.generate_feature_importance_plot('my_feature_plot.png')
detector.generate_shap_summary_plot(test_data, 'my_shap_plot.png')
```

## Troubleshooting Guide

### Common Issues

1. **Installation Problems**
```bash
# Clear pip cache
pip cache purge
# Reinstall requirements
pip install -r requirements.txt
```

2. **Import Errors**
```python
# Check Python path
import sys
print(sys.path)
# Add project root if needed
sys.path.append('/path/to/threat-detection-system')
```

3. **Data Format Issues**
```python
# Check data types
print(df.dtypes)
# Convert types if needed
df = df.astype({'bytes': float, 'packets': float, 'duration': float})
```

4. **Memory Issues**
```python
# Reduce batch size
config['ae_batch_size'] = 16
# Process data in chunks
for chunk in pd.read_csv('large_file.csv', chunksize=1000):
    results = detector.predict(chunk[features])
```

### Error Messages

1. **"ValueError: Input contains NaN"**
   ```python
   # Clean your data
   df = df.dropna()
   ```

2. **"Shape mismatch"**
   ```python
   # Verify feature columns
   print("Expected:", config['feature_names'])
   print("Got:", df.columns)
   ```

3. **"Memory Error"**
   ```python
   # Free memory
   import gc
   gc.collect()
   ```

## Support

### Getting Help
1. Check the [Issues](https://github.com/yourusername/threat-detection-system/issues) page
2. Join our [Discord](https://discord.gg/yourinvite)
3. Email: support@example.com

### Reporting Bugs
1. Use the issue template
2. Include:
   - Python version
   - OS details
   - Error message
   - Minimal reproducible example

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

## Citation
If you use this system in your research, please cite:
```bibtex
@software{threat_detection_system,
  author = {Your Name},
  title = {Advanced Network Threat Detection System},
  year = {2025},
  url = {https://github.com/yourusername/threat-detection-system}
}
