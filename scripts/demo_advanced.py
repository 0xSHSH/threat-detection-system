import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_curve, auc, confusion_matrix
import yaml
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

import asyncio
import logging
import datetime
from datetime import datetime
from src.data_collection import NetworkDataCollector
from src.advanced_ml import HybridThreatDetector

def setup_logging():
    """Setup logging configuration"""
    log_dir = project_root / 'logs'
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'demo.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

async def demo_system():
    """Run the advanced threat detection demo"""
    logger = setup_logging()
    
    # Print welcome message
    print("\n" + "="*80)
    print("Advanced Network Threat Detection System Demo")
    print("="*80 + "\n")
    
    # Load configuration
    with open(project_root / 'config' / 'config.yml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Initialize components
    collector = NetworkDataCollector(config['data_collection'])
    hybrid_detector = HybridThreatDetector(config['models'])
    
    # Create visualization directory if it doesn't exist
    vis_dir = project_root / 'visualizations'
    vis_dir.mkdir(exist_ok=True)
    
    try:
        # Load synthetic data
        print("Step 1: Loading and preparing dataset...")
        
        # Load and clean normal traffic data
        normal_data = pd.read_csv(project_root / 'data' / 'normal_traffic.csv')
        normal_data = normal_data.dropna()
        for col in ['bytes', 'packets', 'duration']:
            normal_data[col] = pd.to_numeric(normal_data[col], errors='coerce')
        normal_data = normal_data.dropna()
        
        # Load and clean attack traffic data
        attack_types = ['ddos', 'port_scan', 'data_exfiltration']
        attack_dfs = []
        
        for attack_type in attack_types:
            try:
                df = pd.read_csv(project_root / 'data' / f'{attack_type}_traffic.csv')
                df = df.dropna()
                for col in ['bytes', 'packets', 'duration']:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
                df = df.dropna()
                df['attack_type'] = attack_type
                attack_dfs.append(df)
                logger.info(f"Loaded {attack_type} traffic data: {len(df)} samples")
            except Exception as e:
                logger.error(f"Error loading {attack_type} traffic data: {str(e)}")
                raise
        
        attack_data = pd.concat(attack_dfs, ignore_index=True)
        
        # Prepare features
        features = ['bytes', 'packets', 'duration']
        
        # Debug data shapes before processing
        print("\nInitial Data Shapes:")
        print(f"Normal data: {normal_data.shape}")
        print(f"Attack data: {attack_data.shape}")
        
        # Ensure all required features are present
        for df in [normal_data, attack_data]:
            missing_cols = set(features) - set(df.columns)
            if missing_cols:
                raise ValueError(f"Missing columns in dataset: {missing_cols}")
        
        # Create feature matrix X and ensure it's float64
        X = pd.concat([
            normal_data[features],
            attack_data[features]
        ], ignore_index=True)
        
        # Convert to float64 and handle any remaining invalid values
        for col in features:
            X[col] = pd.to_numeric(X[col], errors='coerce')
        
        # Drop any rows with NaN values after conversion
        X = X.dropna()
        
        # Convert to numpy array
        X = X.values.astype(np.float64)
        
        # Create labels y
        y = np.concatenate([
            np.zeros(len(normal_data), dtype=np.float64),
            np.ones(len(attack_data), dtype=np.float64)
        ])
        
        # Verify data integrity
        print("\nData Integrity Check:")
        print(f"X shape: {X.shape}")
        print(f"y shape: {y.shape}")
        print(f"X dtype: {X.dtype}")
        print(f"y dtype: {y.dtype}")
        assert len(X) == len(y), f"X and y lengths don't match: {len(X)} vs {len(y)}"
        assert not np.isnan(X).any(), "Found NaN values in features"
        
        # Print dataset statistics
        print(f"\nDataset Statistics:")
        print(f"Total samples: {len(X)}")
        print(f"Normal traffic samples: {len(normal_data)}")
        print(f"Attack traffic samples: {len(attack_data)}")
        print("\nAttack distribution:")
        for attack_type in attack_types:
            count = sum(attack_data['attack_type'] == attack_type)
            print(f"- {attack_type}: {count} samples")
        
        # Split data with stratification
        print("\nStep 2: Splitting dataset...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Verify split shapes
        print("\nTrain-Test Split Shapes:")
        print(f"X_train: {X_train.shape}")
        print(f"X_test: {X_test.shape}")
        print(f"y_train: {y_train.shape}")
        print(f"y_test: {y_test.shape}")
        
        print("\nStep 3: Training hybrid threat detection model...")
        config = {
            'feature_names': features,
            'reconstruction_error_std_multiplier': 2.0,
            'display_plots': False,
            'dbscan_eps': 0.3,
            'dbscan_min_samples': 5
        }
        hybrid_detector = HybridThreatDetector(config)
        hybrid_detector.train_models(X_train, y_train)
        
        print("\nStep 4: Making predictions on test data...")
        predictions = hybrid_detector.predict(X_test)
        
        # Verify prediction shapes
        print("\nPrediction Shapes:")
        print(f"Test set size: {len(y_test)}")
        print(f"Predictions size: {len(predictions['is_threat'])}")
        print(f"Probabilities size: {len(predictions['threat_probabilities'])}")
        
        print("\nStep 5: Generating model explanations...")
        sample_idx = 0  # Explain first test sample
        explanations = hybrid_detector.explain_prediction(X_test, sample_idx)
        
        print("\nStep 6: Generating visualization plots...")
        
        # Generate plots
        hybrid_detector.generate_feature_importance_plot(
            str(vis_dir / 'feature_importance.png')
        )
        
        hybrid_detector.generate_shap_summary_plot(
            X_test[:10],  # Use first 10 samples for SHAP plot
            str(vis_dir / 'shap_summary.png')
        )
        
        # 3. ROC Curve
        fpr, tpr, _ = roc_curve(y_test, predictions['threat_probabilities'])
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(10, 8))
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.savefig(vis_dir / 'roc_curve.png')
        plt.close()
        
        # 4. Confusion Matrix
        cm = confusion_matrix(y_test, predictions['is_threat'])
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.title('Confusion Matrix')
        plt.savefig(vis_dir / 'confusion_matrix.png')
        plt.close()
        
        # Print performance metrics
        print("\nModel Performance Metrics:")
        print("-" * 40)
        print(classification_report(y_test, predictions['is_threat']))
        
        # Save explanations to file
        explanation_file = vis_dir / 'explanations.txt'
        with open(explanation_file, 'w') as f:
            f.write("Model Explanations for Sample Prediction\n")
            f.write("=======================================\n\n")
            
            f.write("SHAP Feature Importance:\n")
            f.write("-" * 30 + "\n")
            for feature, value in sorted(explanations['shap_values'].items(), 
                                      key=lambda x: abs(x[1]), reverse=True):
                f.write(f"{feature:15s}: {value:>10.4f}\n")
            
            f.write("\nLIME Explanation:\n")
            f.write("-" * 30 + "\n")
            for feature, value in explanations['lime_explanation'].items():
                f.write(f"{feature:15s}: {value:>10.4f}\n")
        
        print("\nDemo completed successfully!")
        print("-" * 40)
        print(f"Visualization plots saved in: {vis_dir}")
        print(f"Model explanations saved in: {explanation_file}")
        print("\nGenerated files:")
        for file in vis_dir.glob('*'):
            print(f"- {file.name}")
        
    except Exception as e:
        logger.error(f"Error during demo: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        
        print("Advanced Network Threat Detection System Demo")
        print("=" * 79)
        
        # Get project root
        project_root = Path(__file__).resolve().parent.parent
        
        # Create visualization directory
        vis_dir = project_root / 'visualizations'
        vis_dir.mkdir(exist_ok=True)
        
        try:
            # Load synthetic data
            print("\nStep 1: Loading and preparing dataset...")
            
            # Load and clean normal traffic data
            normal_data = pd.read_csv(project_root / 'data' / 'normal_traffic.csv')
            normal_data = normal_data.dropna()
            for col in ['bytes', 'packets', 'duration']:
                normal_data[col] = pd.to_numeric(normal_data[col], errors='coerce')
            normal_data = normal_data.dropna()
            
            # Load and clean attack traffic data
            attack_types = ['ddos', 'port_scan', 'data_exfiltration']
            attack_dfs = []
            
            for attack_type in attack_types:
                try:
                    df = pd.read_csv(project_root / 'data' / f'{attack_type}_traffic.csv')
                    df = df.dropna()
                    for col in ['bytes', 'packets', 'duration']:
                        df[col] = pd.to_numeric(df[col], errors='coerce')
                    df = df.dropna()
                    df['attack_type'] = attack_type
                    attack_dfs.append(df)
                    logger.info(f"Loaded {attack_type} traffic data: {len(df)} samples")
                except Exception as e:
                    logger.error(f"Error loading {attack_type} traffic data: {str(e)}")
                    raise
            
            attack_data = pd.concat(attack_dfs, ignore_index=True)
            
            # Prepare features
            features = ['bytes', 'packets', 'duration']
            
            # Debug data shapes before processing
            print("\nInitial Data Shapes:")
            print(f"Normal data: {normal_data.shape}")
            print(f"Attack data: {attack_data.shape}")
            
            # Ensure all required features are present
            for df in [normal_data, attack_data]:
                missing_cols = set(features) - set(df.columns)
                if missing_cols:
                    raise ValueError(f"Missing columns in dataset: {missing_cols}")
            
            # Create feature matrix X and ensure it's float64
            X = pd.concat([
                normal_data[features],
                attack_data[features]
            ], ignore_index=True)
            
            # Convert to float64 and handle any remaining invalid values
            for col in features:
                X[col] = pd.to_numeric(X[col], errors='coerce')
            
            # Drop any rows with NaN values after conversion
            X = X.dropna()
            
            # Convert to numpy array
            X = X.values.astype(np.float64)
            
            # Create labels y
            y = np.concatenate([
                np.zeros(len(normal_data), dtype=np.float64),
                np.ones(len(attack_data), dtype=np.float64)
            ])
            
            # Verify data integrity
            print("\nData Integrity Check:")
            print(f"X shape: {X.shape}")
            print(f"y shape: {y.shape}")
            print(f"X dtype: {X.dtype}")
            print(f"y dtype: {y.dtype}")
            assert len(X) == len(y), f"X and y lengths don't match: {len(X)} vs {len(y)}"
            assert not np.isnan(X).any(), "Found NaN values in features"
            
            # Print dataset statistics
            print(f"\nDataset Statistics:")
            print(f"Total samples: {len(X)}")
            print(f"Normal traffic samples: {len(normal_data)}")
            print(f"Attack traffic samples: {len(attack_data)}")
            print("\nAttack distribution:")
            for attack_type in attack_types:
                count = sum(attack_data['attack_type'] == attack_type)
                print(f"- {attack_type}: {count} samples")
            
            # Split data with stratification
            print("\nStep 2: Splitting dataset...")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Verify split shapes
            print("\nTrain-Test Split Shapes:")
            print(f"X_train: {X_train.shape}")
            print(f"X_test: {X_test.shape}")
            print(f"y_train: {y_train.shape}")
            print(f"y_test: {y_test.shape}")
            
            # Initialize and train the hybrid detector
            print("\nStep 3: Training hybrid threat detection model...")
            config = {
                'feature_names': features,
                'reconstruction_error_std_multiplier': 2.0,
                'display_plots': False,
                'dbscan_eps': 0.3,
                'dbscan_min_samples': 5
            }
            hybrid_detector = HybridThreatDetector(config)
            hybrid_detector.train_models(X_train, y_train)
            
            print("\nStep 4: Making predictions on test data...")
            predictions = hybrid_detector.predict(X_test)
            
            # Verify prediction shapes
            print("\nPrediction Shapes:")
            print(f"Test set size: {len(y_test)}")
            print(f"Predictions size: {len(predictions['is_threat'])}")
            print(f"Probabilities size: {len(predictions['threat_probabilities'])}")
            
            print("\nStep 5: Generating model explanations...")
            sample_idx = 0  # Explain first test sample
            explanations = hybrid_detector.explain_prediction(X_test, sample_idx)
            
            print("\nStep 6: Generating visualization plots...")
            
            # Generate plots with better error handling
            try:
                print("Generating feature importance plot...")
                hybrid_detector.generate_feature_importance_plot(
                    str(vis_dir / 'feature_importance.png')
                )
                
                print("Generating SHAP summary plot...")
                X_test_subset = X_test[:min(10, len(X_test))]  # Use up to 10 samples
                hybrid_detector.generate_shap_summary_plot(
                    X_test_subset,
                    str(vis_dir / 'shap_summary.png')
                )
                
                # Print performance metrics
                print("\nModel Performance Metrics:")
                print("-" * 40)
                print(classification_report(y_test, predictions['is_threat']))
                
                print("\nDemo completed successfully!")
                print("-" * 40)
                print(f"Visualization plots saved in: {vis_dir}")
                print("\nGenerated files:")
                for file in vis_dir.glob('*'):
                    print(f"- {file.name}")
                
            except Exception as e:
                logger.error(f"Error generating plots: {str(e)}")
                raise
            
        except Exception as e:
            logger.error(f"Error during demo: {str(e)}")
            raise
            
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)
