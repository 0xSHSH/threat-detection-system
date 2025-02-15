import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import shap
import lime
import lime.lime_tabular
from typing import Dict, Any, Tuple, List
import logging
from pathlib import Path
import optuna
from tensorflow.keras.layers import Dense, Dropout, Input
from tensorflow.keras.models import Model
import matplotlib.pyplot as plt

class HybridThreatDetector:
    """Hybrid threat detection system combining multiple ML models"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the hybrid detector with configuration"""
        self.config = config or {}
        self.feature_names = self.config.get('feature_names', ['bytes', 'packets', 'duration'])
        self.reconstruction_error_std_multiplier = self.config.get('reconstruction_error_std_multiplier', 2)
        self.display_plots = self.config.get('display_plots', False)
        
        # Initialize models
        self.rf_model = None
        self.autoencoder = None
        self.dbscan = None
        self.scaler = StandardScaler()
        
        # Storage for training data (needed for SHAP/LIME)
        self._X_train = None
        self._y_train = None
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def create_autoencoder(self, input_dim: int) -> Model:
        """Create autoencoder model for anomaly detection"""
        # Encoder
        input_layer = Input(shape=(input_dim,))
        encoder = Dense(64, activation='relu')(input_layer)
        encoder = Dropout(0.2)(encoder)
        encoder = Dense(32, activation='relu')(encoder)
        encoder = Dense(16, activation='relu')(encoder)
        
        # Decoder
        decoder = Dense(32, activation='relu')(encoder)
        decoder = Dropout(0.2)(decoder)
        decoder = Dense(64, activation='relu')(decoder)
        decoder = Dense(input_dim, activation='sigmoid')(decoder)
        
        # Create model
        autoencoder = Model(input_layer, decoder)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        return autoencoder
        
    def optimize_random_forest(self, X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
        """Optimize Random Forest hyperparameters using Optuna"""
        def objective(trial):
            params = {
                'n_estimators': trial.suggest_int('n_estimators', 100, 500),
                'max_depth': trial.suggest_int('max_depth', 10, 50),
                'min_samples_split': trial.suggest_int('min_samples_split', 2, 10),
                'min_samples_leaf': trial.suggest_int('min_samples_leaf', 1, 5)
            }
            
            model = RandomForestClassifier(**params, random_state=42)
            model.fit(X, y)
            return model.score(X, y)
            
        study = optuna.create_study(direction='maximize')
        study.optimize(objective, n_trials=20)
        
        # Create optimized model
        best_params = study.best_params
        return RandomForestClassifier(**best_params, random_state=42)
        
    def train_models(self, X: np.ndarray, y: np.ndarray) -> None:
        """Train all models in the hybrid detector"""
        # Convert inputs to numpy arrays with consistent dtypes
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y, dtype=np.float64)
        
        # Verify input shapes and types
        if len(X) != len(y):
            raise ValueError(f"Input shapes don't match: X: {X.shape}, y: {y.shape}")
        
        self.logger.info(f"Training data shapes - X: {X.shape}, y: {y.shape}")
        self.logger.info(f"Data types - X: {X.dtype}, y: {y.dtype}")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        assert len(X_scaled) == len(y), "Scaled data and labels have different lengths"
        
        # Train Random Forest
        self.logger.info(f"Training Random Forest with {len(X)} samples...")
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42
        )
        self.rf_model.fit(X_scaled, y)
        
        # Train Autoencoder
        self.logger.info(f"Training Autoencoder with input_dim={X.shape[1]}...")
        self.autoencoder = self._train_autoencoder(X_scaled)
        
        # Train DBSCAN
        dbscan_eps = self.config.get('dbscan_eps', 0.3)
        dbscan_min_samples = self.config.get('dbscan_min_samples', 5)
        self.logger.info(f"Training DBSCAN with eps={dbscan_eps}, min_samples={dbscan_min_samples}...")
        self.dbscan = self._train_dbscan(X_scaled)
        
        # Store training data for SHAP/LIME
        self._X_train = X_scaled
        self._y_train = y
        
        self.logger.info("All models trained successfully")
    
    def predict(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """Make predictions using all models"""
        # Convert input to numpy array with consistent dtype
        X = np.asarray(X, dtype=np.float64)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        assert len(X_scaled) == len(X), "Scaled data and input data have different lengths"
        
        # Get predictions from each model
        rf_probs = self.rf_model.predict_proba(X_scaled)[:, 1]
        
        # Get autoencoder reconstruction error
        reconstructed = self.autoencoder.predict(X_scaled)
        reconstruction_errors = np.mean(np.square(X_scaled - reconstructed), axis=1)
        
        # Use pre-trained DBSCAN model for predictions
        dbscan_labels = self.dbscan.fit_predict(X_scaled)
        
        # Calculate dynamic threshold for reconstruction errors
        reconstruction_error_threshold = (
            np.mean(reconstruction_errors) + 
            self.reconstruction_error_std_multiplier * np.std(reconstruction_errors)
        )
        
        # Combine predictions (convert to float64 for consistency)
        is_threat = np.logical_or.reduce([
            rf_probs > 0.5,
            reconstruction_errors > reconstruction_error_threshold,
            dbscan_labels == -1
        ]).astype(np.float64)
        
        self.logger.info(f"Made predictions for {len(X)} samples")
        self.logger.debug(f"Threats detected: {np.sum(is_threat)}")
        
        return {
            'is_threat': is_threat,
            'threat_probabilities': rf_probs,
            'reconstruction_errors': reconstruction_errors,
            'dbscan_labels': dbscan_labels.astype(np.float64)
        }
    
    def explain_prediction(self, X: np.ndarray, sample_idx: int) -> Dict[str, Any]:
        """Generate explanations for a specific prediction"""
        # Ensure sample_idx is an integer
        sample_idx = int(sample_idx)
        
        # Convert input to numpy array and scale
        X = np.asarray(X, dtype=np.float64)
        X_scaled = self.scaler.transform(X)
        
        self.logger.debug(f"Explaining prediction for sample {sample_idx}")
        self.logger.debug(f"Input shape: {X.shape}, Scaled shape: {X_scaled.shape}")
        
        # Get SHAP values for Random Forest
        explainer = shap.TreeExplainer(self.rf_model)
        shap_values = explainer.shap_values(X_scaled[sample_idx:sample_idx+1])
        
        # Handle both single and multi-class outputs
        if isinstance(shap_values, list):
            self.logger.debug("Multi-class SHAP values detected")
            # For binary classification, use class 1 (attack) values
            shap_values = shap_values[1]
        
        # Get the first (and only) sample
        shap_values = shap_values.reshape(-1)
        self.logger.debug(f"SHAP values shape: {shap_values.shape}")
        
        # Create LIME explainer
        lime_explainer = lime.lime_tabular.LimeTabularExplainer(
            training_data=self._X_train,
            feature_names=self.feature_names,
            class_names=['normal', 'attack'],
            mode='classification',
            training_labels=self._y_train
        )
        
        # Get LIME explanation
        lime_exp = lime_explainer.explain_instance(
            data_row=X_scaled[sample_idx],
            predict_fn=self.rf_model.predict_proba,
            num_features=len(self.feature_names)
        )
        
        # Format explanations
        shap_dict = dict(zip(self.feature_names, shap_values))
        lime_dict = dict(lime_exp.as_list())
        
        self.logger.info(f"Generated explanations for sample {sample_idx}")
        return {
            'shap_values': shap_dict,
            'lime_explanation': lime_dict
        }
    
    def generate_feature_importance_plot(self, output_path: str) -> None:
        """Generate and save feature importance plot"""
        # Get feature importances from Random Forest
        importances = np.array(self.rf_model.feature_importances_)
        feature_names = np.array(self.feature_names)
        indices = np.argsort(importances)[::-1]
        
        self.logger.debug(f"Feature importance shape: {importances.shape}")
        self.logger.debug(f"Feature names: {feature_names}")
        
        # Create bar plot
        plt.figure(figsize=(10, 6))
        plt.title('Feature Importances')
        x_pos = np.arange(len(importances))
        plt.bar(x_pos, importances[indices])
        plt.xticks(
            x_pos,
            feature_names[indices],
            rotation=45
        )
        plt.xlabel('Features')
        plt.ylabel('Importance')
        plt.tight_layout()
        
        # Save plot
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        if self.display_plots:
            plt.show()
        plt.close()
        
        self.logger.info(f"Feature importance plot saved to {output_path}")
    
    def generate_shap_summary_plot(self, X: np.ndarray, output_path: str) -> None:
        """Generate and save SHAP summary plot"""
        try:
            # Convert and scale input data
            X = np.asarray(X, dtype=np.float64)
            X_scaled = self.scaler.transform(X)
            self.logger.debug(f"Input shape: {X.shape}, Scaled shape: {X_scaled.shape}")
            self.logger.debug(f"Feature names: {self.feature_names}")

            # Create explainer and get SHAP values
            explainer = shap.TreeExplainer(self.rf_model)
            shap_values = explainer.shap_values(X_scaled)

            # Handle binary classification (SHAP returns a list of arrays)
            if isinstance(shap_values, list):
                self.logger.debug("Binary classification detected")
                # For binary classification, use class 1 (attack) values
                shap_values = shap_values[1]  # Select SHAP values for class 1
            
            # Convert to numpy array if needed
            shap_values = np.array(shap_values)
            
            # Ensure SHAP values are 2D (samples × features)
            if len(shap_values.shape) > 2:
                self.logger.debug(f"Reshaping SHAP values from {shap_values.shape} to 2D")
                # Take the first class values if multi-class
                shap_values = shap_values[:, :, 0]

            self.logger.debug(f"Final SHAP values shape: {shap_values.shape}")
            self.logger.debug(f"X_scaled shape: {X_scaled.shape}")
            
            # Verify shapes match
            if shap_values.shape[1] != X_scaled.shape[1]:
                self.logger.error(f"Shape mismatch: SHAP values {shap_values.shape} vs X_scaled {X_scaled.shape}")
                raise ValueError("SHAP values shape does not match input data shape")

            # Create summary plot
            plt.figure(figsize=(10, 6))
            shap.summary_plot(
                shap_values,
                X_scaled,
                feature_names=self.feature_names,
                plot_type="bar",
                show=False
            )
            plt.tight_layout()

            # Save plot
            plt.savefig(output_path, bbox_inches='tight', dpi=300)
            if self.display_plots:
                plt.show()
            plt.close()

            self.logger.info(f"SHAP summary plot saved to {output_path}")
        except Exception as e:
            self.logger.error(f"Error generating SHAP plot: {str(e)}")
            self.logger.error(f"SHAP values type: {type(shap_values)}")
            if isinstance(shap_values, (list, np.ndarray)):
                try:
                    self.logger.error(f"SHAP values shape: {np.array(shap_values).shape}")
                except:
                    self.logger.error("Could not determine SHAP values shape")
            raise
    
    def _train_autoencoder(self, X: np.ndarray) -> tf.keras.Model:
        """Train autoencoder model for anomaly detection"""
        input_dim = X.shape[1]
        encoding_dim = min(input_dim // 2, 32)  # Reduce dimensionality, but not too much
        
        # Build encoder
        inputs = tf.keras.layers.Input(shape=(input_dim,))
        encoded = tf.keras.layers.Dense(encoding_dim * 2, activation='relu')(inputs)
        encoded = tf.keras.layers.Dense(encoding_dim, activation='relu')(encoded)
        
        # Build decoder
        decoded = tf.keras.layers.Dense(encoding_dim * 2, activation='relu')(encoded)
        decoded = tf.keras.layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Build autoencoder
        autoencoder = tf.keras.Model(inputs, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        # Train
        autoencoder.fit(
            X, X,
            epochs=50,
            batch_size=32,
            shuffle=True,
            validation_split=0.2,
            verbose=0
        )
        
        return autoencoder
    
    def _train_dbscan(self, X: np.ndarray) -> DBSCAN:
        """Train DBSCAN model for clustering-based anomaly detection"""
        # Initialize DBSCAN with optimized parameters
        dbscan_eps = self.config.get('dbscan_eps', 0.3)
        dbscan_min_samples = self.config.get('dbscan_min_samples', 5)
        dbscan = DBSCAN(
            eps=dbscan_eps,  # Distance threshold for neighborhood
            min_samples=dbscan_min_samples,  # Minimum samples in neighborhood for core point
            n_jobs=-1  # Use all available CPU cores
        )
        
        # Fit the model
        dbscan.fit(X)
        
        return dbscan
