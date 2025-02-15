import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from typing import Tuple, List, Dict
import logging
from datetime import datetime
import os
import yaml

class DataPreprocessor:
    def __init__(self):
        """Initialize the DataPreprocessor with necessary preprocessing components."""
        self.setup_logging()
        self.scalers = {}
        self.label_encoders = {}
        self.pca = None
        
    def setup_logging(self):
        """Set up logging configuration."""
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"preprocessor_{datetime.now().strftime('%Y%m%d')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def preprocess_network_traffic(self, data: pd.DataFrame) -> pd.DataFrame:
        """Preprocess network traffic data."""
        try:
            self.logger.info("Preprocessing network traffic data")
            
            # Create a copy to avoid modifying original data
            df = data.copy()
            
            # Convert timestamp to datetime if it's not already
            if 'timestamp' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Extract temporal features
            df['hour'] = df['timestamp'].dt.hour
            df['minute'] = df['timestamp'].dt.minute
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            
            # Convert protocol to numeric using one-hot encoding
            if 'protocol' in df.columns:
                protocol_dummies = pd.get_dummies(df['protocol'], prefix='protocol')
                df = pd.concat([df, protocol_dummies], axis=1)
                df.drop('protocol', axis=1, inplace=True)
            
            # Handle ports
            if 'src_port' in df.columns:
                df['src_port'] = df['src_port'].fillna(-1).astype(float)
            if 'dst_port' in df.columns:
                df['dst_port'] = df['dst_port'].fillna(-1).astype(float)
            
            # Handle packet length
            if 'length' in df.columns:
                df['length'] = df['length'].fillna(0).astype(float)
            
            # Drop non-numeric columns that we don't need for modeling
            columns_to_drop = ['timestamp', 'src_ip', 'dst_ip']
            df = df.drop([col for col in columns_to_drop if col in df.columns], axis=1)
            
            # Fill any remaining missing values
            df = df.fillna(0)
            
            self.logger.info("Preprocessing completed")
            return df
            
        except Exception as e:
            self.logger.error(f"Error preprocessing network traffic: {str(e)}")
            raise

    def preprocess_system_logs(self, data: pd.DataFrame) -> pd.DataFrame:
        """Preprocess system logs data."""
        self.logger.info("Preprocessing system logs")
        try:
            # Handle missing values
            data = self._handle_missing_values(data)
            
            # Extract features specific to system logs
            # Implementation depends on log format
            
            return data
            
        except Exception as e:
            self.logger.error(f"Error preprocessing system logs: {str(e)}")
            raise

    def preprocess_user_activity(self, data: pd.DataFrame) -> pd.DataFrame:
        """Preprocess user activity data."""
        self.logger.info("Preprocessing user activity data")
        try:
            # Handle missing values
            data = self._handle_missing_values(data)
            
            # Extract user behavior features
            # Implementation depends on activity data format
            
            return data
            
        except Exception as e:
            self.logger.error(f"Error preprocessing user activity: {str(e)}")
            raise

    def _handle_missing_values(self, data: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values in the dataset."""
        # Fill numeric columns with median
        numeric_columns = data.select_dtypes(include=[np.number]).columns
        data[numeric_columns] = data[numeric_columns].fillna(data[numeric_columns].median())
        
        # Fill categorical columns with mode
        categorical_columns = data.select_dtypes(include=['object']).columns
        data[categorical_columns] = data[categorical_columns].fillna(data[categorical_columns].mode().iloc[0])
        
        return data

    def _extract_temporal_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Extract features from timestamp data."""
        if 'timestamp' in data.columns:
            # Convert timestamp to datetime if it's not already
            if not pd.api.types.is_datetime64_any_dtype(data['timestamp']):
                data['timestamp'] = pd.to_datetime(data['timestamp'])
            
            # Extract temporal features
            data['hour'] = data['timestamp'].dt.hour.astype(float)
            data['minute'] = data['timestamp'].dt.minute.astype(float)
            data['day_of_week'] = data['timestamp'].dt.dayofweek.astype(float)
            
            # Drop the original timestamp column as it can't be used for ML
            data = data.drop('timestamp', axis=1)
            
        return data

    def _encode_categorical_features(self, data: pd.DataFrame, 
                                   categorical_columns: List[str]) -> pd.DataFrame:
        """Encode categorical features using LabelEncoder."""
        for column in categorical_columns:
            if column in data.columns:
                if column not in self.label_encoders:
                    self.label_encoders[column] = LabelEncoder()
                data[column] = self.label_encoders[column].fit_transform(data[column])
        
        return data

    def _scale_numerical_features(self, data: pd.DataFrame, 
                                numerical_columns: List[str],
                                scaler_key: str) -> pd.DataFrame:
        """Scale numerical features using StandardScaler."""
        if scaler_key not in self.scalers:
            self.scalers[scaler_key] = StandardScaler()
            
        data[numerical_columns] = self.scalers[scaler_key].fit_transform(data[numerical_columns])
        return data

    def _calculate_traffic_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Calculate additional traffic-related features."""
        # Calculate traffic volume per source IP
        if 'src_ip' in data.columns:
            volume_by_src = data.groupby('src_ip')['length'].sum()
            data['src_ip_volume'] = data['src_ip'].map(volume_by_src)
        
        # Calculate traffic volume per destination IP
        if 'dst_ip' in data.columns:
            volume_by_dst = data.groupby('dst_ip')['length'].sum()
            data['dst_ip_volume'] = data['dst_ip'].map(volume_by_dst)
        
        return data

    def reduce_dimensionality(self, data: pd.DataFrame, n_components: int = 0.95) -> pd.DataFrame:
        """Reduce dimensionality using PCA."""
        try:
            if self.pca is None:
                self.pca = PCA(n_components=n_components)
                
            numerical_columns = data.select_dtypes(include=[np.number]).columns
            data_pca = self.pca.fit_transform(data[numerical_columns])
            
            # Convert to DataFrame with meaningful column names
            columns = [f'PC{i+1}' for i in range(data_pca.shape[1])]
            data_pca = pd.DataFrame(data_pca, columns=columns, index=data.index)
            
            # Add back any non-numerical columns
            for col in data.columns:
                if col not in numerical_columns:
                    data_pca[col] = data[col]
            
            return data_pca
            
        except Exception as e:
            self.logger.error(f"Error reducing dimensionality: {str(e)}")
            raise

    def _load_config(self, config_path=None):
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'config',
                'config.yml'
            )
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config

if __name__ == "__main__":
    # Example usage
    preprocessor = DataPreprocessor()
    
    # Load and preprocess network traffic data
    network_data = pd.read_csv("../data/raw/network_traffic.csv")
    processed_network_data = preprocessor.preprocess_network_traffic(network_data)
    
    # Reduce dimensionality
    reduced_data = preprocessor.reduce_dimensionality(processed_network_data)
    
    # Save processed data
    processed_network_data.to_csv("../data/processed/network_traffic_processed.csv", index=False)
    reduced_data.to_csv("../data/processed/network_traffic_reduced.csv", index=False)
