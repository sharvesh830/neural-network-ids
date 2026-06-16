import yaml
import os
from pathlib import Path

class Config:
    def __init__(self, config_path=None):
        if config_path is None:
            # Get config path relative to this file
            config_dir = Path(__file__).parent
            config_path = config_dir / "neural_config.yaml"
        
        self.config_path = config_path
        self.config = self._load_config()
        self._setup_paths()
    
    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            print(f"Config file not found: {self.config_path}")
            # Create default config if file doesn't exist
            return self._create_default_config()
        except yaml.YAMLError as e:
            print(f"Error parsing config file: {e}")
            raise
    
    def _create_default_config(self):
        """Create default configuration"""
        return {
            'project': {
                'name': 'Neural_IDS_CICIDS2017',
                'version': '1.0',
                'base_path': 'D:/IDS_Neural_Project'
            },
            'data': {
                'dataset_name': 'CICIDS2017',
                'raw_data_path': 'data/raw',
                'processed_data_path': 'data/processed',
                'final_dataset': 'data/processed/cicids_combined.csv',
                'export_path': 'data/export',
                'sample_size': 800000,
                'test_split': 0.2,
                'val_split': 0.1,
                'random_state': 42
            },
            'features': {
                'selected_features': [
                    "Flow Duration",
                    "Total Fwd Packets",
                    "Total Backward Packets",
                    "Total Length of Fwd Packets",
                    "Total Length of Bwd Packets",
                    "Fwd Packet Length Max",
                    "Fwd Packet Length Min",
                    "Fwd Packet Length Mean",
                    "Fwd Packet Length Std",
                    "Bwd Packet Length Max",
                    "Bwd Packet Length Min",
                    "Bwd Packet Length Mean",
                    "Bwd Packet Length Std",
                    "Flow Bytes/s",
                    "Flow Packets/s",
                    "Flow IAT Mean",
                    "Flow IAT Std",
                    "Flow IAT Max"
                ]
            }
        }
    
    def _setup_paths(self):
        """Setup and create necessary directories"""
        base_path = Path(self.config['project']['base_path'])
        
        # Create directories if they don't exist
        directories = [
            'data/raw', 'data/processed', 'data/export',
            'models/training', 'models/final', 'models/export',
            'logs', 'results'
        ]
        
        for directory in directories:
            dir_path = base_path / directory
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def get(self, key_path, default=None):
        """Get configuration value using dot notation"""
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except KeyError:
            return default
    
    def get_data_path(self, relative_path=""):
        """Get full data path"""
        base_path = Path(self.config['project']['base_path'])
        return base_path / self.config['data']['processed_data_path'] / relative_path
    
    def get_model_path(self, relative_path=""):
        """Get full model path"""
        base_path = Path(self.config['project']['base_path'])
        return base_path / 'models' / relative_path
    
    def get_export_path(self, relative_path=""):
        """Get full export path"""
        base_path = Path(self.config['project']['base_path'])
        return base_path / 'models/export' / relative_path

# Global config instance
config = Config()

# Make Config class available for import too
__all__ = ['config', 'Config']