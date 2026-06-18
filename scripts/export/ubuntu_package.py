"""
Package trained models for Ubuntu deployment
"""
import shutil
import json
import joblib
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import config

class UbuntuPackager:
    def __init__(self):
        self.base_path = Path(config.get('project.base_path'))
        self.models_path = self.base_path / 'models' / 'final'
        self.export_path = self.base_path / 'models' / 'export' / 'ubuntu_deployment'
        
        # Create export directory
        self.export_path.mkdir(parents=True, exist_ok=True)
        
    def package_models(self):
        """Package all necessary files for Ubuntu deployment"""
        print(" Packaging models for Ubuntu deployment...")
        
        # Create subdirectories
        (self.export_path / 'models').mkdir(exist_ok=True)
        (self.export_path / 'config').mkdir(exist_ok=True)
        (self.export_path / 'scripts').mkdir(exist_ok=True)
        
        # Copy model files
        model_files = [
            'ids_classifier.pth',
            'anomaly_detector.pth',
            'classifier_scaler.pkl',
            'autoencoder_scaler.pkl',
            'label_encoder.pkl',
            'model_metadata.json'
        ]
        
        print("\n Copying model files:")
        for file in model_files:
            src = self.models_path / file
            dst = self.export_path / 'models' / file
            if src.exists():
                shutil.copy2(src, dst)
                print(f"   {file}")
            else:
                print(f"   {file} - NOT FOUND")
        
        # Create deployment configuration
        deployment_config = {
            'system': 'Ubuntu Wazuh SIEM',
            'model_version': '1.0',
            'trained_on': 'Windows 11',
            'dataset': 'CICIDS2017',
            'samples_trained': 800000,
            'features': config.get('features.selected_features'),
            'deployment_notes': [
                'Models trained on Windows 11 host',
                'Deploy to Ubuntu VM for SIEM integration',
                'Requires Python 3.8+, PyTorch, scikit-learn'
            ]
        }
        
        with open(self.export_path / 'config' / 'deployment_config.json', 'w') as f:
            json.dump(deployment_config, f, indent=2)
        
        # Create requirements.txt for Ubuntu
        requirements = [
            'torch>=2.0.0',
            'numpy>=1.24.0',
            'pandas>=2.0.0',
            'scikit-learn>=1.3.0',
            'scapy>=2.5.0',
            'psutil>=5.9.0',
            'flask>=2.3.0',
            'python-dotenv>=1.0.0'
        ]
        
        with open(self.export_path / 'requirements.txt', 'w') as f:
            f.write('\n'.join(requirements))
            # Create README for Ubuntu setup
        readme = """# Neural Network IDS - Ubuntu Deployment Package

## Contents
- models/ - Trained neural network models and preprocessing objects
- config/ - Deployment configuration
- requirements.txt - Python dependencies

## Installation on Ubuntu

1. Install Python dependencies

pip install -r requirements.txt

2. Copy the models folder to your Ubuntu server

3. Load models in Python

Example:

import torch
import joblib

classifier = torch.load('models/ids_classifier.pth')

## Included Files

- ids_classifier.pth
- anomaly_detector.pth
- classifier_scaler.pkl
- autoencoder_scaler.pkl
- label_encoder.pkl
- model_metadata.json

"""

        with open(self.export_path / 'README.md', 'w', encoding='utf-8') as f:
            f.write(readme)

        print("\n Ubuntu deployment package created successfully!")
        print(f" Export location: {self.export_path}")

        return self.export_path


def main():
    packager = UbuntuPackager()
    packager.package_models()


if __name__ == "__main__":
    main()
