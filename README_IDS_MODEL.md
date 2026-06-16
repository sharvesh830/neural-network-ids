Neural Network IDS - Windows Training Pipeline
🎯 Overview
Complete machine learning training pipeline for developing neural network models to detect network intrusions and classify cyber attacks. This Windows-based training system generates models that are deployed in the live Ubuntu IDS environment.

🏗️ Architecture
Model Pipeline
Framework: PyTorch
Dataset: CIC-IDS2017 (2.8M+ network flows)
Input Features: 18 network flow features
Output Classes: 15 attack types + Normal traffic
Models: Dual architecture (Classifier + Autoencoder)
Attack Detection Capabilities
DDoS attacks - Distributed denial of service
Port scanning - Network reconnaissance
Botnet communication - C&C traffic
Web attacks - SQL injection, XSS, brute force
SSH/FTP brute force - Credential attacks
DoS variants - Hulk, GoldenEye, Slowloris
And 8+ additional attack types
📁 Project Structure
text

IDS_Neural_Project/
├── 🚀 run_training.py          # Main training orchestrator
├── 🎯 main_launcher.py         # Training launcher with error handling
├── 📊 scripts/
│   ├── 📂 data_processing/
│   │   └── process_cicids.py   # CIC-IDS2017 dataset processing
│   ├── 📂 models/
│   │   ├── neural_networks.py  # PyTorch model architectures
│   │   ├── losses.py          # Focal loss for imbalanced data
│   │   └── metrics.py         # Evaluation metrics
│   ├── 📂 training/
│   │   └── train_complete.py  # End-to-end training pipeline
│   ├── 📂 evaluation/         # Model evaluation utilities
│   ├── 📂 export/
│   │   └── ubuntu_packager.py # Deploy models to Ubuntu IDS
│   └── 📂 utils/              # Helper functions
├── 📂 config/
│   ├── neural_config.yaml     # Training hyperparameters
│   └── __init__.py            # Config loader
├── 📂 data/                   # Dataset storage (excluded from git)
├── 📂 models/                 # Trained models (excluded from git)
├── 📂 results/               # Training results & visualizations
├── 📂 logs/                  # Training logs
├── 📂 notebooks/             # Jupyter analysis notebooks
├── 📋 requirements.txt        # Python dependencies
└── 📄 README.md              # This documentation
🚀 Quick Start
1. Environment Setup
Bash

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
2. Dataset Preparation
Bash

# Download CIC-IDS2017 dataset
# Place CSV files in data/raw/

# Run preprocessing
python scripts/data_processing/process_cicids.py
3. Model Training
Bash

# Complete training pipeline
python run_training.py

# Alternative launcher with error handling
python main_launcher.py
4. Deploy to Ubuntu IDS
Bash

# Package trained models
python scripts/export/ubuntu_packager.py

# Copy to Ubuntu system
# Files exported to models/ubuntu_deployment/
📊 Training Pipeline
Data Processing
Dataset Loading: CIC-IDS2017 CSV files
Feature Extraction: 18 network flow statistics
Data Cleaning: Handle infinite/NaN values
Normalization: StandardScaler for neural networks
Train/Val/Test Split: 70%/10%/20%
Model Architecture
Classifier Network
Python

Input (18 features) → Dense(128) → ReLU → Dropout(0.3)
                   → Dense(64)  → ReLU → Dropout(0.3)
                   → Dense(32)  → ReLU → Dropout(0.3)
                   → Dense(15)  → Softmax
Autoencoder Network
Python

Encoder: Input(18) → Dense(64) → ReLU → Dense(32) → ReLU → Dense(32)
Decoder: Dense(32) → ReLU → Dense(64) → ReLU → Dense(18)
Training Features
Focal Loss: Handles class imbalance
Early Stopping: Prevents overfitting
Learning Rate Scheduling: Adaptive learning
Batch Processing: Optimized for large datasets
GPU Acceleration: CUDA support
Evaluation Metrics
Accuracy: Overall classification accuracy
Precision/Recall: Per-class performance
F1-Score: Balanced performance metric
Detection Rate: True positive rate for attacks
False Positive Rate: Misclassified normal traffic
Confusion Matrix: Detailed classification results
📈 Model Performance
Expected Results
Classifier Accuracy: >95% on test set
Detection Rate: >90% for attack traffic
False Positive Rate: <5% for normal traffic
Inference Speed: <1ms per flow (real-time capable)
Training Time
Full Pipeline: ~30-60 minutes
Dataset Size: 2.8M+ flows
Hardware: GPU recommended for faster training
🔧 Configuration
Training Parameters (config/neural_config.yaml)
YAML

models:
  classifier:
    hidden_layers: [128, 64, 32]
    dropout: 0.3
    learning_rate: 0.001
    batch_size: 1024
    epochs: 50
    
  autoencoder:
    encoding_dim: 32
    hidden_layers: [64, 32]
    learning_rate: 0.001
    batch_size: 512
    epochs: 30

training:
  early_stopping_patience: 10
  test_size: 0.2
  validation_size: 0.1
Feature Set (18 Features)
YAML

features:
  selected_features:
    - Flow Duration
    - Total Fwd/Bwd Packets
    - Packet Length Statistics
    - Flow Bytes/Packets per second
    - Inter-arrival Time Statistics
    # ... and 10 more flow features
🔗 Integration with Ubuntu IDS
Model Export Process
Training Completion: Models saved as .pth files
Preprocessing Objects: Scalers and encoders saved as .pkl
Metadata Export: Model configuration as JSON
Ubuntu Package: All files prepared for deployment
Transfer: Copy to Ubuntu ~/neural_ids/models/
Deployment Integration
Python

# Export for production deployment
python scripts/export/ubuntu_packager.py

# Files exported to models/ubuntu_deployment/:
# - ids_classifier.pth (15-class neural network)
# - anomaly_detector.pth (autoencoder for anomaly detection)
# - classifier_scaler.pkl (feature normalization)
# - label_encoder.pkl (attack class mapping)
# - model_metadata.json (configuration)
🧪 Usage Examples
Custom Training
Python

# Modify model architecture
# Edit: scripts/models/neural_networks.py

# Adjust training parameters
# Edit: config/neural_config.yaml

# Run training
python run_training.py
Model Evaluation
Python

from scripts.models.neural_networks import IDSClassifier
from scripts.evaluation.metrics import IDSMetrics

# Load trained model
model = IDSClassifier(input_dim=18, num_classes=15)
model.load_state_dict(torch.load('models/final/ids_classifier.pth'))

# Evaluate on test data
metrics = IDSMetrics()
results = metrics.evaluate_model(model, test_data)
Real-time Inference
Python

# Single flow prediction
flow_features = extract_flow_features(packet_data)
prediction = model(flow_features)
attack_type = label_encoder.inverse_transform([prediction.argmax()])
confidence = torch.softmax(prediction, dim=0).max().item()
📚 Dataset Information
CIC-IDS2017 Dataset
Source: Canadian Institute for Cybersecurity
Size: 2.8M+ labeled network flows
Duration: 5 days of network traffic
Labels: 15 attack types + normal traffic
Features: 80+ flow-based features (18 selected)
Attack Distribution
BENIGN: ~80% (normal traffic)
DDoS: ~12% (various DDoS attacks)
PortScan: ~5% (reconnaissance)
Others: ~3% (web attacks, brute force, etc.)
🛠️ Development
Requirements
Python: 3.8+
PyTorch: 1.9.0+
CUDA: Optional (GPU acceleration)
RAM: 8GB+ recommended
Storage: 10GB+ for dataset and models
Dependencies
txt

torch>=1.9.0          # Deep learning framework
pandas>=1.3.0         # Data manipulation
scikit-learn>=1.0.0   # Machine learning utilities
matplotlib>=3.4.0     # Visualization
seaborn>=0.11.0       # Statistical plots
tqdm>=4.62.0          # Progress bars
pyyaml>=5.4.0         # Configuration files
Testing
Bash

# Run unit tests
python -m pytest tests/

# Syntax validation
python -m py_compile run_training.py

# Model validation
python scripts/evaluation/validate_models.py
🔍 Monitoring and Logging
Training Logs
Location: logs/training.log
Content: Training progress, metrics, errors
Format: Timestamped structured logging
Model Checkpoints
Best Models: models/training/best_*.pth
Automatic Saving: Based on validation performance
Recovery: Resume training from checkpoints
Visualization
Training Curves: Loss and accuracy plots
Confusion Matrix: Classification performance
Feature Importance: Model interpretation
ROC Curves: Threshold analysis
🚀 Production Deployment
Live Integration
This training pipeline generates models for the Neural Network IDS production system:

Repository: neural-network-ids
Platform: Ubuntu 20.04+ SIEM environment
Deployment: Real-time packet analysis
Integration: Wazuh SIEM, email alerts, auto-blocking
Performance in Production
Throughput: 1000+ packets/second
Latency: <1ms per flow analysis
Accuracy: 95%+ attack detection
Uptime: 24/7 continuous monitoring
🤝 Contributing
Development Workflow
Fork the repository
Create feature branch
Implement changes with tests
Validate model performance
Submit pull request
Code Standards
PEP 8: Python code formatting
Type Hints: Function annotations
Docstrings: Comprehensive documentation
Testing: Unit tests for all components

Project: Neural Network Intrusion Detection System
Purpose: Enterprise cybersecurity and research
License: Educational and research use
🛡️ Enterprise-grade machine learning pipeline for cybersecurity applications.

🔗 Integrated with live production IDS deployment for real-world network protection.