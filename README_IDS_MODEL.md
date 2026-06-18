# 🛡️ Neural Network IDS - Windows Training Pipeline

Enterprise-grade machine learning training pipeline for developing neural network models that detect network intrusions and classify cyber attacks.

---

## 🎯 Overview

This project provides a complete Windows-based training environment for building and exporting machine learning models used by a live Ubuntu Intrusion Detection System (IDS).

### Key Features

* PyTorch-based neural network training
* CIC-IDS2017 dataset support (2.8M+ network flows)
* Multi-class attack classification (15 attack classes)
* Autoencoder-based anomaly detection
* Automated preprocessing and model packaging
* Ubuntu deployment integration
* Real-time inference ready

---

## 🏗️ Architecture

### Framework

* **Deep Learning:** PyTorch
* **Dataset:** CIC-IDS2017
* **Input Features:** 18 network flow features
* **Output Classes:** 15 attack types + Normal traffic
* **Models:** Classifier + Autoencoder

### Attack Detection Capabilities

* DDoS Attacks
* Port Scanning
* Botnet Communication
* SQL Injection
* Cross-Site Scripting (XSS)
* Web Brute Force Attacks
* SSH Brute Force
* FTP Brute Force
* DoS Hulk
* DoS GoldenEye
* DoS Slowloris
* Additional attack variants

---

# 📁 Project Structure

```text
IDS_Neural_Project/
│
├── 🚀 run_training.py
├── 🎯 main_launcher.py
│
├── 📊 scripts/
│   ├── data_processing/
│   │   └── process_cicids.py
│   │
│   ├── models/
│   │   ├── neural_networks.py
│   │   ├── losses.py
│   │   └── metrics.py
│   │
│   ├── training/
│   │   └── train_complete.py
│   │
│   ├── evaluation/
│   │
│   ├── export/
│   │   └── ubuntu_packager.py
│   │
│   └── utils/
│
├── 📂 config/
│   ├── neural_config.yaml
│   └── __init__.py
│
├── 📂 data/
├── 📂 models/
├── 📂 results/
├── 📂 logs/
├── 📂 notebooks/
│
├── 📋 requirements.txt
└── 📄 README.md
```

---

# 🚀 Quick Start

## 1. Environment Setup

```bash
python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt
```

---

## 2. Dataset Preparation

Download the CIC-IDS2017 dataset and place CSV files inside:

```text
data/raw/
```

Run preprocessing:

```bash
python scripts/data_processing/process_cicids.py
```

---

## 3. Train Models

Run the complete training pipeline:

```bash
python run_training.py
```

Alternative launcher:

```bash
python main_launcher.py
```

---

## 4. Deploy to Ubuntu IDS

Package trained models:

```bash
python scripts/export/ubuntu_packager.py
```

Deployment package will be generated in:

```text
models/ubuntu_deployment/
```

Copy the exported files to the Ubuntu IDS system.

---

# 📊 Training Pipeline

## Data Processing

* CIC-IDS2017 CSV loading
* Feature extraction
* Missing value handling
* Infinite value cleaning
* StandardScaler normalization
* Train / Validation / Test split

### Dataset Split

| Dataset    | Percentage |
| ---------- | ---------- |
| Training   | 70%        |
| Validation | 10%        |
| Testing    | 20%        |

---

# 🧠 Model Architectures

## Classifier Network

```text
Input (18)
   ↓
Dense (128)
   ↓
ReLU
   ↓
Dropout (0.3)
   ↓
Dense (64)
   ↓
ReLU
   ↓
Dropout (0.3)
   ↓
Dense (32)
   ↓
ReLU
   ↓
Dropout (0.3)
   ↓
Dense (15)
   ↓
Softmax
```

---

## Autoencoder Network

```text
Encoder
18 → 64 → 32 → 32

Decoder
32 → 64 → 18
```

---

# ⚙️ Training Features

* Focal Loss
* Early Stopping
* Learning Rate Scheduling
* GPU Acceleration (CUDA)
* Model Checkpointing
* Large Batch Processing

---

# 📈 Evaluation Metrics

The system evaluates models using:

* Accuracy
* Precision
* Recall
* F1-Score
* Detection Rate
* False Positive Rate
* Confusion Matrix
* ROC Curves

---

# 📊 Expected Performance

| Metric                | Target |
| --------------------- | ------ |
| Classifier Accuracy   | >95%   |
| Attack Detection Rate | >90%   |
| False Positive Rate   | <5%    |
| Inference Time        | <1 ms  |

### Training Requirements

| Resource | Recommendation |
| -------- | -------------- |
| RAM      | 8GB+           |
| Storage  | 10GB+          |
| GPU      | Recommended    |
| Python   | 3.8+           |

Training Time:

```text
30–60 minutes
```

Depending on hardware configuration.

---

# 🔧 Configuration

## neural_config.yaml

```yaml
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
```

---

# 🔢 Selected Features

The model uses 18 optimized network flow features including:

* Flow Duration
* Total Fwd Packets
* Total Bwd Packets
* Total Length of Fwd Packets
* Total Length of Bwd Packets
* Fwd Packet Length Mean
* Bwd Packet Length Mean
* Flow Bytes/s
* Flow Packets/s
* Destination Port
* Flow IAT Mean
* Flow IAT Std
* Fwd IAT Mean
* Bwd IAT Mean
* Packet Length Std
* Packet Length Variance
* SYN Flag Count
* ACK Flag Count

---

# 🔗 Ubuntu IDS Integration

## Exported Deployment Files

```text
models/ubuntu_deployment/

├── ids_classifier.pth
├── anomaly_detector.pth
├── classifier_scaler.pkl
├── label_encoder.pkl
└── model_metadata.json
```

These files are transferred to:

```bash
~/neural_ids/models/
```

on the Ubuntu production IDS.

---

# 🧪 Usage Examples

## Load Trained Model

```python
from scripts.models.neural_networks import IDSClassifier

model = IDSClassifier(
    input_dim=18,
    num_classes=15
)

model.load_state_dict(
    torch.load("models/final/ids_classifier.pth")
)
```

---

## Real-Time Prediction

```python
flow_features = extract_flow_features(packet_data)

prediction = model(flow_features)

attack_type = label_encoder.inverse_transform(
    [prediction.argmax()]
)

confidence = torch.softmax(
    prediction,
    dim=0
).max().item()
```

---

# 📚 Dataset Information

## CIC-IDS2017

| Property | Value                                |
| -------- | ------------------------------------ |
| Source   | Canadian Institute for Cybersecurity |
| Size     | 2.8M+ flows                          |
| Duration | 5 days                               |
| Labels   | 15 attack types + normal             |
| Features | 80+ available                        |

### Approximate Distribution

```text
BENIGN      ~80%
DDoS        ~12%
PortScan     ~5%
Others       ~3%
```

---

# 📦 Dependencies

```txt
torch>=1.9.0
pandas>=1.3.0
scikit-learn>=1.0.0
matplotlib>=3.4.0
seaborn>=0.11.0
tqdm>=4.62.0
pyyaml>=5.4.0
```

---

# 🧪 Testing

Run unit tests:

```bash
python -m pytest tests/
```

Validate syntax:

```bash
python -m py_compile run_training.py
```

Validate trained models:

```bash
python scripts/evaluation/validate_models.py
```

---

# 📊 Monitoring & Logging

## Training Logs

```text
logs/training.log
```

Includes:

* Training progress
* Validation metrics
* Errors and warnings
* Performance statistics

### Checkpoints

```text
models/training/
```

Features:

* Best model saving
* Automatic checkpointing
* Training recovery support

---

# 🚀 Production Deployment

The generated models are deployed within the live Ubuntu Neural IDS platform.

### Production Capabilities

| Metric             | Value           |
| ------------------ | --------------- |
| Throughput         | 1000+ flows/sec |
| Latency            | <1 ms           |
| Detection Accuracy | 95%+            |
| Availability       | 24/7            |

### Integrated Components

* Wazuh SIEM
* Email Alerting
* Automated Blocking
* Real-Time Packet Analysis
* Network Flow Monitoring

---

# 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes
4. Add tests
5. Validate model performance
6. Submit a pull request

---

# 📜 License

Educational and Research Use Only.

---

## 👨‍💻 Project Information

**Project:** Neural Network Intrusion Detection System

**Purpose:** Enterprise Cybersecurity Research and Intrusion Detection

**Technology Stack:** PyTorch, Python, Machine Learning, Network Security

---

🛡️ **Enterprise-grade machine learning pipeline for cybersecurity applications.**

🔗 **Integrated with a live Ubuntu IDS deployment for real-world network protection.**
