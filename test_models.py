import torch
import joblib
import json

print("Testing model loading...")

# Load metadata
with open('models/model_metadata.json', 'r') as f:
    metadata = json.load(f)

print(f" Metadata loaded: {metadata['num_classes']} classes")
print(f" Features: {len(metadata['features'])}")
print(f" Anomaly threshold: {metadata['anomaly_threshold']}")

# Load scalers
cls_scaler = joblib.load('models/classifier_scaler.pkl')
ae_scaler = joblib.load('models/autoencoder_scaler.pkl')
label_encoder = joblib.load('models/label_encoder.pkl')

print(f" Scalers loaded")
print(f" Classes: {label_encoder.classes_}")

print("\n All models loaded successfully!")
