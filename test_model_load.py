import torch
import joblib
import json
from scripts.models.model_architectures import IDSClassifier, AnomalyAutoEncoder

print(" Loading Neural Network Models...")

# Load metadata
with open('models/model_metadata.json', 'r') as f:
    metadata = json.load(f)

device = torch.device('cpu')

# Load classifier
classifier = IDSClassifier(
    input_dim=metadata['input_dim'],
    num_classes=metadata['num_classes'],
    hidden_layers=metadata['classifier_params']['hidden_layers'],
    dropout=metadata['classifier_params']['dropout']
)
classifier.load_state_dict(torch.load('models/ids_classifier.pth', map_location=device))
classifier.eval()
print(" Classifier loaded")

# Load autoencoder
autoencoder = AnomalyAutoEncoder(
    input_dim=metadata['input_dim'],
    encoding_dim=metadata['autoencoder_params']['encoding_dim'],
    hidden_layers=metadata['autoencoder_params']['hidden_layers']
)
autoencoder.load_state_dict(torch.load('models/anomaly_detector.pth', map_location=device))
autoencoder.eval()
print(" Autoencoder loaded")

# Load scalers
cls_scaler = joblib.load('models/classifier_scaler.pkl')
ae_scaler = joblib.load('models/autoencoder_scaler.pkl')
label_encoder = joblib.load('models/label_encoder.pkl')
print(" Scalers loaded")

print(f"\n System Ready!")
print(f"Classes: {metadata['num_classes']}")
print(f"Features: {metadata['input_dim']}")
print(f"Threshold: {metadata['anomaly_threshold']}")
