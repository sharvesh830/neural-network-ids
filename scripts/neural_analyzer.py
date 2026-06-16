import torch
import joblib
import json
import numpy as np
from datetime import datetime
from pathlib import Path
from scripts.models.model_architectures import IDSClassifier, AnomalyAutoEncoder

class NeuralAnalyzer:
    def __init__(self, base_path='/home/sharvesh/neural_ids'):
        self.base_path = Path(base_path)
        self.device = torch.device('cpu')
        self._load_models()
        
        # Severity mapping
        self.severity_map = {
            'BENIGN': 'NONE',
            'DDoS': 'SEVERE',
            'DoS Hulk': 'SEVERE',
            'DoS GoldenEye': 'SEVERE',
            'DoS slowloris': 'SEVERE',
            'DoS Slowhttptest': 'SEVERE',
            'FTP-Patator': 'HIGH',
            'SSH-Patator': 'HIGH',
            'PortScan': 'MEDIUM',
            'Bot': 'HIGH',
            'Web Attack � Brute Force': 'HIGH',
            'Web Attack � XSS': 'HIGH',
            'Web Attack � Sql Injection': 'SEVERE',
            'Infiltration': 'SEVERE',
            'Heartbleed': 'SEVERE'
        }
    
    def _load_models(self):
        with open(self.base_path / 'models/model_metadata.json', 'r') as f:
            self.metadata = json.load(f)
        
        self.input_dim = self.metadata['input_dim']
        self.num_classes = self.metadata['num_classes']
        self.classes = self.metadata['classes']
        self.features = self.metadata['features']
        self.anomaly_threshold = self.metadata['anomaly_threshold']
        
        # Load classifier
        self.classifier = IDSClassifier(
            input_dim=self.input_dim,
            num_classes=self.num_classes,
            hidden_layers=self.metadata['classifier_params']['hidden_layers'],
            dropout=self.metadata['classifier_params']['dropout']
        )
        self.classifier.load_state_dict(
            torch.load(self.base_path / 'models/ids_classifier.pth', map_location=self.device)
        )
        self.classifier.eval()
        
        # Load autoencoder
        self.autoencoder = AnomalyAutoEncoder(
            input_dim=self.input_dim,
            encoding_dim=self.metadata['autoencoder_params']['encoding_dim'],
            hidden_layers=self.metadata['autoencoder_params']['hidden_layers']
        )
        self.autoencoder.load_state_dict(
            torch.load(self.base_path / 'models/anomaly_detector.pth', map_location=self.device)
        )
        self.autoencoder.eval()
        
        # Load scalers
        self.cls_scaler = joblib.load(self.base_path / 'models/classifier_scaler.pkl')
        self.ae_scaler = joblib.load(self.base_path / 'models/autoencoder_scaler.pkl')
        self.label_encoder = joblib.load(self.base_path / 'models/label_encoder.pkl')
        
        print(f"✅ Neural Analyzer Ready: {self.num_classes} classes, {self.input_dim} features")
    
    def analyze_flow(self, flow_features):
        try:
            feature_vector = np.array([
                flow_features.get(feat, 0.0) for feat in self.features
            ]).reshape(1, -1)
            
            feature_vector = np.nan_to_num(feature_vector, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Classifier prediction
            X_scaled = self.cls_scaler.transform(feature_vector)
            X_tensor = torch.FloatTensor(X_scaled).to(self.device)
            
            with torch.no_grad():
                outputs = self.classifier(X_tensor)
                probabilities = torch.softmax(outputs, dim=1)
                confidence, predicted_class = torch.max(probabilities, 1)
            
            predicted_label = self.classes[predicted_class.item()]
            confidence_score = confidence.item()
            
            # Autoencoder anomaly detection
            X_ae_scaled = self.ae_scaler.transform(feature_vector)
            X_ae_tensor = torch.FloatTensor(X_ae_scaled).to(self.device)
            
            with torch.no_grad():
                reconstructed = self.autoencoder(X_ae_tensor)
                reconstruction_error = torch.mean((X_ae_tensor - reconstructed) ** 2).item()
            
            is_anomaly = reconstruction_error > self.anomaly_threshold
            severity = self.severity_map.get(predicted_label, 'MEDIUM')
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'predicted_attack': predicted_label,
                'confidence': round(confidence_score * 100, 2),
                'severity': severity,
                'is_anomaly': bool(is_anomaly),
                'reconstruction_error': round(reconstruction_error, 6),
                'anomaly_threshold': round(self.anomaly_threshold, 6),
                'is_threat': predicted_label != 'BENIGN'
            }
            
            return result
            
        except Exception as e:
            print(f"Analysis error: {e}")
            return None

if __name__ == "__main__":
    # Test
    analyzer = NeuralAnalyzer()
    
    # Test with dummy data
    test_features = {feat: 0.0 for feat in analyzer.features}
    test_features['Flow Duration'] = 1000
    test_features['Total Fwd Packets'] = 10
    test_features['Total Backward Packets'] = 5
    
    result = analyzer.analyze_flow(test_features)
    print(f"\n🧪 Test Analysis:")
    print(f"Attack: {result['predicted_attack']}")
    print(f"Confidence: {result['confidence']}%")
    print(f"Severity: {result['severity']}")
    print(f"Is Threat: {result['is_threat']}")
