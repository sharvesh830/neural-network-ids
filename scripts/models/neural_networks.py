import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

class IDSClassifier(nn.Module):
    """
    Multi-class neural network classifier for intrusion detection
    """
    def __init__(self, input_dim, num_classes, hidden_layers=[128, 64, 32], dropout=0.3):
        super(IDSClassifier, self).__init__()
        
        self.input_dim = input_dim
        self.num_classes = num_classes
        
        # Build layers
        layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_layers:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])
            prev_dim = hidden_dim
        
        # Output layer
        layers.append(nn.Linear(prev_dim, num_classes))
        
        self.network = nn.Sequential(*layers)
        
    def forward(self, x):
        return self.network(x)

class AnomalyAutoEncoder(nn.Module):
    """
    Autoencoder for anomaly detection in network traffic
    """
    def __init__(self, input_dim, encoding_dim=32, hidden_layers=[64, 32]):
        super(AnomalyAutoEncoder, self).__init__()
        
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        
        # Encoder
        encoder_layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_layers:
            encoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        encoder_layers.append(nn.Linear(prev_dim, encoding_dim))
        self.encoder = nn.Sequential(*encoder_layers)
        
        # Decoder (reverse of encoder)
        decoder_layers = []
        prev_dim = encoding_dim
        
        for hidden_dim in reversed(hidden_layers):
            decoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)
        
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        return self.encoder(x)

class FocalLoss(nn.Module):
    """
    Focal Loss for addressing class imbalance
    """
    def __init__(self, alpha=0.25, gamma=2.0, num_classes=None):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.num_classes = num_classes
        
    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = self.alpha * (1-pt)**self.gamma * ce_loss
        return focal_loss.mean()