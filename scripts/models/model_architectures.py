import torch
import torch.nn as nn

class IDSClassifier(nn.Module):
    def __init__(self, input_dim, num_classes, hidden_layers=[128, 64, 32], dropout=0.3):
        super(IDSClassifier, self).__init__()
        
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
        
        layers.append(nn.Linear(prev_dim, num_classes))
        self.network = nn.Sequential(*layers)
        
    def forward(self, x):
        return self.network(x)

class AnomalyAutoEncoder(nn.Module):
    def __init__(self, input_dim, encoding_dim=32, hidden_layers=[64, 32]):
        super(AnomalyAutoEncoder, self).__init__()
        
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
