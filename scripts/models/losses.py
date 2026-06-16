import torch
import torch.nn as nn
import torch.nn.functional as F

class WeightedFocalLoss(nn.Module):
    """
    Weighted Focal Loss for multi-class imbalanced dataset
    """
    def __init__(self, alpha=None, gamma=2.0, reduction='mean'):
        super(WeightedFocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction
        
    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, reduction='none', weight=self.alpha)
        pt = torch.exp(-ce_loss)
        focal_loss = (1 - pt) ** self.gamma * ce_loss
        
        if self.reduction == 'mean':
            return focal_loss.mean()
        elif self.reduction == 'sum':
            return focal_loss.sum()
        else:
            return focal_loss

class ReconstructionLoss(nn.Module):
    """
    Mean Squared Error loss for autoencoder reconstruction
    """
    def __init__(self):
        super(ReconstructionLoss, self).__init__()
        self.mse = nn.MSELoss()
        
    def forward(self, reconstructed, original):
        return self.mse(reconstructed, original)