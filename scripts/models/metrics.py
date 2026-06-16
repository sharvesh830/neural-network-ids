import torch
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.metrics import roc_auc_score, classification_report

class IDSMetrics:
    """
    Comprehensive metrics for IDS evaluation
    """
    def __init__(self, num_classes, class_names=None):
        self.num_classes = num_classes
        self.class_names = class_names
        
    def compute_metrics(self, y_true, y_pred, y_prob=None):
        """
        Compute comprehensive metrics
        """
        metrics = {}
        
        # Basic metrics
        metrics['accuracy'] = accuracy_score(y_true, y_pred)
        
        # Per-class metrics
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true, y_pred, average=None, zero_division=0
        )
        
        # Macro and weighted averages
        metrics['macro_precision'] = np.mean(precision)
        metrics['macro_recall'] = np.mean(recall)
        metrics['macro_f1'] = np.mean(f1)
        
        precision_w, recall_w, f1_w, _ = precision_recall_fscore_support(
            y_true, y_pred, average='weighted', zero_division=0
        )
        metrics['weighted_precision'] = precision_w
        metrics['weighted_recall'] = recall_w
        metrics['weighted_f1'] = f1_w
        
        # Confusion matrix
        metrics['confusion_matrix'] = confusion_matrix(y_true, y_pred)
        
        # ROC AUC (if probabilities provided)
        if y_prob is not None and self.num_classes == 2:
            metrics['roc_auc'] = roc_auc_score(y_true, y_prob[:, 1])
        elif y_prob is not None and self.num_classes > 2:
            try:
                metrics['roc_auc_macro'] = roc_auc_score(
                    y_true, y_prob, multi_class='ovr', average='macro'
                )
                metrics['roc_auc_weighted'] = roc_auc_score(
                    y_true, y_prob, multi_class='ovr', average='weighted'
                )
            except ValueError:
                # Handle case where not all classes are present
                pass
        
        # Classification report
        if self.class_names is not None:
            metrics['classification_report'] = classification_report(
                y_true, y_pred, target_names=self.class_names
            )
        
        return metrics
    
    def detection_rate_false_positive_rate(self, y_true, y_pred):
        """
        Compute Detection Rate and False Positive Rate for IDS
        """
        # Convert to binary: 0 = Normal, 1 = Attack
        y_true_binary = (y_true != 0).astype(int)  # Assuming class 0 is BENIGN
        y_pred_binary = (y_pred != 0).astype(int)
        
        # True Positives, False Positives, True Negatives, False Negatives
        tp = np.sum((y_true_binary == 1) & (y_pred_binary == 1))
        fp = np.sum((y_true_binary == 0) & (y_pred_binary == 1))
        tn = np.sum((y_true_binary == 0) & (y_pred_binary == 0))
        fn = np.sum((y_true_binary == 1) & (y_pred_binary == 0))
        
        # Detection Rate (True Positive Rate)
        detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # False Positive Rate
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        return {
            'detection_rate': detection_rate,
            'false_positive_rate': false_positive_rate,
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn
        }