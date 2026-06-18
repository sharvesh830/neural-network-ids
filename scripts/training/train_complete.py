import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from pathlib import Path
import sys
import json
import time
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import config
from scripts.models.neural_networks import IDSClassifier, AnomalyAutoEncoder, FocalLoss
from scripts.models.metrics import IDSMetrics

class CompleteIDSTrainer:
    """
    Complete training pipeline for Neural Network IDS
    """
    def __init__(self):
        self.config = config
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.base_path = Path(self.config.get('project.base_path'))
        
        # Paths
        self.data_path = self.base_path / 'data' / 'processed'
        self.model_path = self.base_path / 'models'
        self.results_path = self.base_path / 'results'
        
        # Create directories
        (self.model_path / 'training').mkdir(parents=True, exist_ok=True)
        (self.model_path / 'final').mkdir(parents=True, exist_ok=True)
        (self.results_path / 'training_history').mkdir(parents=True, exist_ok=True)
        (self.results_path / 'visualizations').mkdir(parents=True, exist_ok=True)
        (self.results_path / 'model_performance').mkdir(parents=True, exist_ok=True)
        print(f" IDS Trainer initialized")
        print(f"Device: {self.device}")
        print(f"Data path: {self.data_path}")
        print(f"Model path: {self.model_path}")
        
    def load_and_prepare_data(self):
        """
        Load and prepare data for training
        """
        print("\n Loading processed dataset...")
        
        # Load combined dataset
        data_file = self.data_path / 'cicids_combined.csv'
        df = pd.read_csv(data_file, encoding='utf-8-sig')
        
        print(f"Dataset shape: {df.shape}")
        print(f"Attack distribution:")
        for attack, count in df['Label'].value_counts().items():
            percentage = (count / len(df)) * 100
            print(f"  {attack}: {count:,} ({percentage:.1f}%)")
        
        # Separate features and labels
        feature_columns = [col for col in df.columns if col != 'Label']
        X = df[feature_columns].copy()
        y = df['Label'].copy()
        
        # Handle infinite and NaN values
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)
        
        # Select our specific features
        selected_features = self.config.get('features.selected_features')
        available_features = [feat for feat in selected_features if feat in X.columns]
        
        print(f"\n Using {len(available_features)} features:")
        for feat in available_features:
            print(f"   {feat}")
        
        missing_features = [feat for feat in selected_features if feat not in X.columns]
        if missing_features:
            print(f"\n Missing features:")
            for feat in missing_features:
                print(f"   {feat}")
        
        X_selected = X[available_features].copy()
        
        # Encode labels
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Store class information
        self.classes = self.label_encoder.classes_
        self.num_classes = len(self.classes)
        
        print(f"\n Class encoding:")
        for i, class_name in enumerate(self.classes):
            print(f"  {i}: {class_name}")
        
        return X_selected, y_encoded
    
    def split_and_scale_data(self, X, y):
        """
        Split data and apply scaling
        """
        print("\n Splitting and scaling data...")
        
        # Split data
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=0.125, random_state=42, stratify=y_temp  # 0.125 * 0.8 = 0.1
        )
        
        print(f"Train set: {X_train.shape[0]:,} samples")
        print(f"Validation set: {X_val.shape[0]:,} samples") 
        print(f"Test set: {X_test.shape[0]:,} samples")
        
        # Scale features for classifier
        self.classifier_scaler = StandardScaler()
        X_train_scaled = self.classifier_scaler.fit_transform(X_train)
        X_val_scaled = self.classifier_scaler.transform(X_val)
        X_test_scaled = self.classifier_scaler.transform(X_test)
        
        # Scale features for autoencoder (using normal traffic only)
        normal_mask = y_train == 0  # Assuming class 0 is BENIGN
        X_train_normal = X_train[normal_mask]
        
        self.autoencoder_scaler = StandardScaler()
        X_train_normal_scaled = self.autoencoder_scaler.fit_transform(X_train_normal)
        X_train_ae_scaled = self.autoencoder_scaler.transform(X_train)
        X_val_ae_scaled = self.autoencoder_scaler.transform(X_val)
        X_test_ae_scaled = self.autoencoder_scaler.transform(X_test)
        
        # Convert to tensors
        self.train_data = {
            'X': torch.FloatTensor(X_train_scaled).to(self.device),
            'y': torch.LongTensor(y_train).to(self.device),
            'X_ae': torch.FloatTensor(X_train_ae_scaled).to(self.device),
            'X_normal': torch.FloatTensor(X_train_normal_scaled).to(self.device)
        }
        
        self.val_data = {
            'X': torch.FloatTensor(X_val_scaled).to(self.device),
            'y': torch.LongTensor(y_val).to(self.device),
            'X_ae': torch.FloatTensor(X_val_ae_scaled).to(self.device)
        }
        
        self.test_data = {
            'X': torch.FloatTensor(X_test_scaled).to(self.device),
            'y': torch.LongTensor(y_test).to(self.device),
            'X_ae': torch.FloatTensor(X_test_ae_scaled).to(self.device)
        }
        
        self.input_dim = X_train_scaled.shape[1]
        print(f"Input dimension: {self.input_dim}")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def create_models(self):
        """
        Create neural network models
        """
        print("\n Creating neural network models...")
        
        # Classifier
        self.classifier = IDSClassifier(
            input_dim=self.input_dim,
            num_classes=self.num_classes,
            hidden_layers=self.config.get('models.classifier.hidden_layers', [128, 64, 32]),
            dropout=self.config.get('models.classifier.dropout', 0.3)
        ).to(self.device)
        
        # Autoencoder
        self.autoencoder = AnomalyAutoEncoder(
            input_dim=self.input_dim,
            encoding_dim=self.config.get('models.autoencoder.encoding_dim', 32),
            hidden_layers=self.config.get('models.autoencoder.hidden_layers', [64, 32])
        ).to(self.device)
        
        print(f" Classifier: {sum(p.numel() for p in self.classifier.parameters()):,} parameters")
        print(f" Autoencoder: {sum(p.numel() for p in self.autoencoder.parameters()):,} parameters")
        
        # Loss functions
        self.classifier_criterion = FocalLoss(
            alpha=self.config.get('models.classifier.focal_loss_alpha', 0.25),
            gamma=self.config.get('models.classifier.focal_loss_gamma', 2.0)
        )
        self.autoencoder_criterion = nn.MSELoss()
        
        # Optimizers
        self.classifier_optimizer = optim.Adam(
            self.classifier.parameters(),
            lr=self.config.get('models.classifier.learning_rate', 0.001)
        )
        self.autoencoder_optimizer = optim.Adam(
            self.autoencoder.parameters(),
            lr=self.config.get('models.autoencoder.learning_rate', 0.001)
        )
        
        # Learning rate schedulers
        self.classifier_scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            self.classifier_optimizer, mode='min', patience=5, factor=0.5
        )
        self.autoencoder_scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            self.autoencoder_optimizer, mode='min', patience=5, factor=0.5
        )
    
    def create_data_loaders(self):
        """
        Create data loaders
        """
        # Classifier data loaders
        train_dataset = TensorDataset(self.train_data['X'], self.train_data['y'])
        val_dataset = TensorDataset(self.val_data['X'], self.val_data['y'])
        
        self.train_loader = DataLoader(
            train_dataset,
            batch_size=self.config.get('models.classifier.batch_size', 1024),
            shuffle=True
        )
        self.val_loader = DataLoader(
            val_dataset,
            batch_size=self.config.get('models.classifier.batch_size', 1024),
            shuffle=False
        )
        
        # Autoencoder data loaders (normal traffic only for training)
        normal_dataset = TensorDataset(self.train_data['X_normal'], self.train_data['X_normal'])
        val_ae_dataset = TensorDataset(self.val_data['X_ae'], self.val_data['X_ae'])
        
        self.normal_loader = DataLoader(
            normal_dataset,
            batch_size=self.config.get('models.autoencoder.batch_size', 512),
            shuffle=True
        )
        self.val_ae_loader = DataLoader(
            val_ae_dataset,
            batch_size=self.config.get('models.autoencoder.batch_size', 512),
            shuffle=False
        )
    
    def train_classifier(self):
        """
        Train the classifier network
        """
        print(f"\n Training Classifier...")
        
        num_epochs = self.config.get('models.classifier.epochs', 50)
        best_val_loss = float('inf')
        patience_counter = 0
        patience = self.config.get('training.early_stopping_patience', 10)
        
        train_losses = []
        val_losses = []
        val_accuracies = []
        
        for epoch in range(num_epochs):
            # Training
            self.classifier.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0
            
            progress_bar = tqdm(self.train_loader, desc=f'Epoch {epoch+1}/{num_epochs}')
            for batch_X, batch_y in progress_bar:
                self.classifier_optimizer.zero_grad()
                
                outputs = self.classifier(batch_X)
                loss = self.classifier_criterion(outputs, batch_y)
                
                loss.backward()
                self.classifier_optimizer.step()
                
                train_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                train_total += batch_y.size(0)
                train_correct += (predicted == batch_y).sum().item()
                
                progress_bar.set_postfix({
                    'Loss': f'{loss.item():.4f}',
                    'Acc': f'{100.*train_correct/train_total:.1f}%'
                })
            
            # Validation
            self.classifier.eval()
            val_loss = 0.0
            val_correct = 0
            val_total = 0
            
            with torch.no_grad():
                for batch_X, batch_y in self.val_loader:
                    outputs = self.classifier(batch_X)
                    loss = self.classifier_criterion(outputs, batch_y)
                    
                    val_loss += loss.item()
                    _, predicted = torch.max(outputs.data, 1)
                    val_total += batch_y.size(0)
                    val_correct += (predicted == batch_y).sum().item()
            
            # Calculate averages
            train_loss = train_loss / len(self.train_loader)
            val_loss = val_loss / len(self.val_loader)
            val_accuracy = 100. * val_correct / val_total
            
            train_losses.append(train_loss)
            val_losses.append(val_loss)
            val_accuracies.append(val_accuracy)
            
            print(f'Epoch {epoch+1}/{num_epochs}:')
            print(f'  Train Loss: {train_loss:.4f}')
            print(f'  Val Loss: {val_loss:.4f}, Val Acc: {val_accuracy:.2f}%')
            
            # Learning rate scheduling
            self.classifier_scheduler.step(val_loss)
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                torch.save(self.classifier.state_dict(), 
                          self.model_path / 'training' / 'best_classifier.pth')
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f'Early stopping at epoch {epoch+1}')
                    break
        
        # Load best model
        self.classifier.load_state_dict(
            torch.load(self.model_path / 'training' / 'best_classifier.pth')
        )
        
        # Save training history
        history = {
            'train_losses': train_losses,
            'val_losses': val_losses,
            'val_accuracies': val_accuracies
        }
        
        return history
    
    def train_autoencoder(self):
        """
        Train the autoencoder for anomaly detection
        """
        print(f"\n Training Autoencoder...")
        
        num_epochs = self.config.get('models.autoencoder.epochs', 30)
        best_val_loss = float('inf')
        patience_counter = 0
        patience = self.config.get('training.early_stopping_patience', 10)
        
        train_losses = []
        val_losses = []
        
        for epoch in range(num_epochs):
            # Training
            self.autoencoder.train()
            train_loss = 0.0
            
            progress_bar = tqdm(self.normal_loader, desc=f'AE Epoch {epoch+1}/{num_epochs}')
            for batch_X, _ in progress_bar:  # _ because input and target are the same
                self.autoencoder_optimizer.zero_grad()
                
                reconstructed = self.autoencoder(batch_X)
                loss = self.autoencoder_criterion(reconstructed, batch_X)
                
                loss.backward()
                self.autoencoder_optimizer.step()
                
                train_loss += loss.item()
                
                progress_bar.set_postfix({
                    'Loss': f'{loss.item():.6f}'
                })
            
            # Validation
            self.autoencoder.eval()
            val_loss = 0.0
            
            with torch.no_grad():
                for batch_X, _ in self.val_ae_loader:
                    reconstructed = self.autoencoder(batch_X)
                    loss = self.autoencoder_criterion(reconstructed, batch_X)
                    val_loss += loss.item()
            
            # Calculate averages
            train_loss = train_loss / len(self.normal_loader)
            val_loss = val_loss / len(self.val_ae_loader)
            
            train_losses.append(train_loss)
            val_losses.append(val_loss)
            
            print(f'AE Epoch {epoch+1}/{num_epochs}:')
            print(f'  Train Loss: {train_loss:.6f}')
            print(f'  Val Loss: {val_loss:.6f}')
            
            # Learning rate scheduling
            self.autoencoder_scheduler.step(val_loss)
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                torch.save(self.autoencoder.state_dict(), 
                          self.model_path / 'training' / 'best_autoencoder.pth')
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f'AE Early stopping at epoch {epoch+1}')
                    break
        
        # Load best model
        self.autoencoder.load_state_dict(
            torch.load(self.model_path / 'training' / 'best_autoencoder.pth')
        )
        
        # Calculate anomaly threshold
        self.calculate_anomaly_threshold()
        
        # Save training history
        history = {
            'train_losses': train_losses,
            'val_losses': val_losses
        }
        
        return history
    
    def calculate_anomaly_threshold(self):
        """
        Calculate anomaly detection threshold using normal traffic
        """
        print("\n Calculating anomaly threshold...")
        
        self.autoencoder.eval()
        reconstruction_errors = []
        
        with torch.no_grad():
            # Calculate reconstruction errors on normal traffic
            for batch_X, _ in self.normal_loader:
                reconstructed = self.autoencoder(batch_X)
                mse = torch.mean((batch_X - reconstructed) ** 2, dim=1)
                reconstruction_errors.extend(mse.cpu().numpy())
        
        reconstruction_errors = np.array(reconstruction_errors)
        
        # Set threshold at 95th percentile of normal traffic reconstruction errors
        self.anomaly_threshold = np.percentile(reconstruction_errors, 95)
        
        print(f"Anomaly threshold: {self.anomaly_threshold:.6f}")
        print(f"Mean reconstruction error (normal): {np.mean(reconstruction_errors):.6f}")
        print(f"Std reconstruction error (normal): {np.std(reconstruction_errors):.6f}")
    
    def evaluate_classifier(self):
        """
        Evaluate classifier performance
        """
        print("\n Evaluating Classifier...")
        
        self.classifier.eval()
        y_true = []
        y_pred = []
        y_prob = []
        
        with torch.no_grad():
            for batch_X, batch_y in DataLoader(
                TensorDataset(self.test_data['X'], self.test_data['y']),
                batch_size=1024, shuffle=False
            ):
                outputs = self.classifier(batch_X)
                probabilities = torch.softmax(outputs, dim=1)
                _, predicted = torch.max(outputs, 1)
                
                y_true.extend(batch_y.cpu().numpy())
                y_pred.extend(predicted.cpu().numpy())
                y_prob.extend(probabilities.cpu().numpy())
        
        # Calculate metrics
        metrics_calculator = IDSMetrics(self.num_classes, self.classes)
        metrics = metrics_calculator.compute_metrics(
            np.array(y_true), np.array(y_pred), np.array(y_prob)
        )
        
        # Detection rate and false positive rate
        ids_metrics = metrics_calculator.detection_rate_false_positive_rate(
            np.array(y_true), np.array(y_pred)
        )
        
        print(f"\n Classifier Performance:")
        print(f"  Accuracy: {metrics['accuracy']:.4f}")
        print(f"  Weighted F1: {metrics['weighted_f1']:.4f}")
        print(f"  Detection Rate: {ids_metrics['detection_rate']:.4f}")
        print(f"  False Positive Rate: {ids_metrics['false_positive_rate']:.4f}")
        
        return metrics, ids_metrics
    
    def evaluate_autoencoder(self):
        """
        Evaluate autoencoder anomaly detection
        """
        print("\n Evaluating Autoencoder...")
        
        self.autoencoder.eval()
        y_true_binary = []
        y_pred_binary = []
        reconstruction_errors = []
        
        with torch.no_grad():
            for batch_X, batch_y in DataLoader(
                TensorDataset(self.test_data['X_ae'], self.test_data['y']),
                batch_size=1024, shuffle=False
            ):
                reconstructed = self.autoencoder(batch_X)
                mse = torch.mean((batch_X - reconstructed) ** 2, dim=1)
                
                # Binary classification: 0 = Normal, 1 = Anomaly
                true_binary = (batch_y != 0).cpu().numpy()  # 0 is BENIGN class
                pred_binary = (mse.cpu().numpy() > self.anomaly_threshold).astype(int)
                
                y_true_binary.extend(true_binary)
                y_pred_binary.extend(pred_binary)
                reconstruction_errors.extend(mse.cpu().numpy())
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        accuracy = accuracy_score(y_true_binary, y_pred_binary)
        precision = precision_score(y_true_binary, y_pred_binary)
        recall = recall_score(y_true_binary, y_pred_binary)
        f1 = f1_score(y_true_binary, y_pred_binary)
        
        print(f"\n Autoencoder Performance:")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall (Detection Rate): {recall:.4f}")
        print(f"  F1 Score: {f1:.4f}")
        
        ae_metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'threshold': self.anomaly_threshold
        }
        
        return ae_metrics
    
    def save_models(self):
        """
        Save trained models and preprocessing objects
        """
        print("\n Saving trained models...")
        
        # Save model weights
        torch.save(self.classifier.state_dict(), 
                   self.model_path / 'final' / 'ids_classifier.pth')
        torch.save(self.autoencoder.state_dict(), 
                   self.model_path / 'final' / 'anomaly_detector.pth')
        
        # Save preprocessing objects
        joblib.dump(self.classifier_scaler, 
                    self.model_path / 'final' / 'classifier_scaler.pkl')
        joblib.dump(self.autoencoder_scaler, 
                    self.model_path / 'final' / 'autoencoder_scaler.pkl')
        joblib.dump(self.label_encoder, 
                    self.model_path / 'final' / 'label_encoder.pkl')
        
        # Save model metadata (convert numpy types to Python types)
        metadata = {
            'input_dim': int(self.input_dim),
            'num_classes': int(self.num_classes),
            'classes': [str(c) for c in self.classes.tolist()],
            'anomaly_threshold': float(self.anomaly_threshold),
            'classifier_params': {
                'hidden_layers': self.config.get('models.classifier.hidden_layers'),
                'dropout': float(self.config.get('models.classifier.dropout'))
            },
            'autoencoder_params': {
                'encoding_dim': int(self.config.get('models.autoencoder.encoding_dim')),
                'hidden_layers': self.config.get('models.autoencoder.hidden_layers')
            },
            'features': self.config.get('features.selected_features')
        }
        
        with open(self.model_path / 'final' / 'model_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(" Models saved successfully!")
    
    def plot_training_history(self, cls_history, ae_history):
        """
        Plot training curves
        """
        print("\n Creating training visualizations...")
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Classifier loss
        axes[0, 0].plot(cls_history['train_losses'], label='Train Loss', color='blue')
        axes[0, 0].plot(cls_history['val_losses'], label='Val Loss', color='red')
        axes[0, 0].set_title('Classifier Training Loss')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Loss')
        axes[0, 0].legend()
        axes[0, 0].grid(True)
        
        # Classifier accuracy
        axes[0, 1].plot(cls_history['val_accuracies'], label='Val Accuracy', color='green')
        axes[0, 1].set_title('Classifier Validation Accuracy')
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Accuracy (%)')
        axes[0, 1].legend()
        axes[0, 1].grid(True)
        
        # Autoencoder loss
        axes[1, 0].plot(ae_history['train_losses'], label='Train Loss', color='blue')
        axes[1, 0].plot(ae_history['val_losses'], label='Val Loss', color='red')
        axes[1, 0].set_title('Autoencoder Training Loss')
        axes[1, 0].set_xlabel('Epoch')
        axes[1, 0].set_ylabel('MSE Loss')
        axes[1, 0].legend()
        axes[1, 0].grid(True)
        
        # Remove empty subplot
        axes[1, 1].axis('off')
        
        plt.tight_layout()
        plt.savefig(self.results_path / 'visualizations' / 'training_curves.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print(" Training curves saved!")
    
    def train_complete_system(self):
        """
        Complete training pipeline
        """
        start_time = time.time()
        
        print(" Starting Complete Neural Network IDS Training")
        print("=" * 60)
        
        # Load and prepare data
        X, y = self.load_and_prepare_data()
        X_train, X_val, X_test, y_train, y_val, y_test = self.split_and_scale_data(X, y)
        
        # Create models and data loaders
        self.create_models()
        self.create_data_loaders()
        
        # Train classifier
        print("\n" + "="*60)
        cls_history = self.train_classifier()
        
        # Train autoencoder
        print("\n" + "="*60)
        ae_history = self.train_autoencoder()
        
        # Evaluate models
        print("\n" + "="*60)
        cls_metrics, cls_ids_metrics = self.evaluate_classifier()
        ae_metrics = self.evaluate_autoencoder()
        
        # Save everything
        self.save_models()
        self.plot_training_history(cls_history, ae_history)
        
        # Save evaluation results
        results = {
            'classifier_metrics': cls_metrics,
            'classifier_ids_metrics': cls_ids_metrics,
            'autoencoder_metrics': ae_metrics,
            'training_time': time.time() - start_time
        }
        
        with open(self.results_path / 'model_performance' / 'evaluation_results.json', 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            json_results = {}
            for key, value in results.items():
                if isinstance(value, dict):
                    json_results[key] = {}
                    for k, v in value.items():
                        if isinstance(v, np.ndarray):
                            json_results[key][k] = v.tolist()
                        elif hasattr(v, 'item'):  # numpy scalars
                            json_results[key][k] = v.item()
                        else:
                            json_results[key][k] = v
                else:
                    json_results[key] = value
            json.dump(json_results, f, indent=2)
        
        training_time = time.time() - start_time
        
        print("\n" + "="*60)
        print(" Training Complete!")
        print(f" Total training time: {training_time:.2f} seconds ({training_time/60:.1f} minutes)")
        print(f" Classifier Accuracy: {cls_metrics['accuracy']:.1%}")
        print(f" Autoencoder F1: {ae_metrics['f1_score']:.1%}")
        print(" Models saved to:", self.model_path / 'final')
        print(" Results saved to:", self.results_path)
        print("=" * 60)
        
        return results

def main():
       """
        Main training function
       """
       trainer = CompleteIDSTrainer()
       results = trainer.train_complete_system()
       return results

if __name__ == "__main__":
       results = main()
