import pandas as pd
import numpy as np
from pathlib import Path
import sys
import os
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Now import config
from config import config

class CICIDSProcessor:
    def __init__(self):
        self.base_path = Path(config.get('project.base_path'))
        self.raw_path = self.base_path / 'data' / 'raw'
        self.processed_path = self.base_path / 'data' / 'processed'
        self.features = config.get('features.selected_features')
        
        # Your specific files
        self.files = [
            "Monday-WorkingHours.pcap_ISCX.csv",
            "Tuesday-WorkingHours.pcap_ISCX.csv", 
            "Wednesday-workingHours.pcap_ISCX.csv",
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
            "Friday-WorkingHours-Morning-Bot.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
        ]
        
        print(f"Processor initialized")
        print(f"Raw data path: {self.raw_path}")
        print(f"Processed data path: {self.processed_path}")
    
    def check_files(self):
        """Check if all required files exist"""
        print("\n🔍 Checking for dataset files...")
        missing_files = []
        
        for file in self.files:
            file_path = self.raw_path / file
            if file_path.exists():
                size_mb = file_path.stat().st_size / (1024 * 1024)
                print(f"✅ {file} ({size_mb:.1f} MB)")
            else:
                print(f"❌ {file} - NOT FOUND")
                missing_files.append(file)
        
        if missing_files:
            print(f"\n⚠️  Missing {len(missing_files)} files!")
            print("Please place all files in:", self.raw_path)
            return False
        
        print(f"\n✅ All {len(self.files)} files found!")
        return True
    
    def load_single_file(self, filename):
        """Load and clean a single CSV file"""
        file_path = self.raw_path / filename
        
        try:
            print(f"\n📖 Loading {filename}...")
            
            # Read with different encoding attempts
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    print(f"   Loaded with {encoding} encoding")
                    break
                except UnicodeDecodeError:
                    continue
            else:
                raise Exception("Could not decode file with any encoding")
            
            print(f"   Shape: {df.shape}")
            print(f"   Columns: {len(df.columns)}")
            
            # Clean column names
            df.columns = df.columns.str.strip()
            
            # Check for label column variations
            label_columns = [col for col in df.columns if 'label' in col.lower()]
            if label_columns:
                label_col = label_columns[0]
                if label_col != 'Label':
                    df = df.rename(columns={label_col: 'Label'})
                print(f"   Label column: {label_col}")
            
            # Remove completely empty rows
            df = df.dropna(how='all')
            
            # Check attack types in this file
            if 'Label' in df.columns:
                attack_types = df['Label'].value_counts()
                print(f"   Attack types found:")
                for attack, count in attack_types.items():
                    print(f"     {attack}: {count:,}")
            
            return df
            
        except Exception as e:
            print(f"❌ Error loading {filename}: {e}")
            return None
    
    def combine_datasets(self):
        """Combine all CSV files into one dataset"""
        print("\n🔄 Combining datasets...")
        
        all_dataframes = []
        total_samples = 0
        attack_summary = {}
        
        for filename in tqdm(self.files, desc="Processing files"):
            df = self.load_single_file(filename)
            
            if df is not None and not df.empty:
                all_dataframes.append(df)
                total_samples += len(df)
                
                # Track attack types
                if 'Label' in df.columns:
                    for attack, count in df['Label'].value_counts().items():
                        attack_summary[attack] = attack_summary.get(attack, 0) + count
        
        if not all_dataframes:
            raise Exception("No valid dataframes loaded!")
        
        print(f"\n📊 Combining {len(all_dataframes)} datasets...")
        combined_df = pd.concat(all_dataframes, ignore_index=True, sort=False)
        
        print(f"✅ Combined dataset shape: {combined_df.shape}")
        print(f"📈 Total samples: {total_samples:,}")
        
        print(f"\n🎯 Attack Distribution:")
        for attack, count in sorted(attack_summary.items()):
            percentage = (count / total_samples) * 100
            print(f"   {attack}: {count:,} ({percentage:.1f}%)")
        
        return combined_df
    
    def clean_dataset(self, df):
        """Clean and prepare the dataset"""
        print(f"\n🧹 Cleaning dataset...")
        
        original_shape = df.shape
        print(f"Original shape: {original_shape}")
        
        # Remove infinite and NaN values
        print("Removing infinite values...")
        df = df.replace([np.inf, -np.inf], np.nan)
        
        print("Removing NaN values...")
        df = df.dropna()
        
        # Ensure we have our required features
        missing_features = []
        for feature in self.features:
            if feature not in df.columns:
                missing_features.append(feature)
        
        if missing_features:
            print(f"⚠️  Missing features: {missing_features}")
            # Try to find similar column names
            print("Available columns:")
            for col in sorted(df.columns):
                print(f"   {col}")
        
        print(f"Cleaned shape: {df.shape}")
        print(f"Removed: {original_shape[0] - df.shape[0]:,} samples")
        
        return df
    
    def sample_dataset(self, df, max_samples=800000):
        """Sample dataset to manageable size while preserving attack distribution"""
        if len(df) <= max_samples:
            print(f"Dataset size ({len(df):,}) is within limit ({max_samples:,})")
            return df
        
        print(f"\n🎲 Sampling dataset from {len(df):,} to {max_samples:,} samples...")
        
        # Separate normal and attack traffic
        normal_df = df[df['Label'] == 'BENIGN'].copy()
        attack_df = df[df['Label'] != 'BENIGN'].copy()
        
        # Keep all attack samples (they're usually minority)
        attack_samples = len(attack_df)
        normal_samples = min(len(normal_df), max_samples - attack_samples)
        
        print(f"Attack samples: {attack_samples:,}")
        print(f"Normal samples: {normal_samples:,}")
        
        # Sample normal traffic
        if normal_samples < len(normal_df):
            normal_df = normal_df.sample(n=normal_samples, random_state=42)
        
        # Combine
        sampled_df = pd.concat([normal_df, attack_df], ignore_index=True)
        sampled_df = sampled_df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
        
        print(f"✅ Sampled dataset shape: {sampled_df.shape}")
        
        return sampled_df
    
    def save_processed_dataset(self, df):
        """Save the processed dataset"""
        output_path = self.processed_path / 'cicids_combined.csv'
        
        print(f"\n💾 Saving processed dataset to: {output_path}")
        df.to_csv(output_path, index=False)
        
        # Save summary
        summary_path = self.processed_path / 'dataset_summary.txt'
        with open(summary_path, 'w') as f:
            f.write("CICIDS2017 Dataset Processing Summary\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Files processed: {len(self.files)}\n")
            f.write(f"Total samples: {len(df):,}\n")
            f.write(f"Features: {len(self.features)}\n\n")
            
            f.write("Attack Distribution:\n")
            f.write("-" * 30 + "\n")
            for attack, count in df['Label'].value_counts().items():
                percentage = (count / len(df)) * 100
                f.write(f"{attack}: {count:,} ({percentage:.1f}%)\n")
        
        print(f"✅ Dataset saved successfully!")
        print(f"📄 Summary saved to: {summary_path}")
        
        return output_path
    
    def process_all(self):
        """Complete processing pipeline"""
        print("🚀 Starting CICIDS2017 dataset processing...")
        
        # Check files
        if not self.check_files():
            return False
        
        try:
            # Combine datasets
            combined_df = self.combine_datasets()
            
            # Clean dataset
            cleaned_df = self.clean_dataset(combined_df)
            
            # Sample if needed
            final_df = self.sample_dataset(cleaned_df)
            
            # Save processed dataset
            output_path = self.save_processed_dataset(final_df)
            
            print(f"\n🎉 Processing complete!")
            print(f"📁 Output file: {output_path}")
            print(f"📊 Final dataset: {final_df.shape[0]:,} samples, {final_df.shape[1]} features")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Processing failed: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    processor = CICIDSProcessor()
    success = processor.process_all()
    
    if success:
        print("\n✅ Ready for neural network training!")
    else:
        print("\n❌ Please fix the issues and try again.")

if __name__ == "__main__":
    main()