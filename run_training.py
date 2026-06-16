"""
Main launcher for Neural Network IDS Training
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import and run training
from scripts.training.train_complete import main

if __name__ == "__main__":
    print("="*70)
    print("  Neural Network Intrusion Detection System - Training Pipeline")
    print("="*70)
    
    try:
        results = main()
        print("\n✅ Training completed successfully!")
    except KeyboardInterrupt:
        print("\n⚠️ Training interrupted by user")
    except Exception as e:
        print(f"\n❌ Training failed with error: {e}")
        import traceback
        traceback.print_exc()