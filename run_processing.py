"""
Run data processing from project root
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import and run processor
from scripts.data_processing.process_cicids import main

if __name__ == "__main__":
    main()