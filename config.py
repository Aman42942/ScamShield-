from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RAW_DATA = BASE_DIR / "data" / "raw" / "raw_dataset.csv"
CLEAN_DATA = BASE_DIR / "data" / "processed" / "cleaned_dataset.csv"
MODEL_PATH = BASE_DIR / "models" / "scam_model.pkl"
REPORT_PATH = BASE_DIR / "reports" / "evaluation.txt"
