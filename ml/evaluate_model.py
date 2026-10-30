from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from ml.model_service import load_or_train

ROOT = Path(__file__).resolve().parents[1]
df = pd.read_csv(ROOT / "data" / "processed" / "cleaned_dataset.csv")
X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
)
model = load_or_train()
pred = model.predict(X_test)
report = classification_report(y_test, pred)
cm = confusion_matrix(y_test, pred)
report_dir = ROOT / "reports"
report_dir.mkdir(exist_ok=True)
(report_dir / "evaluation.txt").write_text(
    "SCAMSHIELD BASELINE EVALUATION\n\n"
    f"Scikit-learn version: {__import__('sklearn').__version__}\n"
    f"Accuracy: {accuracy_score(y_test, pred):.4f}\n\n{report}\n"
    f"Confusion Matrix:\n{cm}\n",
    encoding="utf-8",
)
print(report)
print("Confusion Matrix:\n", cm)
