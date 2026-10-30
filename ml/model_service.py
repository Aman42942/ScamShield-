"""Load a compatible ScamShield model, rebuilding it when needed."""
from pathlib import Path
import json
import joblib
import pandas as pd
import sklearn
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "processed" / "cleaned_dataset.csv"
MODEL_PATH = ROOT / "models" / "scam_model.pkl"
META_PATH = ROOT / "models" / "model_metadata.json"


def train_and_save():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH).dropna(subset=["text", "label"])
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_features=12000)),
        ("classifier", LogisticRegression(max_iter=2500, class_weight="balanced")),
    ])
    model.fit(X_train, y_train)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    META_PATH.write_text(json.dumps({
        "scikit_learn_version": sklearn.__version__,
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "classes": list(model.classes_),
    }, indent=2), encoding="utf-8")
    return model


def load_or_train():
    # Persisted sklearn objects are version-sensitive. Rebuild if the artifact
    # was created with another sklearn version or cannot predict in this env.
    if MODEL_PATH.exists() and META_PATH.exists():
        try:
            meta = json.loads(META_PATH.read_text(encoding="utf-8"))
            if meta.get("scikit_learn_version") == sklearn.__version__:
                model = joblib.load(MODEL_PATH)
                model.predict_proba(["model compatibility check"])
                return model
        except Exception:
            pass
    return train_and_save()
