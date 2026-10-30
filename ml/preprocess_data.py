from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
raw = ROOT / "data" / "raw" / "raw_dataset.csv"
out = ROOT / "data" / "processed" / "cleaned_dataset.csv"

df = pd.read_csv(raw).dropna(subset=["text", "label"])
df["text"] = df["text"].astype(str).str.replace(r"\s+", " ", regex=True).str.strip()
df["label"] = df["label"].astype(str).str.lower().str.strip()
df = df[df["label"].isin(["scam", "legitimate"])]
df = df.drop_duplicates(subset=["text"])
df = df[df["text"].str.len() >= 5]
out.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(out, index=False)
print("Cleaned rows:", len(df))
print(df["label"].value_counts())
