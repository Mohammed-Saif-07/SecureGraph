from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score
from xgboost import XGBClassifier

from core.ml.features import FEATURE_NAMES

MODEL_DIR = Path(__file__).resolve().parent / "models"

def train(csv_path: str, model_path: str | None = None, features_path: str | None = None) -> dict:
    """Train the exploit prediction model from an NVD/EPSS/exploit-in-wild dataset."""
    model_path = model_path or str(MODEL_DIR / "exploit_predictor.joblib")
    features_path = features_path or str(MODEL_DIR / "feature_names.pkl")
    df = pd.read_csv(csv_path)
    X = df[FEATURE_NAMES]
    y = df["exploited_in_wild"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = XGBClassifier(
        n_estimators=180,
        max_depth=4,
        learning_rate=0.06,
        subsample=0.9,
        eval_metric="logloss",
    )
    model.fit(X_train, y_train)
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    joblib.dump(FEATURE_NAMES, features_path)
    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    return {
        "model_path": model_path,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)) if len(set(y_test)) > 1 else 0.0,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train SecureGraph XGBoost exploit predictor.")
    parser.add_argument("csv_path")
    parser.add_argument("--model-path", default=str(MODEL_DIR / "exploit_predictor.joblib"))
    args = parser.parse_args()
    print(train(args.csv_path, model_path=args.model_path))
