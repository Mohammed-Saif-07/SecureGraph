from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from core.ml.features import FEATURE_NAMES


def train(csv_path: str, model_path: str = "models/xgboost_model.json", features_path: str = "models/feature_names.pkl") -> dict:
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
    model.save_model(model_path)
    joblib.dump(FEATURE_NAMES, features_path)
    return {"model_path": model_path, "accuracy": float(model.score(X_test, y_test))}
