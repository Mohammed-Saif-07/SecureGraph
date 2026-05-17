from __future__ import annotations

from pathlib import Path

import joblib
from xgboost import XGBClassifier

from core.ml.features import cve_to_features

MODEL_DIR = Path(__file__).resolve().parent / "models"

class ExploitPredictor:
    """Serve the trained XGBoost model with a calibrated heuristic fallback."""

    def __init__(self, model_path: str | None = None):
        self.model_path = Path(model_path) if model_path else MODEL_DIR / "exploit_predictor.joblib"
        self.model: XGBClassifier | None = None
        if self.model_path.exists():
            self.model = joblib.load(self.model_path)

    def predict(self, cve: dict) -> float:
        """Return exploit likelihood in the range [0, 1]."""
        if not self.model:
            cvss = float(cve.get("cvss_score", 0)) / 10
            epss = float(cve.get("epss_score", 0))
            reference_signal = min(float(cve.get("references_count", 0)) / 20, 1.0)
            patch_signal = 0.08 if cve.get("has_patch") or cve.get("patch_available") else 0.0
            return round(min(max(cvss * 0.35 + epss * 0.55 + reference_signal * 0.1 + patch_signal, epss), 1.0), 4)
        return float(self.model.predict_proba([cve_to_features(cve)])[0][1])
