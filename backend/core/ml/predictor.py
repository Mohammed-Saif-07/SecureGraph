from __future__ import annotations

from pathlib import Path

from xgboost import XGBClassifier

from core.ml.features import cve_to_features


class ExploitPredictor:
    def __init__(self, model_path: str = "models/xgboost_model.json"):
        self.model_path = Path(model_path)
        self.model: XGBClassifier | None = None
        if self.model_path.exists():
            self.model = XGBClassifier()
            self.model.load_model(str(self.model_path))

    def predict(self, cve: dict) -> float:
        if not self.model:
            cvss = float(cve.get("cvss_score", 0)) / 10
            epss = float(cve.get("epss_score", 0))
            return round(max(cvss * 0.45 + epss * 0.55, epss), 4)
        return float(self.model.predict_proba([cve_to_features(cve)])[0][1])
