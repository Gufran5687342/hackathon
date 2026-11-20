"""
Isolation Forest anomaly detector for Smart Observability Platform.

Models are trained separately for each tenant and metric so that one
tenant's telemetry is never used to train another tenant's model.

A model requires at least MIN_TRAINING_SAMPLES historical observations.
Until that threshold is reached, the API should report that ML training
data is insufficient rather than pretending a rule-based result is ML.
"""

from collections import defaultdict
from math import isfinite
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest


MIN_TRAINING_SAMPLES = 20
DEFAULT_CONTAMINATION = 0.05


class IsolationForestDetector:
    def __init__(
        self,
        min_training_samples: int = MIN_TRAINING_SAMPLES,
        contamination: float = DEFAULT_CONTAMINATION,
        random_state: int = 42,
    ):
        if min_training_samples < 2:
            raise ValueError("min_training_samples must be at least 2")

        if not 0.0 < contamination <= 0.5:
            raise ValueError("contamination must be greater than 0 and at most 0.5")

        self.min_training_samples = min_training_samples
        self.contamination = contamination
        self.random_state = random_state
        self.models: dict[tuple[str, str], IsolationForest] = {}
        # Observations seen at the last training run (also kept when too few to train).
        self.training_counts: dict[tuple[str, str], int] = {}
        # Learned baseline per model, used to explain predictions.
        self.baselines: dict[tuple[str, str], dict[str, float]] = {}

    @staticmethod
    def _key(tenant_id: str, metric_name: str) -> tuple[str, str]:
        return tenant_id.strip(), metric_name.strip().lower()

    def train(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Train one model for each tenant + metric pair in records.

        Each record must contain tenant_id, metric_name and metric_value.
        """
        grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
        display_names: dict[tuple[str, str], str] = {}

        for record in records:
            tenant_id = str(record.get("tenant_id", "")).strip()
            metric_name = str(record.get("metric_name", "")).strip()

            if not tenant_id or not metric_name:
                continue

            try:
                value = float(record.get("metric_value"))
            except (TypeError, ValueError):
                continue

            if not isfinite(value):
                continue

            key = self._key(tenant_id, metric_name)
            grouped[key].append(value)
            display_names[key] = metric_name

        results = []

        for key, values in grouped.items():
            tenant_id, normalized_metric = key
            metric_name = display_names[key]
            sample_count = len(values)

            self.training_counts[key] = sample_count

            if sample_count < self.min_training_samples:
                # Drop any older model so we never score with stale or thin data.
                self.models.pop(key, None)
                self.baselines.pop(key, None)

                results.append({
                    "tenant_id": tenant_id,
                    "metric_name": metric_name,
                    "model_status": "insufficient_data",
                    "training_samples": sample_count,
                    "minimum_required": self.min_training_samples,
                    "message": (
                        f"Need at least {self.min_training_samples} observations "
                        f"for this metric; currently have {sample_count}."
                    ),
                })
                continue

            data = np.array(values, dtype=float).reshape(-1, 1)

            model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=self.random_state,
            )
            model.fit(data)

            self.models[key] = model
            self.baselines[key] = {
                "mean": float(np.mean(data)),
                "std": float(np.std(data)),
                "min": float(np.min(data)),
                "max": float(np.max(data)),
            }

            results.append({
                "tenant_id": tenant_id,
                "metric_name": metric_name,
                "model_status": "trained",
                "training_samples": sample_count,
                "baseline": {k: round(v, 3) for k, v in self.baselines[key].items()},
            })

        return {
            "models_trained": sum(1 for r in results if r["model_status"] == "trained"),
            "models_skipped": sum(1 for r in results if r["model_status"] != "trained"),
            "results": results,
        }

    def predict(self, tenant_id: str, metric_name: str, value: Any) -> dict[str, Any]:
        """
        Score one observation with that tenant's model for that metric.

        Never falls back to rules: if there is no trained model the result
        says so, and ml_anomaly_detected is None (unknown), not False.
        """
        key = self._key(tenant_id, metric_name)

        try:
            value = float(value)
        except (TypeError, ValueError):
            return {
                "model_status": "invalid_value",
                "ml_anomaly_detected": None,
                "message": "metric_value is not a number.",
            }

        if not isfinite(value):
            return {
                "model_status": "invalid_value",
                "ml_anomaly_detected": None,
                "message": "metric_value is not a finite number.",
            }

        model = self.models.get(key)

        if model is None:
            count = self.training_counts.get(key, 0)
            return {
                "model_status": "insufficient_data" if count else "not_trained",
                "ml_anomaly_detected": None,
                "training_samples": count,
                "minimum_required": self.min_training_samples,
                "message": (
                    f"No ML model for this metric yet: {count} of "
                    f"{self.min_training_samples} required observations."
                ),
            }

        point = np.array([[value]], dtype=float)
        is_anomaly = int(model.predict(point)[0]) == -1
        score = float(model.decision_function(point)[0])  # negative = more anomalous

        baseline = self.baselines[key]
        mean, std = baseline["mean"], baseline["std"]
        deviation = (value - mean) / std if std > 1e-9 else 0.0
        direction = "above" if value > mean else "below" if value < mean else "at"

        if is_anomaly:
            explanation = (
                f"{metric_name} = {value:g} is {abs(deviation):.1f} standard deviations "
                f"{direction} this tenant's learned baseline (mean {mean:.1f}). "
                f"Isolation Forest separated it from normal readings unusually quickly "
                f"(score {score:.3f}; negative means anomalous)."
            )
        else:
            explanation = (
                f"{metric_name} = {value:g} is within this tenant's learned baseline "
                f"(mean {mean:.1f}, observed range {baseline['min']:g} to {baseline['max']:g})."
            )

        return {
            "model_status": "trained",
            "ml_anomaly_detected": is_anomaly,
            "anomaly_score": round(score, 4),
            "deviation_std": round(deviation, 2),
            "training_samples": self.training_counts[key],
            "baseline_mean": round(mean, 2),
            "explanation": explanation,
        }
