
"""
Isolation Forest anomaly detector for Smart Observability Platform.

Separate models are maintained for each tenant and metric.
Insufficient training data is reported explicitly.
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
            raise ValueError(
                "min_training_samples must be at least 2"
            )

        if not 0.0 < contamination <= 0.5:
            raise ValueError(
                "contamination must be greater than 0 and at most 0.5"
            )

        self.min_training_samples = min_training_samples
        self.contamination = contamination
        self.random_state = random_state

        self.models: dict[
            tuple[str, str], IsolationForest
        ] = {}

        self.training_counts: dict[
            tuple[str, str], int
        ] = {}

        self.baselines: dict[
            tuple[str, str], dict[str, float]
        ] = {}

    @staticmethod
    def _key(
        tenant_id: str,
        metric_name: str
    ) -> tuple[str, str]:

        return (
            tenant_id.strip(),
            metric_name.strip().lower()
        )

    def train(
        self,
        records: list[dict[str, Any]]
    ) -> dict[str, Any]:

        grouped: dict[
            tuple[str, str], list[float]
        ] = defaultdict(list)

        display_names = {}

        for record in records:

            tenant_id = str(
                record.get("tenant_id", "")
            ).strip()

            metric_name = str(
                record.get("metric_name", "")
            ).strip()

            if not tenant_id or not metric_name:
                continue

            try:
                value = float(
                    record.get("metric_value")
                )
            except (TypeError, ValueError):
                continue

            if not isfinite(value):
                continue

            key = self._key(
                tenant_id,
                metric_name
            )

            grouped[key].append(value)
            display_names[key] = metric_name

        results = []

        for key, values in grouped.items():

            tenant_id, normalized_metric = key
            metric_name = display_names[key]
            sample_count = len(values)

            self.training_counts[key] = sample_count

            if sample_count < self.min_training_samples:

                self.models.pop(key, None)
                self.baselines.pop(key, None)

                results.append({
                    "tenant_id": tenant_id,
                    "metric_name": metric_name,
                    "model_status": "insufficient_data",
                    "training_samples": sample_count,
                    "minimum_required": (
                        self.min_training_samples
                    ),
                    "message": (
                        f"Need at least "
                        f"{self.min_training_samples} observations; "
                        f"currently have {sample_count}."
                    )
                })

                continue

            data = np.asarray(
                values,
                dtype=float
            ).reshape(-1, 1)

            model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=-1
            )

            model.fit(data)

            self.models[key] = model

            self.baselines[key] = {
                "mean": float(np.mean(data)),
                "std": float(np.std(data)),
                "min": float(np.min(data)),
                "max": float(np.max(data))
            }

            results.append({
                "tenant_id": tenant_id,
                "metric_name": metric_name,
                "model_status": "trained",
                "training_samples": sample_count,
                "baseline": {
                    name: round(value, 3)
                    for name, value
                    in self.baselines[key].items()
                }
            })

        return {
            "algorithm": "IsolationForest",
            "models_trained": sum(
                1 for result in results
                if result["model_status"] == "trained"
            ),
            "models_skipped": sum(
                1 for result in results
                if result["model_status"] != "trained"
            ),
            "results": results
        }

    def predict(
        self,
        tenant_id: str,
        metric_name: str,
        value: Any
    ) -> dict[str, Any]:

        key = self._key(
            tenant_id,
            metric_name
        )

        try:
            value = float(value)
        except (TypeError, ValueError):

            return {
                "model_status": "invalid_value",
                "ml_anomaly_detected": None,
                "message": "metric_value is not numeric."
            }

        if not isfinite(value):

            return {
                "model_status": "invalid_value",
                "ml_anomaly_detected": None,
                "message": "metric_value is not finite."
            }

        model = self.models.get(key)

        if model is None:

            count = self.training_counts.get(
                key,
                0
            )

            return {
                "model_status": (
                    "insufficient_data"
                    if count
                    else "not_trained"
                ),
                "ml_anomaly_detected": None,
                "training_samples": count,
                "minimum_required": (
                    self.min_training_samples
                ),
                "message": (
                    f"No trained ML model available: "
                    f"{count} of "
                    f"{self.min_training_samples} "
                    f"required observations."
                )
            }

        point = np.asarray(
            [[value]],
            dtype=float
        )

        prediction = int(
            model.predict(point)[0]
        )

        score = float(
            model.decision_function(point)[0]
        )

        baseline = self.baselines[key]

        mean = baseline["mean"]
        std = baseline["std"]

        deviation = (
            (value - mean) / std
            if std > 1e-9
            else 0.0
        )

        direction = (
            "above"
            if value > mean
            else "below"
            if value < mean
            else "at"
        )

        is_anomaly = prediction == -1

        if is_anomaly:

            explanation = (
                f"{metric_name} = {value:g} is "
                f"{abs(deviation):.1f} standard deviations "
                f"{direction} this tenant's learned baseline "
                f"(mean {mean:.1f}). Isolation Forest "
                f"identified an unusual observation "
                f"(score {score:.3f})."
            )

        else:

            explanation = (
                f"{metric_name} = {value:g} is within "
                f"the learned pattern "
                f"(mean {mean:.1f}, observed range "
                f"{baseline['min']:g} to "
                f"{baseline['max']:g})."
            )

        return {
            "model_status": "trained",
            "ml_anomaly_detected": is_anomaly,
            "anomaly_score": round(score, 4),
            "deviation_std": round(deviation, 2),
            "training_samples": self.training_counts[key],
            "baseline_mean": round(mean, 2),
            "explanation": explanation
        }

    def get_status(self) -> dict[str, Any]:

        models = []

        for (tenant_id, metric_name), count in (
            self.training_counts.items()
        ):

            models.append({
                "tenant_id": tenant_id,
                "metric_name": metric_name,
                "model_status": (
                    "trained"
                    if (tenant_id, metric_name) in self.models
                    else "insufficient_data"
                ),
                "training_samples": count
            })

        return {
            "algorithm": "IsolationForest",
            "minimum_training_samples": (
                self.min_training_samples
            ),
            "models_in_memory": len(self.models),
            "models": models,
            "persistence": (
                "Models are stored in memory. "
                "Retrain after restarting the backend."
            )
        }


# Shared detector instance is created by backend.py.
