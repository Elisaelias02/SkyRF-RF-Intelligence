"""Clasificación en vivo / offline con un modelo entrenado."""

from __future__ import annotations

import joblib

from skyrf.features.extract import extract_window, split_windows


def load_model(path: str):
    bundle = joblib.load(path)
    return bundle["model"], bundle["features"]


def classify_stream(model, stream, window_s: float = 5.0) -> list[dict]:
    """Clasifica cada ventana de un stream. Devuelve label + confianza."""
    results = []
    for w in split_windows(stream, window_s=window_s):
        feats = [extract_window(w, window_s=window_s)]
        proba = model.predict_proba(feats)[0]
        idx = int(proba.argmax())
        results.append({
            "t_start": w[0].timestamp,
            "label": model.classes_[idx],
            "confidence": float(proba[idx]),
            "n_packets": len(w),
        })
    return results
