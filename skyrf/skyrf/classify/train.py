"""Entrenamiento y evaluación del clasificador de protocolo."""

from __future__ import annotations

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from skyrf.capture.synthetic_source import generate_dataset
from skyrf.features.extract import FEATURE_NAMES, extract_window, split_windows

MODEL_PATH = "skyrf_protocol_model.joblib"


def build_xy(samples: int = 40, seed: int = 1337):
    """Genera dataset sintético y lo convierte en matrices X/y por ventana."""
    X, y = [], []
    for stream in generate_dataset(samples=samples, seed=seed):
        label = stream[0].protocol_hint
        for w in split_windows(stream, window_s=5.0):
            X.append(extract_window(w, window_s=5.0))
            y.append(label)
    return np.array(X), np.array(y)


def train(samples: int = 40, seed: int = 1337, model_path: str = MODEL_PATH):
    X, y = build_xy(samples=samples, seed=seed)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=seed, stratify=y)

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=200, max_depth=12, random_state=seed,
            class_weight="balanced")),
    ])
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, digits=3)
    cm = confusion_matrix(y_test, y_pred, labels=sorted(set(y)))

    joblib.dump({"model": model, "features": FEATURE_NAMES}, model_path)
    return model, report, cm, sorted(set(y))
