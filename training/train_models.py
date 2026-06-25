"""Train, tune, calibrate, and export baseline vulnerability models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import precision_recall_curve, f1_score, precision_score, recall_score


def evaluate_candidate(
    vectorizer: TfidfVectorizer,
    model: any,
    X_train: pd.Series,
    y_train: pd.Series,
    X_val: pd.Series,
    y_val: pd.Series,
) -> tuple[float, float, float, float, any]:
    """Train a candidate, compute probabilities on validation, and return metrics at threshold 0.5."""
    # Transform text
    X_train_vec = vectorizer.fit_transform(X_train)
    X_val_vec = vectorizer.transform(X_val)
    
    # Train
    model.fit(X_train_vec, y_train)
    
    # Predict
    probs = model.predict_proba(X_val_vec)[:, 1]
    preds = (probs >= 0.5).astype(int)
    
    # Calculate metrics
    prec = precision_score(y_val, preds, zero_division=0)
    rec = recall_score(y_val, preds, zero_division=0)
    f1 = f1_score(y_val, preds, zero_division=0)
    
    return f1, prec, rec, probs, model


def find_optimal_threshold(y_val: pd.Series, probs: np.ndarray, target_recall: float = 0.70) -> tuple[float, float, float]:
    """Find threshold that maximizes F1 score, or fallback to achieving target_recall if possible."""
    precisions, recalls, thresholds = precision_recall_curve(y_val, probs)
    
    # f1 = 2 * p * r / (p + r)
    f1_scores = np.zeros_like(thresholds)
    for i in range(len(thresholds)):
        p, r = precisions[i], recalls[i]
        if p + r > 0:
            f1_scores[i] = 2 * p * r / (p + r)
            
    best_idx = np.argmax(f1_scores)
    best_threshold = float(thresholds[best_idx])
    best_f1 = float(f1_scores[best_idx])
    
    # Also find threshold that guarantees target_recall (e.g. 70%) if F1 optimal is lower recall
    # (since security tools often favor recall to prevent missed vulns)
    recall_ok_indices = np.where(recalls >= target_recall)[0]
    if len(recall_ok_indices) > 0:
        # Of those with enough recall, pick the one with highest precision
        best_recall_idx = recall_ok_indices[np.argmax(precisions[recall_ok_indices])]
        if best_recall_idx < len(thresholds):
            recall_threshold = float(thresholds[best_recall_idx])
            recall_f1 = 2 * precisions[best_recall_idx] * recalls[best_recall_idx] / (precisions[best_recall_idx] + recalls[best_recall_idx])
            # If the recall threshold has a reasonable F1, we can prefer it or let user review
            # For this baseline, we will use the F1-maximizing threshold, but log the recall-targeted one.
            
    return best_threshold, best_f1, f1_scores[best_idx]


def train_pipeline(data_path: Path, output_dir: Path) -> dict:
    df = pd.read_parquet(data_path)
    
    # Filter splits
    train_df = df[df["split"] == "train"]
    val_df = df[df["split"] == "val"]
    
    X_train, y_train = train_df["cleaned_code"], train_df["label"]
    X_val, y_val = val_df["cleaned_code"], val_df["label"]
    
    # Define candidate pipelines
    candidates = [
        {
            "name": "word_tfidf_logistic_regression",
            "vectorizer": TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                max_features=5000,
                token_pattern=r"(?u)\b\w+\b",
            ),
            "model": LogisticRegression(C=1.0, class_weight="balanced", random_state=42, max_iter=1000),
        },
        {
            "name": "char_tfidf_logistic_regression",
            "vectorizer": TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                max_features=10000,
            ),
            "model": LogisticRegression(C=1.0, class_weight="balanced", random_state=42, max_iter=1000),
        },
        {
            "name": "char_tfidf_linear_svm",
            "vectorizer": TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                max_features=10000,
            ),
            "model": CalibratedClassifierCV(
                estimator=LinearSVC(C=1.0, dual=False, class_weight="balanced", random_state=42),
                method="sigmoid",
                cv=5,
            ),
        },
    ]
    
    best_name = None
    best_f1 = -1.0
    best_metrics = {}
    best_vectorizer = None
    best_model = None
    best_probs = None
    
    print("Training candidate models...")
    for cand in candidates:
        name = cand["name"]
        f1, prec, rec, probs, trained_model = evaluate_candidate(
            cand["vectorizer"],
            cand["model"],
            X_train,
            y_train,
            X_val,
            y_val,
        )
        print(f"- {name}: F1={f1:.4f}, Precision={prec:.4f}, Recall={rec:.4f}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_metrics = {"f1_at_0.5": f1, "precision_at_0.5": prec, "recall_at_0.5": rec}
            best_vectorizer = cand["vectorizer"]
            best_model = trained_model
            best_probs = probs
            
    # Find calibrated threshold for the best model
    opt_threshold, opt_f1, _ = find_optimal_threshold(y_val, best_probs)
    
    # Calculate metrics at optimal threshold
    opt_preds = (best_probs >= opt_threshold).astype(int)
    opt_prec = precision_score(y_val, opt_preds, zero_division=0)
    opt_rec = recall_score(y_val, opt_preds, zero_division=0)
    
    print(f"\nBest Model: {best_name}")
    print(f"Optimal Threshold: {opt_threshold:.4f} (F1={opt_f1:.4f}, Precision={opt_prec:.4f}, Recall={opt_rec:.4f})")
    
    # Save artifacts
    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, output_dir / "vulnerability_model.pkl")
    joblib.dump(best_vectorizer, output_dir / "tfidf_vectorizer.pkl")
    
    config = {
        "model_name": best_name,
        "optimal_threshold": opt_threshold,
        "validation_metrics": {
            "default_0.5": best_metrics,
            "optimal_threshold": {
                "f1": opt_f1,
                "precision": opt_prec,
                "recall": opt_rec,
            }
        }
    }
    
    (output_dir / "model_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/cvefixes_clean_pairs.parquet"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    train_pipeline(args.input, args.output_dir)
    print("Model training pipeline completed. Artifacts exported successfully.")


if __name__ == "__main__":
    main()
