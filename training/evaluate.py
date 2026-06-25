"""Evaluate the selected vulnerability detection model on unseen test repositories."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)


def evaluate_split(
    df: pd.DataFrame,
    vectorizer: any,
    model: any,
    threshold: float,
) -> tuple[dict, pd.DataFrame]:
    """Evaluate predictions on the split and return metrics and prediction df."""
    X_vec = vectorizer.transform(df["cleaned_code"])
    probs = model.predict_proba(X_vec)[:, 1]
    preds = (probs >= threshold).astype(int)
    
    y = df["label"]
    
    cm = confusion_matrix(y, preds)
    tn, fp, fn, tp = cm.ravel()
    
    metrics = {
        "accuracy": float(accuracy_score(y, preds)),
        "precision": float(precision_score(y, preds, zero_division=0)),
        "recall": float(recall_score(y, preds, zero_division=0)),
        "f1": float(f1_score(y, preds, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, probs)),
        "pr_auc": float(average_precision_score(y, probs)),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        }
    }
    
    eval_df = df.copy()
    eval_df["prob"] = probs
    eval_df["pred"] = preds
    return metrics, eval_df


def analyze_cwe_performance(eval_df: pd.DataFrame) -> dict:
    """Analyze performance per CWE code."""
    cwe_results = {}
    
    # We explode by CWE
    exploded = eval_df.copy()
    exploded["cwe"] = exploded["cwe_ids"].fillna("").str.split(",")
    exploded = exploded.explode("cwe")
    exploded["cwe"] = exploded["cwe"].str.strip()
    exploded = exploded[exploded["cwe"] != ""]
    
    if len(exploded) == 0:
        return {}
        
    for cwe, group in exploded.groupby("cwe"):
        y = group["label"]
        preds = group["pred"]
        
        # Only evaluate CWEs with at least 5 instances
        if len(group) < 5:
            continue
            
        rec = recall_score(y, preds, zero_division=0)
        cwe_results[cwe] = {
            "samples": int(len(group)),
            "vulnerable_samples": int(y.sum()),
            "recall": float(rec),
        }
        
    return cwe_results


def analyze_nloc_performance(eval_df: pd.DataFrame) -> dict:
    """Analyze performance by lines of code (nloc) size."""
    nloc_results = {}
    
    def get_nloc_bucket(nloc):
        if pd.isna(nloc):
            return "unknown"
        elif nloc < 10:
            return "<10 lines"
        elif nloc <= 30:
            return "10-30 lines"
        else:
            return ">30 lines"
            
    eval_df["nloc_bucket"] = eval_df["nloc"].map(get_nloc_bucket)
    
    for bucket, group in eval_df.groupby("nloc_bucket"):
        y = group["label"]
        preds = group["pred"]
        
        prec = precision_score(y, preds, zero_division=0)
        rec = recall_score(y, preds, zero_division=0)
        f1 = f1_score(y, preds, zero_division=0)
        
        nloc_results[bucket] = {
            "samples": int(len(group)),
            "vulnerable_samples": int(y.sum()),
            "precision": float(prec),
            "recall": float(rec),
            "f1": float(f1),
        }
        
    return nloc_results


def generate_markdown_report(metrics: dict, cwe_perf: dict, nloc_perf: dict, model_name: str, threshold: float) -> str:
    cm = metrics["confusion_matrix"]
    
    report_lines = [
        f"# Sentinel Vulnerability Detection — Model Evaluation Report",
        "",
        f"**Model Name**: `{model_name}`",
        f"**Classification Probability Threshold**: `{threshold:.4f}`",
        "",
        "## Overall Test Metrics (Unseen Repositories)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Accuracy | {metrics['accuracy']:.2%} |",
        f"| Precision (Vulnerable Class) | {metrics['precision']:.2%} |",
        f"| Recall (Vulnerable Class) | {metrics['recall']:.2%} |",
        f"| F1-Score | {metrics['f1']:.4f} |",
        f"| ROC-AUC | {metrics['roc_auc']:.4f} |",
        f"| PR-AUC | {metrics['pr_auc']:.4f} |",
        "",
        "### Confusion Matrix",
        "",
        "| | Predicted Clean (0) | Predicted Vulnerable (1) |",
        "|---|---:|---:|",
        f"| **Actual Clean (0)** | {cm['tn']:,} | {cm['fp']:,} |",
        f"| **Actual Vulnerable (1)** | {cm['fn']:,} | {cm['tp']:,} |",
        "",
        "## Performance by CWE (Vulnerable Recall)",
        "",
        "| CWE | Total Samples | Vulnerable Samples | Recall |",
        "|---|---:|---:|---:|",
    ]
    
    # Sort CWEs by sample size descending
    sorted_cwes = sorted(cwe_perf.items(), key=lambda item: item[1]["samples"], reverse=True)
    for cwe, stats in sorted_cwes:
        report_lines.append(
            f"| {cwe} | {stats['samples']:,} | {stats['vulnerable_samples']:,} | {stats['recall']:.2%} |"
        )
        
    report_lines.extend([
        "",
        "## Performance by Code Length (NLOC)",
        "",
        "| NLOC Range | Total Samples | Vulnerable Samples | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    
    # Order buckets
    buckets_order = ["<10 lines", "10-30 lines", ">30 lines", "unknown"]
    for bucket in buckets_order:
        if bucket in nloc_perf:
            stats = nloc_perf[bucket]
            report_lines.append(
                f"| {bucket} | {stats['samples']:,} | {stats['vulnerable_samples']:,} | "
                f"{stats['precision']:.2%} | {stats['recall']:.2%} | {stats['f1']:.4f} |"
            )
            
    return "\n".join(report_lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/cvefixes_clean_pairs.parquet"),
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path("artifacts"),
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path("reports"),
    )
    args = parser.parse_args()
    
    # Load model artifacts
    model = joblib.load(args.artifacts_dir / "vulnerability_model.pkl")
    vectorizer = joblib.load(args.artifacts_dir / "tfidf_vectorizer.pkl")
    config = json.loads((args.artifacts_dir / "model_config.json").read_text(encoding="utf-8"))
    
    threshold = config["optimal_threshold"]
    model_name = config["model_name"]
    
    # Load dataset
    df = pd.read_parquet(args.input)
    test_df = df[df["split"] == "test"]
    
    # Evaluate
    metrics, eval_df = evaluate_split(test_df, vectorizer, model, threshold)
    cwe_perf = analyze_cwe_performance(eval_df)
    nloc_perf = analyze_nloc_performance(eval_df)
    
    # Write json output
    args.report_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "metrics": metrics,
        "cwe_performance": cwe_perf,
        "nloc_performance": nloc_perf,
    }
    (args.report_dir / "model_evaluation_metrics.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    
    # Generate markdown report
    md_report = generate_markdown_report(metrics, cwe_perf, nloc_perf, model_name, threshold)
    (args.report_dir / "model_evaluation_report.md").write_text(md_report, encoding="utf-8")
    
    print("Evaluation completed successfully.")
    print(f"Overall F1: {metrics['f1']:.4f}")
    print(f"Overall Recall: {metrics['recall']:.2%}")
    print(f"Overall Precision: {metrics['precision']:.2%}")


if __name__ == "__main__":
    main()
