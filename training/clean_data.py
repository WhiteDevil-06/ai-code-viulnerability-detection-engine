"""Data cleaning, deduplication, conflict removal, pairing, and splitting."""

from __future__ import annotations

import argparse
import ast
import json
import random
import re
from pathlib import Path
import pandas as pd


def custom_dedent(code: str) -> str:
    """Dedent Python code using the first line's indentation level."""
    if not code:
        return code
    lines = code.splitlines()
    first_line = lines[0]
    
    # Calculate leading whitespace of the first line
    leading_whitespace = ""
    for char in first_line:
        if char in " \t":
            leading_whitespace += char
        else:
            break
            
    if not leading_whitespace:
        return code
        
    res = []
    for line in lines:
        if line.startswith(leading_whitespace):
            res.append(line[len(leading_whitespace):])
        else:
            # If a line has less indentation, strip leading spaces only if empty
            res.append(line.lstrip() if not line.strip() else line)
    return "\n".join(res)


def pre_clean_code(code: str) -> str:
    """Preprocess code: strip comments, docstrings, and normalize whitespace."""
    if not code:
        return ""
    # Remove comments
    code = re.sub(r"#.*", "", code)
    # Remove triple-quoted docstrings
    code = re.sub(r'"""[\s\S]*?"""', "", code)
    code = re.sub(r"'''[\s\S]*?'''", "", code)
    # Normalize whitespace: compress multiple spaces/newlines/tabs into a single space
    code = re.sub(r"\s+", " ", code).strip()
    return code


def clean_and_pair(df: pd.DataFrame, random_seed: int = 42) -> tuple[pd.DataFrame, dict]:
    """Clean the extracted dataset, match pairs, remove conflicts/duplicates, and split by repository."""
    # 1. Filter out non-Python files
    data = df.copy()
    data["extension"] = data["filename"].fillna("").map(lambda x: Path(x).suffix.lower())
    data = data[data["extension"] == ".py"].copy()

    # 2. Apply custom dedenting
    data["code"] = data["code"].fillna("").map(custom_dedent)
    
    # 3. Add normalized clean code for duplicate/conflict detection
    data["cleaned_code"] = data["code"].map(pre_clean_code)
    
    # 4. Remove exact duplicates (identical code AND label)
    before_len = len(data)
    data = data.drop_duplicates(subset=["cleaned_code", "label"], keep="first")
    exact_dups_removed = before_len - len(data)
    
    # 5. Remove conflicting labels (same code body with different labels)
    code_label_counts = data.groupby("cleaned_code")["label"].nunique()
    conflicting_code = code_label_counts[code_label_counts > 1].index
    data = data[~data["cleaned_code"].isin(conflicting_code)].copy()
    conflicts_removed = len(code_label_counts) - len(data.groupby("cleaned_code"))
    
    # 6. Set pair key
    data["pair_key"] = (
        data["file_change_id"].astype(str)
        + "::"
        + data["method_name"].fillna("").astype(str)
    )
    
    # 7. Identify paired groups (having exactly one label 0 and one label 1)
    pair_labels = data.groupby("pair_key")["label"].agg(set)
    valid_paired_keys = pair_labels[pair_labels == {0, 1}].index
    
    data = data[data["pair_key"].isin(valid_paired_keys)].copy()
    
    # 8. Group split by repository
    # Ensure every pair is in the same split, and repositories do not leak between splits.
    unique_repos = sorted(data["commit_repo_url"].dropna().unique())
    
    repo_counts = data.groupby("commit_repo_url").size().to_dict()
    
    rng = random.Random(random_seed)
    rng.shuffle(unique_repos)
    
    train_repos = set()
    val_repos = set()
    test_repos = set()
    
    total_samples = len(data)
    train_target = total_samples * 0.70
    val_target = total_samples * 0.15
    
    current_train = 0
    current_val = 0
    
    for repo in unique_repos:
        count = repo_counts[repo]
        if current_train < train_target:
            train_repos.add(repo)
            current_train += count
        elif current_val < val_target:
            val_repos.add(repo)
            current_val += count
        else:
            test_repos.add(repo)
            
    def get_split(repo_url):
        if repo_url in train_repos:
            return "train"
        elif repo_url in val_repos:
            return "val"
        else:
            return "test"
            
    data["split"] = data["commit_repo_url"].map(get_split)
    
    split_counts = data["split"].value_counts().to_dict()
    
    report = {
        "initial_rows": int(len(df)),
        "python_only_rows": int(len(df[df["filename"].fillna("").str.endswith(".py")])),
        "exact_duplicates_removed": int(exact_dups_removed),
        "conflicting_code_removed_rows": int(conflicts_removed),
        "cleaned_paired_rows": int(len(data)),
        "pairs_count": int(len(data) // 2),
        "train_rows": int(split_counts.get("train", 0)),
        "val_rows": int(split_counts.get("val", 0)),
        "test_rows": int(split_counts.get("test", 0)),
        "train_repos": int(len(train_repos)),
        "val_repos": int(len(val_repos)),
        "test_repos": int(len(test_repos)),
    }
    
    return data, report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/interim/cvefixes_python_methods.parquet"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/cvefixes_clean_pairs.parquet"),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("reports/cvefixes_cleaning_summary.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    df = pd.read_parquet(args.input)
    cleaned_df, report = clean_and_pair(df)
    
    args.output.parent.mkdir(parents=True, exist_ok=True)
    cleaned_df.to_parquet(args.output, index=False)
    
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    
    print("Data cleaning completed successfully.")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
