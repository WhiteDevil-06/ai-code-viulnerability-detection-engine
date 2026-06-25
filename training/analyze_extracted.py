"""Analyze quality and leakage risks in the extracted CVEfixes methods."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

import pandas as pd


def is_parseable_python(code: str) -> bool:
    try:
        ast.parse(code)
    except (SyntaxError, TypeError, ValueError):
        return False
    return True


def split_multivalue(series: pd.Series) -> pd.Series:
    return series.dropna().str.split(",").explode().dropna()


def describe_numeric(series: pd.Series) -> dict:
    return {
        key: float(value)
        for key, value in series.describe(
            percentiles=[0.25, 0.5, 0.75, 0.95, 0.99]
        ).items()
    }


def analyze(dataframe: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    data = dataframe.copy()
    data["extension"] = (
        data["filename"]
        .fillna("")
        .map(lambda value: Path(value).suffix.lower() or "(none)")
    )
    data["code_length"] = data["code"].str.len()
    data["is_parseable_python"] = data["code"].map(is_parseable_python)
    data["is_test_path"] = (
        data["filename"].str.contains(r"(^|[/\\])tests?([/\\]|$)", case=False, regex=True)
        | data["filename"].str.contains(r"(^|[_\-.])test([_\-.]|$)", case=False, regex=True)
        | data["method_name"].str.startswith("test", na=False)
    )
    data["pair_key"] = (
        data["file_change_id"].astype(str)
        + "::"
        + data["method_name"].fillna("").astype(str)
    )

    pair_labels = data.groupby("pair_key")["label"].agg(set)
    paired_keys = pair_labels[pair_labels.map(lambda labels: labels == {0, 1})].index
    data["has_before_after_pair"] = data["pair_key"].isin(paired_keys)

    exact_code_labels = data.groupby("code")["label"].nunique()
    conflicting_code = exact_code_labels[exact_code_labels > 1].index

    cwe_counts = split_multivalue(data["cwe_ids"]).value_counts()
    repository_counts = data["commit_repo_url"].fillna("(missing)").value_counts()
    top_10_share = repository_counts.head(10).sum() / len(data)

    report = {
        "rows": int(len(data)),
        "py_extension_rows": int((data["extension"] == ".py").sum()),
        "non_py_extension_rows": int((data["extension"] != ".py").sum()),
        "label_counts": {
            str(key): int(value)
            for key, value in data["label"].value_counts().sort_index().items()
        },
        "parseable_python_rows": int(data["is_parseable_python"].sum()),
        "unparseable_python_rows": int((~data["is_parseable_python"]).sum()),
        "test_like_rows": int(data["is_test_path"].sum()),
        "paired_groups": int(len(paired_keys)),
        "rows_in_paired_groups": int(data["has_before_after_pair"].sum()),
        "unpaired_rows": int((~data["has_before_after_pair"]).sum()),
        "exact_duplicate_rows": int(data.duplicated(subset=["code", "label"]).sum()),
        "unique_code_bodies": int(data["code"].nunique()),
        "code_bodies_with_conflicting_labels": int(len(conflicting_code)),
        "rows_with_conflicting_code_labels": int(
            data["code"].isin(conflicting_code).sum()
        ),
        "missing_cve_rows": int(data["cve_ids"].isna().sum()),
        "missing_cwe_rows": int(data["cwe_ids"].isna().sum()),
        "unique_cves": int(split_multivalue(data["cve_ids"]).nunique()),
        "unique_cwes": int(split_multivalue(data["cwe_ids"]).nunique()),
        "unique_repositories": int(data["commit_repo_url"].nunique()),
        "top_10_repository_row_share": round(float(top_10_share), 4),
        "nloc": describe_numeric(data["nloc"]),
        "code_length": describe_numeric(data["code_length"]),
        "extensions": {
            str(key): int(value) for key, value in data["extension"].value_counts().items()
        },
        "top_repositories": {
            str(key): int(value) for key, value in repository_counts.head(20).items()
        },
        "top_cwes": {
            str(key): int(value) for key, value in cwe_counts.head(25).items()
        },
    }
    return data, report


def render_markdown(report: dict) -> str:
    label_counts = report["label_counts"]
    lines = [
        "# CVEfixes Python Extraction Quality Report",
        "",
        "## Dataset",
        "",
        f"- Rows: {report['rows']:,}",
        f"- `.py` rows: {report['py_extension_rows']:,}",
        f"- Vulnerable/before rows: {label_counts.get('1', 0):,}",
        f"- Fixed/after rows: {label_counts.get('0', 0):,}",
        f"- Repositories: {report['unique_repositories']:,}",
        f"- CVEs: {report['unique_cves']:,}",
        f"- CWEs: {report['unique_cwes']:,}",
        "",
        "## Quality Checks",
        "",
        f"- Parseable with current Python AST: {report['parseable_python_rows']:,}",
        f"- Unparseable methods: {report['unparseable_python_rows']:,}",
        f"- Test-like methods: {report['test_like_rows']:,}",
        f"- Exact duplicate rows: {report['exact_duplicate_rows']:,}",
        (
            "- Code bodies appearing with both labels: "
            f"{report['code_bodies_with_conflicting_labels']:,}"
        ),
        f"- Rows missing CWE metadata: {report['missing_cwe_rows']:,}",
        "",
        "## Pairing And Leakage",
        "",
        f"- Before/after method groups: {report['paired_groups']:,}",
        f"- Rows belonging to paired groups: {report['rows_in_paired_groups']:,}",
        f"- Unpaired rows: {report['unpaired_rows']:,}",
        (
            "- Share of rows from the top 10 repositories: "
            f"{report['top_10_repository_row_share']:.1%}"
        ),
        "",
        "Repository-grouped splitting and duplicate removal are required before training.",
        "",
        "## Top CWEs",
        "",
        "| CWE | Method rows |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {cwe} | {count:,} |" for cwe, count in report["top_cwes"].items()
    )
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/interim/cvefixes_python_methods.parquet"),
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("reports/cvefixes_data_quality.json"),
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("reports/cvefixes_data_quality.md"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataframe = pd.read_parquet(args.input)
    _, report = analyze(dataframe)

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    args.markdown_output.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
