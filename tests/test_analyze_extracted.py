import pandas as pd

from training.analyze_extracted import analyze


def test_analyze_detects_pairs_and_conflicting_labels() -> None:
    dataframe = pd.DataFrame(
        [
            {
                "filename": "src/example.py",
                "code": "def f():\n    return 1\n",
                "label": 1,
                "method_name": "f",
                "file_change_id": "file-1",
                "cve_ids": "CVE-1",
                "cwe_ids": "CWE-79",
                "commit_repo_url": "https://example.test/repo",
                "nloc": 2,
            },
            {
                "filename": "src/example.py",
                "code": "def f():\n    return 1\n",
                "label": 0,
                "method_name": "f",
                "file_change_id": "file-1",
                "cve_ids": "CVE-1",
                "cwe_ids": "CWE-79",
                "commit_repo_url": "https://example.test/repo",
                "nloc": 2,
            },
        ]
    )

    _, report = analyze(dataframe)

    assert report["paired_groups"] == 1
    assert report["rows_in_paired_groups"] == 2
    assert report["code_bodies_with_conflicting_labels"] == 1
