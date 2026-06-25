import pandas as pd
from training.clean_data import custom_dedent, pre_clean_code, clean_and_pair


def test_custom_dedent_preserves_multiline_docstrings() -> None:
    code = """    def test_func():
        # indented comment
        x = \"\"\"
line in docstring
        \"\"\"
        return x
"""
    dedented = custom_dedent(code)
    expected_lines = [
        "def test_func():",
        "    # indented comment",
        "    x = \"\"\"",
        "line in docstring",
        "    \"\"\"",
        "    return x",
    ]
    assert dedented.splitlines() == expected_lines


def test_pre_clean_code_removes_comments_and_docstrings() -> None:
    code = """
    # a comment
    def foo():
        \"\"\"docstring\"\"\"
        x = 1  # inline comment
        '''another docstring'''
        return x
    """
    cleaned = pre_clean_code(code)
    # Check that comments and docstrings are gone and whitespace is normalized
    assert "comment" not in cleaned
    assert "docstring" not in cleaned
    assert cleaned == "def foo(): x = 1 return x"


def test_clean_and_pair_pipeline() -> None:
    df = pd.DataFrame(
        [
            # Paired group 1 (repo A) - Python - valid pair
            {
                "filename": "file1.py",
                "code": "    def foo():\n        return 1",
                "label": 1,
                "method_name": "foo",
                "file_change_id": "fc1",
                "commit_repo_url": "repo_a",
            },
            {
                "filename": "file1.py",
                "code": "    def foo():\n        return 2",
                "label": 0,
                "method_name": "foo",
                "file_change_id": "fc1",
                "commit_repo_url": "repo_a",
            },
            # Non-python extension - should be filtered
            {
                "filename": "file2.h",
                "code": "void bar();",
                "label": 1,
                "method_name": "bar",
                "file_change_id": "fc2",
                "commit_repo_url": "repo_a",
            },
            {
                "filename": "file2.h",
                "code": "void bar();",
                "label": 0,
                "method_name": "bar",
                "file_change_id": "fc2",
                "commit_repo_url": "repo_a",
            },
            # Conflicting label - same cleaned code body with different labels
            {
                "filename": "file3.py",
                "code": "def conflict(): pass",
                "label": 1,
                "method_name": "conflict",
                "file_change_id": "fc3",
                "commit_repo_url": "repo_b",
            },
            {
                "filename": "file4.py",
                "code": "def conflict(): pass",
                "label": 0,
                "method_name": "conflict",
                "file_change_id": "fc4",
                "commit_repo_url": "repo_b",
            },
            # Unpaired group (repo c) - missing label 0
            {
                "filename": "file5.py",
                "code": "def unpaired(): return 1",
                "label": 1,
                "method_name": "unpaired",
                "file_change_id": "fc5",
                "commit_repo_url": "repo_c",
            },
        ]
    )

    cleaned_df, report = clean_and_pair(df, random_seed=42)

    # Only paired group 1 should remain (2 rows total)
    assert len(cleaned_df) == 2
    assert set(cleaned_df["pair_key"]) == {"fc1::foo"}
    assert report["initial_rows"] == 7
    assert report["cleaned_paired_rows"] == 2
    assert report["pairs_count"] == 1
