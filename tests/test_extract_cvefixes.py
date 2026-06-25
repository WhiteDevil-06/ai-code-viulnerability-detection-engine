import gzip
from pathlib import Path

from training.extract_cvefixes import as_temp_create, iter_sql_statements


def test_iter_sql_statements_handles_multiline_strings(tmp_path: Path) -> None:
    dump = tmp_path / "sample.sql.gz"
    content = """PRAGMA foreign_keys=OFF;
CREATE TABLE IF NOT EXISTS "sample" (
"id" TEXT,
"code" TEXT
);
INSERT INTO sample VALUES('1',replace('line one
line two',char(10)));
COMMIT;
"""
    with gzip.open(dump, "wt", encoding="utf-8") as stream:
        stream.write(content)

    statements = list(iter_sql_statements(dump))

    assert len(statements) == 2
    assert statements[0].startswith("CREATE TABLE")
    assert statements[1].startswith("INSERT INTO")
    assert "line two" in statements[1]


def test_as_temp_create_changes_only_table_kind() -> None:
    statement = 'CREATE TABLE IF NOT EXISTS "file_change" ("id" TEXT);'

    result = as_temp_create(statement)

    assert result.startswith("CREATE TEMP TABLE IF NOT EXISTS")
    assert '"file_change"' in result
