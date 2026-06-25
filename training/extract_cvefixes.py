"""Extract a compact Python method dataset from a CVEfixes SQL dump."""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sqlite3
import time
from collections import Counter
from pathlib import Path
from typing import Iterator

import pandas as pd


INSERT_RE = re.compile(r"^INSERT INTO\s+[\"']?([^\"'\s]+)", re.IGNORECASE)
CREATE_RE = re.compile(
    r'^CREATE TABLE IF NOT EXISTS\s+["\']?([^"\'\s(]+)', re.IGNORECASE
)

PERMANENT_SOURCE_TABLES = {"fixes", "cwe", "cwe_classification"}
TRANSIENT_SOURCE_TABLES = {
    "commits",
    "cve",
    "file_change",
    "method_change",
    "repository",
}
RELEVANT_TABLES = PERMANENT_SOURCE_TABLES | TRANSIENT_SOURCE_TABLES


def iter_sql_statements(dump_path: Path) -> Iterator[str]:
    """Yield complete SQL statements without decompressing the dump to disk."""
    buffer: list[str] = []

    with gzip.open(dump_path, "rt", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if not buffer:
                stripped = line.lstrip()
                if not (
                    stripped.startswith("CREATE TABLE")
                    or stripped.startswith("INSERT INTO")
                ):
                    continue

            buffer.append(line)
            if line.rstrip().endswith(";"):
                statement = "".join(buffer)
                if sqlite3.complete_statement(statement):
                    yield statement
                    buffer.clear()

    if buffer:
        raise ValueError("The SQL dump ended with an incomplete statement.")


def as_temp_create(statement: str) -> str:
    return re.sub(
        r"^CREATE TABLE IF NOT EXISTS",
        "CREATE TEMP TABLE IF NOT EXISTS",
        statement,
        count=1,
        flags=re.IGNORECASE,
    )


def create_output_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS cve_meta (
            cve_id TEXT PRIMARY KEY,
            published_date TEXT,
            last_modified_date TEXT,
            description TEXT,
            severity REAL,
            cvss2_base_score REAL,
            cvss3_base_score REAL,
            cvss3_base_severity TEXT,
            exploitability_score REAL,
            impact_score REAL
        );

        CREATE TABLE IF NOT EXISTS commit_meta (
            hash TEXT PRIMARY KEY,
            repo_url TEXT,
            author_date TEXT,
            committer_date TEXT,
            msg TEXT,
            merge INTEGER,
            num_lines_added INTEGER,
            num_lines_deleted INTEGER
        );

        CREATE TABLE IF NOT EXISTS repository_meta (
            repo_url TEXT PRIMARY KEY,
            repo_name TEXT,
            description TEXT,
            date_created TEXT,
            date_last_push TEXT,
            homepage TEXT,
            repo_language TEXT,
            owner TEXT,
            forks_count INTEGER,
            stars_count INTEGER
        );

        CREATE TABLE IF NOT EXISTS python_file (
            file_change_id TEXT PRIMARY KEY,
            hash TEXT,
            filename TEXT,
            old_path TEXT,
            new_path TEXT,
            change_type TEXT,
            nloc REAL,
            complexity REAL,
            token_count REAL,
            programming_language TEXT,
            num_lines_added INTEGER,
            num_lines_deleted INTEGER
        );

        CREATE TABLE IF NOT EXISTS python_method (
            method_change_id TEXT PRIMARY KEY,
            file_change_id TEXT,
            name TEXT,
            signature TEXT,
            parameters TEXT,
            start_line INTEGER,
            end_line INTEGER,
            code TEXT,
            nloc REAL,
            complexity REAL,
            token_count REAL,
            top_nesting_level REAL,
            before_change TEXT
        );
        """
    )


def copy_current_row(
    connection: sqlite3.Connection,
    source_table: str,
    destination_table: str,
    columns: tuple[str, ...],
) -> None:
    column_list = ", ".join(f'"{column}"' for column in columns)
    placeholders = ", ".join("?" for _ in columns)
    row = connection.execute(
        f'SELECT {column_list} FROM "{source_table}" LIMIT 1'
    ).fetchone()
    if row is not None:
        connection.execute(
            f'INSERT OR REPLACE INTO "{destination_table}" '
            f"({column_list}) VALUES ({placeholders})",
            row,
        )


def process_transient_insert(
    connection: sqlite3.Connection,
    table: str,
    statement: str,
) -> bool:
    connection.execute(statement)
    kept = False

    if table == "file_change":
        row = connection.execute(
            """
            SELECT file_change_id, hash, filename, old_path, new_path,
                   change_type, nloc, complexity, token_count,
                   programming_language, num_lines_added, num_lines_deleted
            FROM file_change
            LIMIT 1
            """
        ).fetchone()
        if row is not None and row[9] == "Python":
            connection.execute(
                """
                INSERT OR REPLACE INTO python_file VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            kept = True

    elif table == "method_change":
        row = connection.execute(
            """
            SELECT method_change_id, file_change_id, name, signature,
                   parameters, start_line, end_line, code, nloc, complexity,
                   token_count, top_nesting_level, before_change
            FROM method_change
            LIMIT 1
            """
        ).fetchone()
        if row is not None:
            is_python = connection.execute(
                "SELECT 1 FROM python_file WHERE file_change_id = ?",
                (row[1],),
            ).fetchone()
            if is_python:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO python_method VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    row,
                )
                kept = True

    elif table == "cve":
        copy_current_row(
            connection,
            "cve",
            "cve_meta",
            (
                "cve_id",
                "published_date",
                "last_modified_date",
                "description",
                "severity",
                "cvss2_base_score",
                "cvss3_base_score",
                "cvss3_base_severity",
                "exploitability_score",
                "impact_score",
            ),
        )

    elif table == "commits":
        copy_current_row(
            connection,
            "commits",
            "commit_meta",
            (
                "hash",
                "repo_url",
                "author_date",
                "committer_date",
                "msg",
                "merge",
                "num_lines_added",
                "num_lines_deleted",
            ),
        )

    elif table == "repository":
        copy_current_row(
            connection,
            "repository",
            "repository_meta",
            (
                "repo_url",
                "repo_name",
                "description",
                "date_created",
                "date_last_push",
                "homepage",
                "repo_language",
                "owner",
                "forks_count",
                "stars_count",
            ),
        )

    connection.execute(f'DELETE FROM "{table}"')
    return kept


def build_flat_dataset(connection: sqlite3.Connection) -> pd.DataFrame:
    query = """
        SELECT
            m.method_change_id AS sample_id,
            m.file_change_id,
            f.hash AS commit_hash,
            f.filename,
            f.old_path,
            f.new_path,
            f.change_type,
            m.name AS method_name,
            m.signature,
            m.parameters,
            m.start_line,
            m.end_line,
            m.code,
            m.nloc,
            m.complexity,
            m.token_count,
            m.top_nesting_level,
            CASE
                WHEN lower(CAST(m.before_change AS TEXT)) IN ('true', '1')
                THEN 1 ELSE 0
            END AS label,
            m.before_change,
            cm.author_date,
            cm.committer_date,
            cm.msg AS commit_message,
            cm.repo_url AS commit_repo_url,
            GROUP_CONCAT(DISTINCT fx.repo_url) AS fix_repo_urls,
            GROUP_CONCAT(DISTINCT fx.cve_id) AS cve_ids,
            GROUP_CONCAT(DISTINCT cc.cwe_id) AS cwe_ids
        FROM python_method AS m
        JOIN python_file AS f
          ON f.file_change_id = m.file_change_id
        LEFT JOIN commit_meta AS cm
          ON cm.hash = f.hash
        LEFT JOIN fixes AS fx
          ON fx.hash = f.hash
        LEFT JOIN cwe_classification AS cc
          ON cc.cve_id = fx.cve_id
        GROUP BY m.method_change_id
        ORDER BY m.method_change_id
    """
    return pd.read_sql_query(query, connection)


def summarize_dataset(dataframe: pd.DataFrame, counters: Counter) -> dict:
    extensions = (
        dataframe["filename"]
        .fillna("")
        .map(lambda value: Path(value).suffix.lower() or "(none)")
        .value_counts()
        .to_dict()
    )
    repositories = (
        dataframe["commit_repo_url"].fillna("(missing)").value_counts().head(20).to_dict()
    )

    return {
        "source_statement_counts": dict(sorted(counters.items())),
        "rows": int(len(dataframe)),
        "label_counts": {
            str(key): int(value)
            for key, value in dataframe["label"].value_counts().sort_index().items()
        },
        "unique_commits": int(dataframe["commit_hash"].nunique()),
        "unique_repositories": int(dataframe["commit_repo_url"].nunique()),
        "unique_cves": int(
            dataframe["cve_ids"].dropna().str.split(",").explode().nunique()
        ),
        "unique_cwes": int(
            dataframe["cwe_ids"].dropna().str.split(",").explode().nunique()
        ),
        "missing_code": int(dataframe["code"].isna().sum()),
        "duplicate_code_rows": int(dataframe.duplicated(subset=["code", "label"]).sum()),
        "method_nloc": dataframe["nloc"].describe().to_dict(),
        "file_extensions": extensions,
        "top_repositories": repositories,
    }


def extract_dataset(
    dump_path: Path,
    database_path: Path,
    parquet_path: Path,
    summary_path: Path,
    progress_every: int = 10_000,
) -> dict:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    parquet_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    if database_path.exists():
        database_path.unlink()

    counters: Counter = Counter()
    started = time.monotonic()

    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA temp_store = MEMORY")
        create_output_schema(connection)

        for index, statement in enumerate(iter_sql_statements(dump_path), start=1):
            create_match = CREATE_RE.match(statement)
            if create_match:
                table = create_match.group(1)
                if table in PERMANENT_SOURCE_TABLES:
                    connection.execute(statement)
                elif table in TRANSIENT_SOURCE_TABLES:
                    connection.execute(as_temp_create(statement))
                continue

            insert_match = INSERT_RE.match(statement)
            if not insert_match:
                continue

            table = insert_match.group(1)
            if table not in RELEVANT_TABLES:
                continue

            counters[f"{table}_seen"] += 1
            if table in PERMANENT_SOURCE_TABLES:
                connection.execute(statement)
            else:
                kept = process_transient_insert(connection, table, statement)
                if kept:
                    counters[f"{table}_kept"] += 1

            if index % progress_every == 0:
                connection.commit()
                elapsed = time.monotonic() - started
                print(
                    f"Processed {index:,} relevant statements in "
                    f"{elapsed / 60:.1f} minutes"
                )

        connection.commit()
        dataframe = build_flat_dataset(connection)

    dataframe.to_parquet(parquet_path, index=False)
    summary = summarize_dataset(dataframe, counters)
    summary["elapsed_seconds"] = round(time.monotonic() - started, 2)
    summary["database_path"] = str(database_path)
    summary["parquet_path"] = str(parquet_path)

    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dump",
        type=Path,
        default=Path(
            "CVEfixes_v1.0.7/CVEfixes_v1.0.7/Data/CVEfixes_v1.0.7.sql.gz"
        ),
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("data/interim/cvefixes_python.sqlite"),
    )
    parser.add_argument(
        "--parquet",
        type=Path,
        default=Path("data/interim/cvefixes_python_methods.parquet"),
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("reports/cvefixes_extraction_summary.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = extract_dataset(
        dump_path=args.dump,
        database_path=args.database,
        parquet_path=args.parquet,
        summary_path=args.summary,
    )
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
