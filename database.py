import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "edr_assistant.db"
LEGACY_CORRECTIONS = Path(__file__).parent / "corrections_memory.json"
LEGACY_AUDIT = Path(__file__).parent / "audit_log.json"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS corrections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                gap_description TEXT NOT NULL,
                original_yaml TEXT NOT NULL,
                corrected_yaml TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                embedding TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_corrections_technique
                ON corrections (technique_id, timestamp DESC);

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                technique_id TEXT,
                rule_title TEXT,
                file_path TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_events (timestamp DESC);
            """
        )
        conn.commit()
    migrate_legacy_json()


def migrate_legacy_json() -> None:
    """One-time import from old JSON files, if they exist."""
    with _connect() as conn:
        if LEGACY_CORRECTIONS.exists():
            existing = conn.execute("SELECT COUNT(*) FROM corrections").fetchone()[0]
            if existing == 0:
                for entry in json.loads(LEGACY_CORRECTIONS.read_text()):
                    technique_id = entry["gap_description"].split(" - ", 1)[0].strip()
                    embedding = entry.get("embedding")
                    conn.execute(
                        """
                        INSERT INTO corrections
                            (timestamp, technique_id, gap_description,
                             original_yaml, corrected_yaml, note, embedding)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            entry["timestamp"],
                            technique_id,
                            entry["gap_description"],
                            entry["original_yaml"],
                            entry["corrected_yaml"],
                            entry.get("note") or "",
                            json.dumps(embedding) if embedding else None,
                        ),
                    )

        if LEGACY_AUDIT.exists():
            existing = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            if existing == 0:
                for entry in json.loads(LEGACY_AUDIT.read_text()):
                    conn.execute(
                        """
                        INSERT INTO audit_events
                            (timestamp, action, technique_id, rule_title, file_path)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            entry["timestamp"],
                            entry["action"],
                            entry.get("technique_id"),
                            entry.get("rule_title"),
                            entry.get("file"),
                        ),
                    )
        conn.commit()


def insert_correction(
    *,
    technique_id: str,
    gap_description: str,
    original_yaml: str,
    corrected_yaml: str,
    note: str,
    embedding: list[float] | None,
) -> int:
    init_db()
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO corrections
                (timestamp, technique_id, gap_description,
                 original_yaml, corrected_yaml, note, embedding)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                technique_id,
                gap_description,
                original_yaml,
                corrected_yaml,
                note,
                json.dumps(embedding) if embedding else None,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def fetch_all_corrections() -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, technique_id, gap_description,
                   original_yaml, corrected_yaml, note, embedding
            FROM corrections
            ORDER BY timestamp DESC
            """
        ).fetchall()
    return [_row_to_correction(row) for row in rows]


def fetch_corrections_for_technique(technique_id: str) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, technique_id, gap_description,
                   original_yaml, corrected_yaml, note, embedding
            FROM corrections
            WHERE technique_id = ?
            ORDER BY timestamp DESC
            """,
            (technique_id,),
        ).fetchall()
    return [_row_to_correction(row) for row in rows]


def fetch_corrections_with_embeddings() -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, technique_id, gap_description,
                   original_yaml, corrected_yaml, note, embedding
            FROM corrections
            WHERE embedding IS NOT NULL
            ORDER BY timestamp DESC
            """
        ).fetchall()
    return [_row_to_correction(row) for row in rows]


def _row_to_correction(row: sqlite3.Row) -> dict:
    entry = {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "technique_id": row["technique_id"],
        "gap_description": row["gap_description"],
        "original_yaml": row["original_yaml"],
        "corrected_yaml": row["corrected_yaml"],
        "note": row["note"],
    }
    if row["embedding"]:
        entry["embedding"] = json.loads(row["embedding"])
    return entry


def log_audit_event(
    *,
    action: str,
    technique_id: str | None = None,
    rule_title: str | None = None,
    file_path: str | None = None,
) -> None:
    init_db()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_events
                (timestamp, action, technique_id, rule_title, file_path)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                action,
                technique_id,
                rule_title,
                file_path,
            ),
        )
        conn.commit()


def all_audit_events() -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT timestamp, action, technique_id, rule_title, file_path
            FROM audit_events
            ORDER BY timestamp DESC
            """
        ).fetchall()
    return [
        {
            "timestamp": row["timestamp"],
            "action": row["action"],
            "technique_id": row["technique_id"],
            "rule_title": row["rule_title"],
            "file": row["file_path"],
        }
        for row in rows
    ]
