import sqlite3
from pathlib import Path


def initialize(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS processed_events (event_id TEXT PRIMARY KEY, discovered TEXT NOT NULL)"
        )


def is_processed(path: Path, event_id: str) -> bool:
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT 1 FROM processed_events WHERE event_id = ?", (event_id,)
        ).fetchone() is not None


def mark_processed(path: Path, event_id: str, discovered: str) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO processed_events(event_id, discovered) VALUES (?, ?)",
            (event_id, discovered),
        )
