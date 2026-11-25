"""Load seed.sql once, only when the users table is empty."""
import os
from pathlib import Path

import psycopg

with psycopg.connect(
    host=os.environ.get("POSTGRES_HOST", "postgres"),
    port=os.environ.get("POSTGRES_PORT", "5432"),
    user=os.environ["POSTGRES_USER"],
    password=os.environ["POSTGRES_PASSWORD"],
    dbname=os.environ["POSTGRES_DB"],
    autocommit=True,
) as conn:
    if conn.execute("SELECT count(*) FROM users").fetchone()[0]:
        print("seed skipped: data already present")
    else:
        conn.execute(Path(__file__).with_name("seed.sql").read_text())
        print("seeded")
