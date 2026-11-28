"""Test setup.

Database tests change data and write audit rows, so they must never run against the real database.
They run only when GOVERNED_TEST_DB=1 and DB_NAME ends in _test, which the `tests` service in
docker-compose.yml sets up against its own throwaway Postgres. Anywhere else they are skipped.

    docker compose --profile test run --rm tests
"""
import os

import psycopg
import pytest

from governed.db import ROLES, connect


def pytest_configure(config):
    config.addinivalue_line("markers", "db: needs the isolated test database (run via the compose test profile)")


def _test_mode() -> bool:
    return os.environ.get("GOVERNED_TEST_DB") == "1"


def pytest_collection_modifyitems(config, items):
    if _test_mode():
        if not os.environ.get("DB_NAME", "").endswith("_test"):
            raise pytest.UsageError("GOVERNED_TEST_DB=1 but DB_NAME does not end in _test. Refusing to run against it.")
        return
    skip = pytest.mark.skip(reason="database test: run it with  docker compose --profile test run --rm tests")
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session", autouse=True)
def _require_test_database():
    """In test mode every role and the admin login must work, so nothing is silently skipped."""
    if not _test_mode():
        return
    for role in ROLES:
        try:
            connect(role).close()
        except Exception as exc:  # noqa: BLE001
            pytest.exit(f"test database: cannot connect as {role}: {type(exc).__name__}", returncode=3)
    try:
        admin_connection().close()
    except Exception as exc:  # noqa: BLE001
        pytest.exit(f"test database: cannot connect as the admin user: {type(exc).__name__}", returncode=3)


def admin_connection() -> psycopg.Connection:
    """The database owner. Used only to simulate tampering that no application role could do."""
    return psycopg.connect(host=os.environ.get("DB_HOST", "postgres"), port=os.environ.get("DB_PORT", "5432"),
                           dbname=os.environ.get("DB_NAME", "ops"), user=os.environ["POSTGRES_USER"],
                           password=os.environ["POSTGRES_PASSWORD"], autocommit=True)


@pytest.fixture
def admin():
    with admin_connection() as conn:
        yield conn
