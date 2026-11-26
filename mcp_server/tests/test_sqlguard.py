import pytest

from governed.errors import ToolError
from governed.sqlguard import validate_select

OK = [
    "SELECT * FROM v_orders",
    "SELECT status, count(*) FROM v_orders GROUP BY status ORDER BY 2 DESC",
    "SELECT * FROM v_app_logs WHERE message LIKE '%timeout%' LIMIT 10",
    "WITH e AS (SELECT * FROM v_app_logs WHERE level='ERROR') SELECT service, count(*) FROM e GROUP BY service",
    "SELECT o.id FROM v_orders o JOIN v_users u ON u.id = o.user_id",
    "SELECT * FROM v_orders; -- trailing comment",
    "SELECT date_trunc('hour', ts) AS h, count(*) FROM v_app_logs GROUP BY 1",
]
BAD = [
    "DROP TABLE orders",
    "SELECT 1; DROP TABLE orders",
    "DELETE FROM orders",
    "UPDATE orders SET status='failed'",
    "INSERT INTO orders DEFAULT VALUES",
    "SELECT * INTO x FROM v_orders",
    "SELECT * FROM v_orders FOR UPDATE",
    "WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d",
    "SELECT * FROM users",
    "SELECT * FROM orders",
    "SELECT * FROM pg_catalog.pg_user",
    "SELECT * FROM public.v_orders",
    "SELECT pg_sleep(10)",
    "SELECT set_config('default_transaction_read_only','off',false)",
    "SELECT lo_import('/etc/passwd')",
    "SELECT * FROM generate_series(1,10)",
    "SET default_transaction_read_only = off",
    "COPY orders TO '/tmp/x'",
    "EXPLAIN ANALYZE DELETE FROM orders",
    "",
    "SELECT " + "1," * 3000 + "1",
]


@pytest.mark.parametrize("sql", OK)
def test_allows_safe_selects(sql):
    assert validate_select(sql).upper().startswith(("SELECT", "WITH"))


@pytest.mark.parametrize("sql", BAD)
def test_rejects_unsafe_sql(sql):
    with pytest.raises(ToolError) as e:
        validate_select(sql)
    assert e.value.code == "SQL_REJECTED"


def test_comments_are_not_executed():
    out = validate_select("SELECT 1 /* ; DROP TABLE orders */ FROM v_orders")
    assert "DROP" not in out.upper()
