import pytest

from governed import audit


def test_hash_is_deterministic_and_chained():
    p = {"a": 1, "b": [1, 2]}
    h1 = audit.compute_hash(audit.GENESIS, p)
    assert h1 == audit.compute_hash(audit.GENESIS, {"b": [1, 2], "a": 1})
    assert h1 != audit.compute_hash("1" * 64, p)


def test_jsonable_strips_nul_and_stringifies():
    out = audit.jsonable({"x": "a\x00b", "d": __import__("decimal").Decimal("1.5")})
    assert out == {"x": "ab", "d": "1.5"}


@pytest.mark.db
def test_chain_verifies_after_writes():
    for i in range(3):
        audit.write_event(actor="pytest", event_type="TEST", tool_name="t", risk_tier=1,
                          args={"i": i, "nested": {"z": [1, 2.5, None]}}, outcome="OK", output={"ok": True})
    assert audit.verify_chain()["ok"]


@pytest.mark.db
def test_concurrent_writers_do_not_fork_the_chain():
    from concurrent.futures import ThreadPoolExecutor

    def w(i):
        return audit.write_event(actor="pytest", event_type="CONCURRENT", args={"i": i}, outcome="OK")

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(w, range(40)))
    assert len(set(ids)) == 40
    assert audit.verify_chain()["ok"]
