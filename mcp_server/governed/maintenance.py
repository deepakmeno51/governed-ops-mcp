"""Background maintenance: expire stale approvals and close executions that never finished.

Both actions are also done lazily when someone looks at an approval. This job makes them happen on time
even when nobody is looking, so an expired approval is marked EXPIRED in the table and the audit log
and an abandoned execution does not stay EXECUTING forever."""
import logging
import threading
from datetime import datetime, timezone

from . import approvals
from .config import get_settings

_log = logging.getLogger("governed.maintenance")
STATE = {"last_run": None, "last_error": None, "runs": 0}


def run_once() -> dict:
    """One pass. Returns what it changed. Never raises: a failing pass is recorded and the next one retries."""
    try:
        expired = approvals.expire_stale()
        abandoned = approvals.recover_stuck_executions()
        STATE.update(last_run=datetime.now(timezone.utc).isoformat(timespec="seconds"), last_error=None)
        STATE["runs"] += 1
        if expired or abandoned:
            _log.info("maintenance expired=%s abandoned=%s", expired, abandoned)
        return {"expired": expired, "abandoned": abandoned}
    except Exception as exc:  # noqa: BLE001
        STATE["last_error"] = type(exc).__name__
        _log.warning("maintenance pass failed: %s", type(exc).__name__)
        return {"error": type(exc).__name__}


def start_background() -> threading.Event:
    """Start the job in a daemon thread. Set the returned event to stop it."""
    stop = threading.Event()
    interval = get_settings().maintenance_interval_seconds

    def loop():
        run_once()
        while not stop.wait(interval):
            run_once()

    threading.Thread(target=loop, name="maintenance", daemon=True).start()
    return stop
