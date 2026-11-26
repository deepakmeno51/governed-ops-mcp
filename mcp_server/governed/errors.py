"""Structured errors. The agent gets a code, a message, and a hint. Never a stack trace."""
import logging
import uuid

import httpx
import psycopg

log = logging.getLogger("governed.errors")


class ToolError(Exception):
    def __init__(self, code: str, message: str, hint: str = "", retryable: bool = False):
        super().__init__(message)
        self.code, self.message, self.hint, self.retryable = code, message, hint, retryable


def error_payload(code: str, message: str, hint: str = "", retryable: bool = False, **extra) -> dict:
    return {"ok": False, "error": {"code": code, "message": message, "hint": hint, "retryable": retryable, **extra}}


def from_exception(exc: Exception) -> dict:
    if isinstance(exc, ToolError):
        return error_payload(exc.code, exc.message, exc.hint, exc.retryable)
    if isinstance(exc, psycopg.errors.QueryCanceled):
        return error_payload("DB_TIMEOUT", "The query ran past its time limit.",
                             "Narrow the time range, add filters, or lower the limit.", True)
    if isinstance(exc, psycopg.errors.InsufficientPrivilege):
        return error_payload("DB_PERMISSION_DENIED", "The database role may not do this.",
                             "Use a different tool, or request approval for a write.")
    if isinstance(exc, psycopg.OperationalError):
        return error_payload("DB_UNAVAILABLE", "The database did not respond.",
                             "Retry in a few seconds. Writes were not applied.", True)
    if isinstance(exc, httpx.TimeoutException):
        return error_payload("DOWNSTREAM_TIMEOUT", "The service did not respond in time.",
                             "Retry once. If it repeats, treat the service as down.", True)
    if isinstance(exc, httpx.HTTPError):
        return error_payload("DOWNSTREAM_ERROR", "The service call failed.", "Retry once, then report the failure.", True)
    error_id = uuid.uuid4().hex[:12]
    log.exception("unhandled tool error error_id=%s", error_id)
    return error_payload("INTERNAL_ERROR", "Unexpected server error.",
                         "Report this error_id to an operator.", False, error_id=error_id)
