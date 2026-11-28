"""@governed_tool: every tool call passes identity -> RBAC -> tier gate -> audit -> run -> redact -> audit.

Tier 1 and 2 run the function. Tier 3 tools with `prepare` never run directly: the decorator
validates the request, stores an approval for a human, and returns PENDING_APPROVAL.
The approved action runs later through execute_approved_action (self_gated=True).
"""
import concurrent.futures
import contextvars
import functools
import inspect
import json
import logging
import sys
import time
from typing import Any, Callable

import anyio.to_thread
from mcp.server.fastmcp import Context

from . import approvals, audit
from .config import get_settings
from .errors import ToolError, error_payload, from_exception
from .identity import AuthError, Identity, resolve_identity
from .policy import ATOMIC_EXECUTORS, EXECUTORS, REGISTRY, Prepared, Tier, role_allows
from .redaction import redact_obj, redact_text

CURRENT_IDENTITY: contextvars.ContextVar[Identity | None] = contextvars.ContextVar("current_identity", default=None)

_log = logging.getLogger("governed")
if not _log.handlers:
    _h = logging.StreamHandler(sys.stderr)  # stdout is reserved for the MCP stdio protocol
    _h.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_h)
    _log.setLevel(logging.INFO)
    _log.propagate = False   # the root logger has its own handler, so propagating printed every line twice

_SPECIAL_KWARGS = ("reasoning", "idempotency_key")

# Worker threads for tool bodies, so a hung call can be abandoned after its deadline.
# A Python thread cannot be killed: an abandoned body keeps running until its own limits end it
# (database statement_timeout, HTTP timeouts), so those limits stay in place underneath this one.
_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=32, thread_name_prefix="tool")


def run_with_deadline(fn: Callable, kwargs: dict, seconds: float | None, tier: Tier) -> Any:
    """Run fn(**kwargs) and give up waiting after `seconds`. seconds=None means no wall-clock limit."""
    if seconds is None:
        return fn(**kwargs)
    ctx = contextvars.copy_context()          # carries CURRENT_IDENTITY into the worker thread
    future = _POOL.submit(ctx.run, lambda: fn(**kwargs))
    try:
        return future.result(timeout=seconds)
    except concurrent.futures.TimeoutError:
        future.cancel()
        if tier == Tier.READ:
            raise ToolError("TOOL_TIMEOUT", f"The call took longer than {seconds:g}s and was abandoned.",
                            "Narrow the request (shorter time range, fewer rows) and retry.", True)
        raise ToolError("TOOL_TIMEOUT", f"The call took longer than {seconds:g}s and was abandoned.",
                        "The write may still have completed. Check the current state before trying again.", False)


def _is_db_unavailable(response: dict) -> bool:
    return response.get("error", {}).get("code") == "DB_UNAVAILABLE"


def jlog(event: str, **fields) -> None:
    _log.info(json.dumps({"event": event, **fields}, default=str))


def _summarize(output: Any, limit: int = 4000) -> Any:
    text = audit.canonical(output)
    if len(text) <= limit:
        return output
    return {"truncated": True, "bytes": len(text), "preview": text[:1500]}


AUDIT_TEXT_LIMIT = 8000


def _clip_text(obj: Any) -> Any:
    """Agent-supplied text can be any size. The audit log keeps the start of it and says how much was cut."""
    if isinstance(obj, str):
        if len(obj) > AUDIT_TEXT_LIMIT:
            return obj[:AUDIT_TEXT_LIMIT] + f"...[audit truncated {len(obj) - AUDIT_TEXT_LIMIT} more characters]"
        return obj
    if isinstance(obj, dict):
        return {k: _clip_text(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clip_text(v) for v in obj]
    return obj


def _audit(**kw) -> int | None:
    # The audit log is append-only and cannot be scrubbed later, so secrets are removed before the write.
    # Arguments and reasoning come from the agent and may contain pasted credentials.
    for field in ("args", "output"):
        if kw.get(field) is not None:
            kw[field] = redact_obj(_clip_text(kw[field]))
    if kw.get("agent_reasoning"):
        kw["agent_reasoning"] = redact_text(_clip_text(kw["agent_reasoning"]))
    try:
        return audit.write_event(**kw)
    except Exception:
        _log.exception("audit write failed")
        return None


def governed_tool(risk: Tier, name: str | None = None, *, prepare: Callable[..., Prepared] | None = None,
                  execute: Callable | None = None, self_gated: bool = False, atomic: bool = False):
    """atomic=True: the execute function's whole effect happens in the one database transaction that also
    marks the approval EXECUTED. Recovery can then say "not applied" for an execution that never finished."""
    def decorate(fn):
        tool_name = name or fn.__name__
        REGISTRY[tool_name] = risk
        if execute is not None:
            EXECUTORS[tool_name] = execute
        if atomic:
            ATOMIC_EXECUTORS.add(tool_name)

        def request_flow(ident: Identity, args: dict, reasoning: str | None, idem: str | None) -> dict:
            """Tier 3: validate, store an approval request, return PENDING_APPROVAL. Nothing is executed."""
            call_id = _audit(actor=ident.actor, event_type="TOOL_CALL", tool_name=tool_name, risk_tier=int(risk),
                             args=args, agent_reasoning=reasoning, outcome="STARTED")
            if call_id is None:
                return error_payload("AUDIT_UNAVAILABLE", "The audit log is unavailable, so no request was created.",
                                     "Retry in a few seconds.", True)
            try:
                prepared = run_with_deadline(prepare, args, get_settings().tool_timeout_seconds, Tier.READ)
                preview = redact_obj({**prepared.preview, "summary": prepared.summary, "agent_reasoning": reasoning})
                row, dedup = approvals.create_request(tool=tool_name, args=prepared.args, requester=ident.actor,
                                                      preview=preview, idempotency_key=idem)
            except Exception as exc:  # noqa: BLE001
                response = from_exception(exc)
                _audit(actor=ident.actor, event_type="TOOL_RESULT", tool_name=tool_name, risk_tier=int(risk),
                       args={"call_audit_id": call_id}, outcome="ERROR:" + response["error"]["code"], output=response)
                return response
            view = approvals.public_view(row)
            status = row["status"]
            next_step = {
                "PENDING": "A human must approve this in the approval UI. Then call execute_approved_action with the approval_id.",
                "APPROVED": "Already approved. Call execute_approved_action with the approval_id.",
            }.get(status, "Call get_approval_status for the current state.")
            result = {"status": "PENDING_APPROVAL" if status == "PENDING" else status,
                      "approval_id": view["approval_id"], "expires_at": view["expires_at"],
                      "args_hash": view["args_hash"], "summary": view["summary"],
                      "preview": {k: v for k, v in (row["preview"] or {}).items() if k != "agent_reasoning"},
                      "deduplicated": dedup, "next_step": next_step}
            done = _audit(actor=ident.actor, event_type="APPROVAL_REQUEST_REPEATED" if dedup else "APPROVAL_CREATED",
                          tool_name=tool_name, risk_tier=int(risk), approval_id=row["id"],
                          args={"call_audit_id": call_id, "args_hash": view["args_hash"], "args": view["args"]},
                          outcome=status, output={"summary": view["summary"], "expires_at": view["expires_at"]})
            response = {"ok": True, "result": result}
            if done is None:
                response["audit_warning"] = "request audit record could not be written"
            jlog("approval_requested", tool=tool_name, actor=ident.actor, approval_id=view["approval_id"], dedup=dedup)
            return response

        def pipeline(ctx, kwargs: dict) -> dict:
            started = time.monotonic()
            reasoning = kwargs.get("reasoning") or None
            idem = kwargs.get("idempotency_key") or None
            args = {k: v for k, v in kwargs.items() if k not in _SPECIAL_KWARGS}

            # 1. identity
            try:
                ident = resolve_identity(ctx)
            except AuthError as e:
                _audit(actor="anonymous", event_type="TOOL_DENIED", tool_name=tool_name, risk_tier=int(risk),
                       args=args, agent_reasoning=reasoning, outcome=f"AUTH: {e}")
                jlog("tool_denied", tool=tool_name, reason="auth")
                return error_payload("UNAUTHENTICATED", "Missing or invalid credentials.", "Send a valid bearer token.")

            # 2. role check
            if not role_allows(ident.role, risk):
                _audit(actor=ident.actor, event_type="TOOL_DENIED", tool_name=tool_name, risk_tier=int(risk),
                       args=args, agent_reasoning=reasoning, outcome=f"RBAC: role {ident.role} may not use tier {int(risk)}")
                jlog("tool_denied", tool=tool_name, actor=ident.actor, reason="rbac")
                return error_payload("PERMISSION_DENIED", f"Role '{ident.role}' may not call {tool_name}.",
                                     "Ask an operator to run this action.")

            # 3. tier 3
            if risk == Tier.DESTRUCTIVE and prepare is not None:
                return request_flow(ident, args, reasoning, idem)
            if risk == Tier.DESTRUCTIVE and not self_gated:   # fail closed
                _audit(actor=ident.actor, event_type="TOOL_DENIED", tool_name=tool_name, risk_tier=int(risk),
                       args=args, agent_reasoning=reasoning, outcome="APPROVAL_REQUIRED")
                return error_payload("APPROVAL_REQUIRED", f"{tool_name} needs human approval.", "Nothing was executed.")

            # 4. audit before acting. No audit record, no action.
            call_id = _audit(actor=ident.actor, event_type="TOOL_CALL", tool_name=tool_name, risk_tier=int(risk),
                             args=args, agent_reasoning=reasoning, outcome="STARTED")
            if call_id is None:
                return error_payload("AUDIT_UNAVAILABLE", "The audit log is unavailable, so the action was not run.",
                                     "Retry in a few seconds.", True)

            # 5. run. Tier 1 and 2 have a wall-clock deadline. Tier 3 execution does not: it is bounded by the
            #    database and HTTP timeouts underneath, because abandoning it midway would leave the outcome unknown.
            deadline = None if risk == Tier.DESTRUCTIVE else get_settings().tool_timeout_seconds
            attempts = 2 if risk == Tier.READ else 1     # a read is safe to repeat once if the database dropped us
            token = CURRENT_IDENTITY.set(ident)
            try:
                def run_and_redact(**kw):            # redaction is part of the work, so the deadline covers it
                    return redact_obj(fn(**kw))

                for attempt in range(1, attempts + 1):
                    try:
                        result = run_with_deadline(run_and_redact, kwargs, deadline, risk)
                        response = {"ok": True, "result": result}
                        outcome = "OK"
                    except Exception as exc:  # noqa: BLE001
                        response = from_exception(exc)
                        outcome = "ERROR:" + response["error"]["code"]
                    if attempt < attempts and _is_db_unavailable(response):
                        time.sleep(0.5)
                        continue
                    break
            finally:
                CURRENT_IDENTITY.reset(token)

            # 6. audit after acting
            ms = int((time.monotonic() - started) * 1000)
            done = _audit(actor=ident.actor, event_type="TOOL_RESULT", tool_name=tool_name, risk_tier=int(risk),
                          args={"call_audit_id": call_id, "duration_ms": ms, "attempts": attempt}, outcome=outcome,
                          output=_summarize(response))
            if done is None:
                response["audit_warning"] = "result audit record could not be written"
            jlog("tool_done", tool=tool_name, actor=ident.actor, outcome=outcome, ms=ms)
            return response

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            ctx = kwargs.pop("ctx", None)
            return await anyio.to_thread.run_sync(lambda: pipeline(ctx, kwargs))

        # Expose the tool's real signature plus ctx so FastMCP injects the request context.
        params = list(inspect.signature(fn).parameters.values())
        params.append(inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=Context))
        wrapper.__signature__ = inspect.Signature(params, return_annotation=dict[str, Any])
        wrapper.__annotations__ = {**fn.__annotations__, "ctx": Context, "return": dict[str, Any]}
        return wrapper

    return decorate
