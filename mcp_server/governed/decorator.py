"""@governed_tool: every tool call passes identity -> RBAC -> tier gate -> audit -> run -> redact -> audit."""
import contextvars
import functools
import inspect
import json
import logging
import sys
import time
from typing import Any

import anyio.to_thread
from mcp.server.fastmcp import Context

from . import audit
from .errors import error_payload, from_exception
from .identity import AuthError, Identity, resolve_identity
from .policy import REGISTRY, Tier, role_allows
from .redaction import redact_obj

CURRENT_IDENTITY: contextvars.ContextVar[Identity | None] = contextvars.ContextVar("current_identity", default=None)

_log = logging.getLogger("governed")
if not _log.handlers:
    _h = logging.StreamHandler(sys.stderr)  # stdout is reserved for the MCP stdio protocol
    _h.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_h)
    _log.setLevel(logging.INFO)


def jlog(event: str, **fields) -> None:
    _log.info(json.dumps({"event": event, **fields}, default=str))


def _summarize(output: Any, limit: int = 4000) -> Any:
    text = audit.canonical(output)
    if len(text) <= limit:
        return output
    return {"truncated": True, "bytes": len(text), "preview": text[:1500]}


def _audit(**kw) -> int | None:
    try:
        return audit.write_event(**kw)
    except Exception:
        _log.exception("audit write failed")
        return None


def governed_tool(risk: Tier, name: str | None = None):
    def decorate(fn):
        tool_name = name or fn.__name__
        REGISTRY[tool_name] = risk

        def pipeline(ctx, kwargs: dict) -> dict:
            started = time.monotonic()
            reasoning = kwargs.get("reasoning") or None
            args = {k: v for k, v in kwargs.items() if k != "reasoning"}

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

            # 3. tier 3 fails closed until the approval flow exists
            if risk == Tier.DESTRUCTIVE:
                _audit(actor=ident.actor, event_type="TOOL_DENIED", tool_name=tool_name, risk_tier=int(risk),
                       args=args, agent_reasoning=reasoning, outcome="APPROVAL_REQUIRED")
                return error_payload("APPROVAL_REQUIRED", f"{tool_name} needs human approval.",
                                     "The approval flow is not enabled yet. Nothing was executed.")

            # 4. audit before acting. No audit record, no action.
            call_id = _audit(actor=ident.actor, event_type="TOOL_CALL", tool_name=tool_name, risk_tier=int(risk),
                             args=args, agent_reasoning=reasoning, outcome="STARTED")
            if call_id is None:
                return error_payload("AUDIT_UNAVAILABLE", "The audit log is unavailable, so the action was not run.",
                                     "Retry in a few seconds.", True)

            # 5. run
            token = CURRENT_IDENTITY.set(ident)
            try:
                result = fn(**kwargs)
                response = {"ok": True, "result": redact_obj(result)}
                outcome = "OK"
            except Exception as exc:  # noqa: BLE001
                response = from_exception(exc)
                outcome = "ERROR:" + response["error"]["code"]
            finally:
                CURRENT_IDENTITY.reset(token)

            # 6. audit after acting
            ms = int((time.monotonic() - started) * 1000)
            done = _audit(actor=ident.actor, event_type="TOOL_RESULT", tool_name=tool_name, risk_tier=int(risk),
                          args={"call_audit_id": call_id, "duration_ms": ms}, outcome=outcome,
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
