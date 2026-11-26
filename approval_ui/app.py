"""Approval UI. A human inspects the exact request and approves or rejects it.
Runs as database role approval_decider: it can decide, but it cannot execute anything."""
import hashlib
import hmac
import os
import secrets
import uuid
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from governed import approvals, audit
from governed.config import get_settings
from governed.db import connect
from templates import render

settings = get_settings()
SECRET = (os.environ.get("UI_SECRET") or secrets.token_hex(32)).encode()

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
basic = HTTPBasic()

MESSAGES = {
    "approved": ("ok", "Approved. The agent can now execute it. It runs once."),
    "rejected": ("ok", "Rejected. The agent cannot execute this request."),
    "self_approval": ("err", "You cannot approve your own request."),
    "already_decided": ("err", "This request was already decided. Nothing changed."),
    "expired": ("err", "This request expired. Ask the agent to request again."),
    "hash_mismatch": ("err", "The request changed since you opened it. Reload and review again."),
    "not_found": ("err", "Request not found."),
    "bad_form": ("err", "Invalid form submission."),
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    resp.headers["X-Frame-Options"] = "DENY"          # blocks clickjacking of the Approve button
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def approver(creds: HTTPBasicCredentials = Depends(basic)) -> str:
    expected = settings.approvers.get(creds.username)
    ok = hmac.compare_digest((expected or "x").encode(), creds.password.encode()) and expected is not None
    if not ok:
        raise HTTPException(401, "Sign in with an approver account", headers={"WWW-Authenticate": 'Basic realm="approvals"'})
    return creds.username


def csrf_token(approval_id: str, who: str, args_hash: str) -> str:
    return hmac.new(SECRET, f"{approval_id}|{who}|{args_hash}".encode(), hashlib.sha256).hexdigest()


def _fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(who: str = Depends(approver)):
    approvals.expire_stale(role="approval_decider")
    with connect("approval_decider") as conn, conn.cursor() as cur:
        cur.execute("SELECT id, tool_name, status, requester, created_at, expires_at, preview FROM approvals "
                    "ORDER BY (status = 'PENDING') DESC, created_at DESC LIMIT 50")
        rows = [{**r, "created": _fmt(r["created_at"]), "expires": _fmt(r["expires_at"]),
                 "summary": (r["preview"] or {}).get("summary", r["tool_name"])} for r in cur.fetchall()]
    return render("index", who=who, rows=rows)


@app.get("/approvals/{approval_id}", response_class=HTMLResponse)
def detail(approval_id: str, msg: str = "", who: str = Depends(approver)):
    try:
        uid = uuid.UUID(approval_id)
    except ValueError:
        raise HTTPException(404)
    approvals.expire_stale(role="approval_decider")
    with connect("approval_decider") as conn, conn.cursor() as cur:
        cur.execute("SELECT *, extract(epoch FROM (expires_at - now()))::int AS secs_left FROM approvals WHERE id = %s", (uid,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(404)
    can_decide = row["status"] == "PENDING" and row["secs_left"] > 0 and row["requester"] != who
    kind_text = MESSAGES.get(msg)
    r = {**row, "created": _fmt(row["created_at"]), "expires": _fmt(row["expires_at"]),
         "decided": _fmt(row["decided_at"]), "summary": (row["preview"] or {}).get("summary", row["tool_name"]),
         "preview": row["preview"] or {}}
    return render("detail", who=who, r=r, can_decide=can_decide,
                  csrf=csrf_token(approval_id, who, row["args_hash"]),
                  message={"kind": kind_text[0], "text": kind_text[1]} if kind_text else None)


def do_decide(approval_id: str, who: str, decision: str, form_hash: str) -> str:
    with connect("approval_decider") as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM approvals WHERE id = %s", (uuid.UUID(approval_id),))
        row = cur.fetchone()
    if row is None:
        return "not_found"
    if row["requester"] == who:
        return "self_approval"
    if row["status"] == "EXPIRED":
        return "expired"
    if row["status"] != "PENDING":
        return "already_decided"
    if not hmac.compare_digest(form_hash, row["args_hash"]) or not approvals.hash_matches(row):
        return "hash_mismatch"

    new_status = "APPROVED" if decision == "approve" else "REJECTED"
    with connect("approval_decider") as conn, conn.cursor() as cur:
        # One atomic UPDATE. A second click, or a second approver, matches zero rows.
        cur.execute("UPDATE approvals SET status = %s, decided_by = %s, decided_at = now() "
                    "WHERE id = %s AND status = 'PENDING' AND expires_at > now() AND args_hash = %s AND requester <> %s "
                    "RETURNING id", (new_status, who, row["id"], row["args_hash"], who))
        won = cur.fetchone()
    if not won:
        return "expired" if _is_expired(approval_id) else "already_decided"
    try:
        audit.write_event(actor=who, event_type="APPROVAL_DECIDED", tool_name=row["tool_name"], approval_id=row["id"],
                          args={"args_hash": row["args_hash"], "decision": new_status}, outcome=new_status)
    except Exception:  # noqa: BLE001
        pass   # the decision itself is recorded on the approvals row (decided_by, decided_at)
    return "approved" if new_status == "APPROVED" else "rejected"


def _is_expired(approval_id: str) -> bool:
    with connect("approval_decider") as conn, conn.cursor() as cur:
        cur.execute("SELECT status, expires_at <= now() AS past FROM approvals WHERE id = %s", (uuid.UUID(approval_id),))
        r = cur.fetchone()
    return bool(r and (r["status"] == "EXPIRED" or r["past"]))


@app.post("/approvals/{approval_id}/decide")
def decide(approval_id: str, request: Request, decision: str = Form(...), args_hash: str = Form(...),
           csrf: str = Form(...), who: str = Depends(approver)):
    origin = request.headers.get("origin")
    if origin and urlparse(origin).netloc != request.headers.get("host"):
        raise HTTPException(403, "cross-origin request refused")
    try:
        uuid.UUID(approval_id)
    except ValueError:
        raise HTTPException(404)
    if decision not in ("approve", "reject") or not hmac.compare_digest(csrf, csrf_token(approval_id, who, args_hash)):
        return RedirectResponse(f"/approvals/{approval_id}?msg=bad_form", status_code=303)
    code = do_decide(approval_id, who, decision, args_hash)
    return RedirectResponse(f"/approvals/{approval_id}?msg={code}", status_code=303)
