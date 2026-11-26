"""Who is calling? HTTP: bearer token -> (actor, role). stdio: fixed identity from the environment."""
import hmac
from dataclasses import dataclass

from .config import get_settings


@dataclass(frozen=True)
class Identity:
    actor: str
    role: str


class AuthError(Exception):
    pass


def _request_of(ctx):
    try:
        return ctx.request_context.request
    except Exception:
        return None


def resolve_identity(ctx) -> Identity:
    s = get_settings()
    request = _request_of(ctx)
    if request is not None:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthError("missing bearer token")
        match = None
        for known, (actor, role) in s.api_tokens.items():
            if hmac.compare_digest(known.encode(), token.encode()):
                match = Identity(actor, role)
        if match is None:
            raise AuthError("invalid token")
        return match
    if s.stdio_identity:
        actor, _, role = s.stdio_identity.partition(":")
        return Identity(actor, role)
    raise AuthError("no identity available")
