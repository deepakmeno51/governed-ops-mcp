"""All configuration comes from environment variables."""
import os
from dataclasses import dataclass, field
from functools import lru_cache


def _parse_tokens(raw: str) -> dict[str, tuple[str, str]]:
    """'token:actor:role,token2:actor2:role2' -> {token: (actor, role)}"""
    out: dict[str, tuple[str, str]] = {}
    for item in filter(None, (p.strip() for p in raw.split(","))):
        token, actor, role = item.split(":")
        out[token] = (actor, role)
    return out


def _parse_pairs(raw: str) -> dict[str, str]:
    """'name:secret,name2:secret2' -> {name: secret}"""
    out: dict[str, str] = {}
    for item in filter(None, (p.strip() for p in raw.split(","))):
        name, secret = item.split(":", 1)
        out[name] = secret
    return out


@dataclass(frozen=True)
class Settings:
    db_host: str = "postgres"
    db_port: int = 5432
    db_name: str = "ops"
    ro_password: str = ""
    rw_password: str = ""
    audit_password: str = ""
    executor_password: str = ""
    decider_password: str = ""
    approvers: dict = field(default_factory=dict)
    approval_ttl_minutes: float = 10.0
    max_mutation_rows: int = 1000
    mock_service_url: str = "http://mock-service:8000"
    api_tokens: dict = field(default_factory=dict)
    stdio_identity: str = ""
    transport: str = "streamable-http"
    host: str = "0.0.0.0"
    port: int = 8000
    row_cap: int = 200

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ
        return cls(
            db_host=e.get("DB_HOST", "postgres"),
            db_port=int(e.get("DB_PORT", "5432")),
            db_name=e.get("DB_NAME", "ops"),
            ro_password=e.get("AGENT_RO_PASSWORD", ""),
            rw_password=e.get("AGENT_RW_PASSWORD", ""),
            audit_password=e.get("AUDIT_WRITER_PASSWORD", ""),
            executor_password=e.get("OPS_EXECUTOR_PASSWORD", ""),
            decider_password=e.get("APPROVAL_DECIDER_PASSWORD", ""),
            approvers=_parse_pairs(e.get("APPROVERS", "")),
            approval_ttl_minutes=float(e.get("APPROVAL_TTL_MINUTES", "10")),
            max_mutation_rows=int(e.get("MAX_MUTATION_ROWS", "1000")),
            mock_service_url=e.get("MOCK_SERVICE_URL", "http://mock-service:8000"),
            api_tokens=_parse_tokens(e.get("MCP_API_TOKENS", "")),
            stdio_identity=e.get("MCP_STDIO_IDENTITY", ""),
            transport=e.get("MCP_TRANSPORT", "streamable-http"),
            host=e.get("MCP_HOST", "0.0.0.0"),
            port=int(e.get("MCP_PORT", "8000")),
            row_cap=int(e.get("ROW_CAP", "200")),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings.from_env()
