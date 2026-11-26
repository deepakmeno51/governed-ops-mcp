"""Risk tiers and role permissions."""
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable


class Tier(IntEnum):
    READ = 1         # runs immediately
    LOW_WRITE = 2    # runs, always audited
    DESTRUCTIVE = 3  # blocked until a human approves


# Which tiers each role may invoke. For tier 3, "invoke" means "request approval".
ROLE_TIERS: dict[str, set[Tier]] = {
    "viewer": {Tier.READ},
    "operator": {Tier.READ, Tier.LOW_WRITE, Tier.DESTRUCTIVE},
}

# tool name -> tier, filled in by @governed_tool
REGISTRY: dict[str, Tier] = {}


def role_allows(role: str, tier: Tier) -> bool:
    return tier in ROLE_TIERS.get(role, set())


# tier-3 tool name -> function(args, approval_row, cursor) that performs the approved action
EXECUTORS: dict[str, Callable[..., Any]] = {}


@dataclass
class Prepared:
    """What a tier-3 tool shows the approver: normalized args (hashed), a summary, and a preview."""
    args: dict
    summary: str
    preview: dict
