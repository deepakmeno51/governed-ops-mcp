"""Risk tiers and role permissions."""
from enum import IntEnum


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
