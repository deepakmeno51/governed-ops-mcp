"""SELECT-only guard for run_readonly_sql.

We parse the SQL, reject anything that is not a plain read of the allowed views,
then execute the SQL we regenerated from the parse tree, not the user's raw string.
That removes parser differentials (comments, odd whitespace, stacked statements).
The database is the next layer: agent_ro only has SELECT on the redacted views.
"""
import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from .errors import ToolError

ALLOWED_RELATIONS = {"v_users", "v_orders", "v_app_logs", "v_tickets", "v_ticket_comments"}

# Functions sqlglot does not model itself are treated as unknown and rejected, unless listed here.
ALLOWED_UNKNOWN_FUNCS = {"now", "date_part", "age", "string_agg", "array_agg", "bool_and", "bool_or", "split_part"}

MAX_SQL_CHARS = 4000

_FORBIDDEN_NAMES = (
    "Insert", "Update", "Delete", "Merge", "Create", "Drop", "Alter", "AlterTable", "Command",
    "Into", "Lock", "Set", "Copy", "TruncateTable", "Grant", "Revoke", "Use", "Commit", "Rollback",
    "Transaction", "Pragma", "Analyze", "Describe", "Show", "Kill", "Execute", "Call", "Declare",
)
FORBIDDEN_NODES = tuple(getattr(exp, n) for n in _FORBIDDEN_NAMES if hasattr(exp, n))


def _reject(reason: str) -> ToolError:
    return ToolError(
        "SQL_REJECTED", reason,
        "Only a single SELECT over v_users, v_orders, v_app_logs, v_tickets, v_ticket_comments is allowed.",
    )


def validate_select(sql: str) -> str:
    """Return safe SQL to execute, or raise ToolError."""
    if not sql or not sql.strip():
        raise _reject("empty query")
    if len(sql) > MAX_SQL_CHARS:
        raise _reject(f"query longer than {MAX_SQL_CHARS} characters")
    try:
        parsed = sqlglot.parse(sql, read="postgres")
        # a bare ';' (possibly carrying only a comment) is not a statement
        statements = [s for s in parsed if s is not None and not isinstance(s, exp.Semicolon)]
    except SqlglotError as e:
        raise _reject(f"could not parse query: {str(e).splitlines()[0][:120]}")
    if len(statements) != 1:
        raise _reject("exactly one statement is allowed")
    tree = statements[0]
    if not isinstance(tree, (exp.Select, exp.Union)):
        raise _reject(f"only SELECT is allowed, got {type(tree).__name__}")

    cte_names = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}

    for node in tree.walk():
        if isinstance(node, FORBIDDEN_NODES):
            raise _reject(f"{type(node).__name__} is not allowed")
        if isinstance(node, exp.Anonymous):
            fname = str(node.name).lower()
            if fname not in ALLOWED_UNKNOWN_FUNCS:
                raise _reject(f"function {fname}() is not allowed")
        if isinstance(node, exp.Table):
            if not isinstance(node.this, exp.Identifier):
                raise _reject("table functions are not allowed")
            if node.args.get("db") or node.args.get("catalog"):
                raise _reject("schema-qualified tables are not allowed")
            name = node.name.lower()
            if name not in ALLOWED_RELATIONS and name not in cte_names:
                raise _reject(f"relation {name} is not allowed")
    return tree.sql(dialect="postgres", comments=False)


# ---------------------------------------------------------------------------
# Mutations (Tier 3). One UPDATE ... WHERE on a small allowlist of tables and columns.
# ---------------------------------------------------------------------------
from dataclasses import dataclass  # noqa: E402

MUTABLE_COLUMNS = {"orders": {"status"}, "tickets": {"status", "severity"}}
SNAPSHOT_MAX_ROWS = 1000


@dataclass
class MutationPlan:
    sql: str            # normalized UPDATE to run after approval
    table: str
    columns: list       # columns the UPDATE changes
    count_sql: str      # SELECT count(*) of the rows the WHERE matches
    sample_sql: str     # SELECT id of the first rows matched
    snapshot_sql: str   # SELECT id plus current values, for rollback hints


def _mreject(reason: str) -> ToolError:
    return ToolError(
        "SQL_REJECTED", reason,
        "Only one UPDATE ... WHERE is allowed: orders(status) or tickets(status, severity).",
    )


def plan_update(sql: str) -> MutationPlan:
    if not sql or not sql.strip():
        raise _mreject("empty query")
    if len(sql) > MAX_SQL_CHARS:
        raise _mreject(f"query longer than {MAX_SQL_CHARS} characters")
    try:
        parsed = sqlglot.parse(sql, read="postgres")
    except SqlglotError as e:
        raise _mreject(f"could not parse query: {str(e).splitlines()[0][:120]}")
    statements = [s for s in parsed if s is not None and not isinstance(s, exp.Semicolon)]
    if len(statements) != 1:
        raise _mreject("exactly one statement is allowed")
    tree = statements[0]
    if not isinstance(tree, exp.Update):
        raise _mreject(f"only UPDATE is allowed, got {type(tree).__name__}")
    if tree.args.get("with_") or tree.args.get("from_") or tree.args.get("returning"):
        raise _mreject("WITH, FROM and RETURNING are not allowed in an UPDATE")
    where = tree.args.get("where")
    if where is None:
        raise _mreject("UPDATE needs a WHERE clause")

    target = tree.this
    if not isinstance(target, exp.Table) or not isinstance(target.this, exp.Identifier):
        raise _mreject("unsupported UPDATE target")
    if target.args.get("db") or target.args.get("catalog"):
        raise _mreject("schema-qualified tables are not allowed")
    table = target.name.lower()
    if table not in MUTABLE_COLUMNS:
        raise _mreject(f"table {table} may not be changed")

    columns: list[str] = []
    for assignment in tree.expressions:
        if not isinstance(assignment, exp.EQ) or not isinstance(assignment.this, exp.Column):
            raise _mreject("SET must be plain column = value assignments")
        col = assignment.this.name.lower()
        if col not in MUTABLE_COLUMNS[table]:
            raise _mreject(f"column {table}.{col} may not be changed")
        columns.append(col)
    if not columns:
        raise _mreject("nothing to SET")

    for node in tree.walk():
        if node is tree:
            continue
        if isinstance(node, FORBIDDEN_NODES):
            raise _mreject(f"{type(node).__name__} is not allowed")
        if isinstance(node, exp.Anonymous) and str(node.name).lower() not in ALLOWED_UNKNOWN_FUNCS:
            raise _mreject(f"function {str(node.name).lower()}() is not allowed")
        if isinstance(node, exp.Table) and node is not target:
            if not isinstance(node.this, exp.Identifier) or node.args.get("db") or node.args.get("catalog"):
                raise _mreject("only plain table names are allowed in subqueries")
            if node.name.lower() not in MUTABLE_COLUMNS:
                raise _mreject(f"relation {node.name.lower()} is not allowed")

    cond = where.this

    def build(*exprs):
        return exp.select(*exprs).from_(target.copy()).where(cond.copy())

    pg = {"dialect": "postgres"}
    return MutationPlan(
        sql=tree.sql(dialect="postgres", comments=False),
        table=table,
        columns=columns,
        count_sql=build(exp.Count(this=exp.Star()).as_("n")).sql(**pg),
        sample_sql=build("id").order_by("id").limit(10).sql(**pg),
        snapshot_sql=build("id", *columns).order_by("id").limit(SNAPSHOT_MAX_ROWS).sql(**pg),
    )
