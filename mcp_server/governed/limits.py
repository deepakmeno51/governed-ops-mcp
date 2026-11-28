"""Size limits on what a tool may hand back to the agent.
The database limits rows (ROW_CAP). These limit how large a row and a whole result can be, so one query
cannot produce a huge payload that is slow to redact, slow to send, or floods the agent's context."""
from typing import Any

MAX_CELL_CHARS = 2000          # one text value
MAX_RESULT_CHARS = 200_000     # all text values in one result, roughly the size of the response


def clip_rows(rows: list[dict[str, Any]], max_cell: int = MAX_CELL_CHARS,
              max_total: int = MAX_RESULT_CHARS) -> tuple[list[dict[str, Any]], bool, int]:
    """Returns (rows, stopped_early, cells_clipped). Long text is cut and marked. When the running total passes
    max_total, the remaining rows are dropped."""
    out: list[dict[str, Any]] = []
    total, clipped = 0, 0
    for row in rows:
        new_row = {}
        for key, value in row.items():
            if isinstance(value, str) and len(value) > max_cell:
                clipped += 1
                value = value[:max_cell] + f"...[truncated {len(value) - max_cell} more characters]"
            total += len(value) if isinstance(value, str) else 12
            new_row[key] = value
        if out and total > max_total:
            return out, True, clipped
        out.append(new_row)
    return out, False, clipped
