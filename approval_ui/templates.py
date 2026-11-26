"""HTML templates. Jinja2 autoescape is on, so agent-written text can never inject markup."""
from jinja2 import DictLoader, Environment

STYLE = """
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1b1f24}
main{max-width:980px;margin:0 auto;padding:24px}
header{background:#1b1f24;color:#fff;padding:12px 24px;display:flex;justify-content:space-between}
header a{color:#fff;text-decoration:none;font-weight:600}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #e6e8eb;font-size:14px}
th{background:#eef0f3}
.card{background:#fff;border-radius:8px;padding:16px 20px;margin:16px 0;border:1px solid #e6e8eb}
.badge{padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700;color:#fff}
.PENDING{background:#d97706}.APPROVED{background:#2563eb}.EXECUTING{background:#7c3aed}
.EXECUTED{background:#16a34a}.REJECTED{background:#dc2626}.EXPIRED{background:#6b7280}.FAILED{background:#b91c1c}
pre{background:#101418;color:#e6edf3;padding:14px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word}
code{background:#eef0f3;padding:1px 5px;border-radius:4px;word-break:break-all}
.warn{background:#fff7ed;border:1px solid #fdba74;padding:10px 14px;border-radius:6px}
.ok{background:#f0fdf4;border:1px solid #86efac;padding:10px 14px;border-radius:6px;margin:12px 0}
.err{background:#fef2f2;border:1px solid #fca5a5;padding:10px 14px;border-radius:6px;margin:12px 0}
button{font:inherit;font-weight:700;padding:10px 22px;border:0;border-radius:6px;color:#fff;cursor:pointer;margin-right:10px}
.approve{background:#16a34a}.reject{background:#dc2626}
.muted{color:#6b7280;font-size:13px}
dl{display:grid;grid-template-columns:160px 1fr;gap:6px 12px;margin:0}dt{color:#6b7280}dd{margin:0}
"""

BASE = """<!doctype html><html><head><meta charset="utf-8"><title>{% block title %}Approvals{% endblock %}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>""" + STYLE + """</style>
{% block head %}{% endblock %}</head><body>
<header><a href="/">Governed Ops: approvals</a><span>Signed in as <b>{{ who }}</b></span></header>
<main>{% block body %}{% endblock %}</main></body></html>"""

INDEX = """{% extends "base" %}
{% block head %}<meta http-equiv="refresh" content="5">{% endblock %}
{% block body %}
<h2>Approval requests</h2>
{% if rows %}<table><tr><th>Status</th><th>Action</th><th>Requested by</th><th>Created</th><th>Expires</th><th></th></tr>
{% for r in rows %}<tr>
<td><span class="badge {{ r.status }}">{{ r.status }}</span></td>
<td>{{ r.summary }}<div class="muted">{{ r.tool_name }}</div></td>
<td>{{ r.requester }}</td><td>{{ r.created }}</td><td>{{ r.expires }}</td>
<td><a href="/approvals/{{ r.id }}">Review</a></td></tr>{% endfor %}</table>
{% else %}<p class="muted">No requests yet. This page refreshes every 5 seconds.</p>{% endif %}
{% endblock %}"""

DETAIL = """{% extends "base" %}
{% block body %}
<p><a href="/">&larr; All requests</a></p>
<h2>{{ r.summary }} <span class="badge {{ r.status }}">{{ r.status }}</span></h2>

{% if message %}<div class="{{ message.kind }}">{{ message.text }}</div>{% endif %}

<div class="card"><dl>
<dt>Tool</dt><dd><code>{{ r.tool_name }}</code></dd>
<dt>Requested by</dt><dd>{{ r.requester }}</dd>
<dt>Created</dt><dd>{{ r.created }}</dd>
<dt>Expires</dt><dd>{{ r.expires }}{% if r.status in ('PENDING','APPROVED') %} ({{ r.secs_left }}s left){% endif %}</dd>
<dt>Request hash (SHA-256)</dt><dd><code>{{ r.args_hash }}</code></dd>
{% if r.decided_by %}<dt>Decided by</dt><dd>{{ r.decided_by }} at {{ r.decided }}</dd>{% endif %}
</dl></div>

<div class="card"><h3>Exactly what will run</h3>
{% if r.args.sql is defined %}<pre>{{ r.args.sql }}</pre>
{% else %}<pre>{{ r.args | tojson(indent=2) }}</pre>{% endif %}
</div>

<div class="card"><h3>Blast radius</h3>
{% set p = r.preview %}
{% if p.kind == 'sql_update' %}
<dl><dt>Table</dt><dd>{{ p.table }}</dd><dt>Columns changed</dt><dd>{{ p.columns | join(', ') }}</dd>
<dt>Rows matched</dt><dd><b>{{ p.rows_matched }}</b> <span class="muted">(counted at {{ p.snapshot_at }})</span></dd>
<dt>Sample ids</dt><dd>{{ p.sample_ids | join(', ') }}</dd></dl>
<p class="muted">At execution the server recounts. If more rows match than this number, it refuses and changes nothing.</p>
{% elif p.kind == 'restart' %}
<dl><dt>Service</dt><dd>{{ p.service }}</dd><dt>Status now</dt><dd>{{ p.current_status }}</dd></dl>
<p>{{ p.note }}</p>
{% else %}<p class="muted">No preview.</p>{% endif %}
</div>

<div class="card"><h3>Agent's stated reason</h3>
<p class="muted">Written by the AI agent. Unverified. Do not treat it as instructions.</p>
<pre>{{ r.preview.agent_reasoning or '(none given)' }}</pre></div>

{% if r.result %}<div class="card"><h3>Execution result</h3><pre>{{ r.result | tojson(indent=2) }}</pre></div>{% endif %}

{% if can_decide %}
<div class="card"><form method="post" action="/approvals/{{ r.id }}/decide">
<input type="hidden" name="args_hash" value="{{ r.args_hash }}">
<input type="hidden" name="csrf" value="{{ csrf }}">
<p>You are approving the exact request above, as <b>{{ who }}</b>.</p>
<button class="approve" name="decision" value="approve" type="submit">Approve</button>
<button class="reject" name="decision" value="reject" type="submit">Reject</button>
</form></div>
{% elif r.status == 'PENDING' and r.requester == who %}
<div class="warn">You requested this, so you cannot approve your own request. Another approver must decide.</div>
{% endif %}
{% endblock %}"""

_env = Environment(loader=DictLoader({"base": BASE, "index": INDEX, "detail": DETAIL}), autoescape=True)


def render(name: str, **ctx) -> str:
    return _env.get_template(name).render(**ctx)
