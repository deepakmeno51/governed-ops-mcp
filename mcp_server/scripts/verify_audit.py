"""python -m scripts.verify_audit  ->  exit 0 if the audit chain is intact, 1 if not."""
import json
import sys

from governed.audit import verify_chain

result = verify_chain()
print(json.dumps(result, indent=2))
sys.exit(0 if result["ok"] else 1)
