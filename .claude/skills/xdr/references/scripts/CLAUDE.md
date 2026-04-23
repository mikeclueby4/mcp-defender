# Investigation scripts

Reusable Python scripts for analysing MCP-XDR overflow files and other investigation artefacts. Create a script here when a task needs more logic than a one-liner but is likely to recur.

**Naming convention:** descriptive and instantly understandable by an LLM: `truncate-long-columns-tsv.py`, `count-distinct-ips-in-all-json-fields.py`.

**CLI contract:** 
- accept a file path as the first positional argument
- (optional additional arguments)
- write tsv to stdout with clearly-inferrable header names

This makes scripts composable.

**When to NOT script vs. one-liner:** if the logic fits in simple-enough e.g. `cut | sort | uniq`, `jq`, `rg -P` or `awk` invocation, don't script it.
