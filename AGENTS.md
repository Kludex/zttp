1. When testing `pytest.raises(ValueError)`, always use the `match` parameter (`match=...`).
2. Avoid small wrapper functions in tests, such as `make_client` and `make_server`.
3. Use `TypedDict` for parameters and dataclasses for output data.

# Pull Requests

- Include a concise `## Summary`.
- For relevant HTTP behavior changes, add `## Other HTTP Parsers` with a `Parser | Language | Behavior | Reference` table. Link exact evidence.
- Omit `## Other HTTP Parsers` when the comparison is not useful.
- Do not include a `## Tests` section.
- End with `## AI Disclaimer` and: `This PR was developed with the assistance of either Claude or Codex. I've reviewed and verified the changes.`
