1. When testing `pytest.raises(ValueError)`, always use the `match` parameter (`match=...`).
2. Avoid small wrapper functions in tests, such as `make_client` and `make_server`.
3. Use `TypedDict` for parameters and dataclasses for output data.

# Pull Request Guidelines

Use this structure for every pull request description:

```markdown
## Summary

<Briefly explain the behavior changed by this PR and why it should change.>

## Other HTTP Parsers

| Parser | Language | Behavior | Reference |
| --- | --- | --- | --- |
| <implementation> | <language> | <behavior for the same case> | <direct link> |

## AI Disclaimer

This PR was developed with the assistance of either Claude or Codex. I've reviewed and verified the changes.
```

- Keep `Summary` short and focused on observable behavior.
- For HTTP behavior changes, compare the same protocol rule or edge case with relevant parsers in at least three different languages.
- For other changes, keep the table and use one `Not applicable` row that explains why no parser behavior is affected.
- Link directly to the implementation, test, or documentation that supports each comparison.
- State meaningful differences instead of implying that all parsers behave alike.
- Do not include a `Tests` section. CI and the changed test files provide the test evidence.
