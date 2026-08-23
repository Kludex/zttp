1. When testing `pytest.raises(ValueError)`, always use the `match` parameter (`match=...`).
2. Avoid small wrapper functions in tests, such as `make_client` and `make_server`.
3. Use `TypedDict` for parameters and dataclasses for output data.
