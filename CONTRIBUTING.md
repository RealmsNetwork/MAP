# Contributing to MAP

Thanks for helping improve Model Access Panel.

Before a PR, search existing issues, explain the use case, keep commits focused, add tests, and update docs/config examples for user-facing changes. Run:

```bash
python -m pip install -e '.[dev]'
ruff check src tests deploy
python -m compileall -q src tests deploy
pytest -q
python -m build
```

## Security expectations

- Never include API keys, bearer tokens, signed Wings URLs, private hosts, or production logs.
- Do not add arbitrary-URL fetching, disabled TLS validation, or implicit redirects.
- Do not weaken host validation or token checks to make a test pass.
- Use mocked HTTP calls; tests must not require live panel credentials.

Use a feature branch and open a PR targeting `main`. Explain migration effects and destructive behavior. By participating, contributors agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
