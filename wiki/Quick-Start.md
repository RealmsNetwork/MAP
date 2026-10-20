# Quick Start

Requires Python 3.11+.

```bash
git clone https://github.com/RealmsNetwork/MAP.git
cd MAP
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
map-server --transport http
```

The default URL is `http://127.0.0.1:8765/mcp`. Read the [configuration guide](https://github.com/RealmsNetwork/MAP/blob/main/docs/configuration.md) before adding a panel.
