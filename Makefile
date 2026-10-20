.PHONY: install lint test build check

install:
	python -m pip install -e '.[dev]'

lint:
	ruff check src tests deploy

test:
	pytest -q

build:
	python -m build

check: lint test build
	python -m compileall -q src tests deploy
