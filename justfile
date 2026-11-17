# Run `just` to list recipes.
default:
    @just --list

setup:
    uv sync

test:
    uv run pytest -q

lint:
    uv run python -m pyflakes src || true

check: test
    uv build
