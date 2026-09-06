.PHONY: setup lint typecheck test phase0-check phase0-full-check fixture-up fixture-check fixture-down

setup:
	uv sync --frozen

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy

test:
	uv run pytest

phase0-check: lint typecheck test

phase0-full-check: phase0-check
	@trap '$(MAKE) fixture-down' EXIT; $(MAKE) fixture-up; $(MAKE) fixture-check

fixture-up:
	docker compose up --build --wait phase0-fixture

fixture-check:
	docker compose exec -T phase0-fixture python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
	docker compose exec -T phase0-fixture python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/records/record-1', timeout=2)"
	docker compose exec -T phase0-fixture sh -c 'test "$$(id -u)" -ne 0'
	docker compose exec -T phase0-fixture sh -c '! touch /phase0-must-remain-read-only'

fixture-down:
	docker compose down --remove-orphans

.PHONY: phase1-check phase1-demo
phase1-check: lint typecheck test

phase1-demo:
	uv run purpleloop phase1-demo
