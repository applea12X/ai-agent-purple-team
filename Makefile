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

.PHONY: phase2-check supportlab-demo
phase2-check: lint typecheck test

supportlab-demo:
	uv run purpleloop supportlab-demo

.PHONY: phase3-check agent-demo judge-report agent-stochastic
phase3-check: lint typecheck test

agent-demo:
	uv run purpleloop agent-demo

judge-report:
	uv run purpleloop judge-report

# Opt-in only. Needs PURPLELOOP_MODEL_ENDPOINT and, for a hosted API, PURPLELOOP_MODEL_API_KEY.
# A missing credential skips the lane; it never falls back to the offline provider.
agent-stochastic:
	uv run purpleloop agent-run scenarios/agent/agent-indirect-ticket.yaml \
		artifacts/agent-stochastic --repetitions 5 --judge \
		--endpoint "$$PURPLELOOP_MODEL_ENDPOINT" --profile "$${PURPLELOOP_MODEL_PROFILE:-openai-compatible}"
