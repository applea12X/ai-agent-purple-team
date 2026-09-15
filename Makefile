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

.PHONY: phase4-check pr-check smoke-demo holdout-check gates corpus-current audit-export
phase4-check: lint typecheck test

# The fast PR lane: full deterministic quality gate with a JUnit report, the cross-lane smoke
# demo, current corpus metrics, and the five enforcing gates over the smoke bundle.
pr-check: lint typecheck
	uv run pytest --junitxml=artifacts/junit.xml
	uv run purpleloop smoke-demo --output-dir artifacts/smoke
	uv run purpleloop corpus-baseline --output artifacts/corpus-current.json
	uv run purpleloop gates "$$(ls -d artifacts/smoke/*/ | tail -1)" \
		--junit artifacts/junit.xml --risk-current artifacts/corpus-current.json \
		--output artifacts/gates.json

smoke-demo:
	uv run purpleloop smoke-demo

holdout-check:
	uv run purpleloop holdout-check

corpus-current:
	uv run purpleloop corpus-baseline --output artifacts/corpus-current.json

gates:
	uv run purpleloop gates "$$(ls -d artifacts/smoke/*/ | tail -1)" \
		--junit artifacts/junit.xml --risk-current artifacts/corpus-current.json

# The release lane, runnable locally: held-out mutations, an attested demo bundle, and its
# audit export. CI's release job runs the same commands.
.PHONY: release-check
release-check: holdout-check
	uv run purpleloop agent-demo --output-dir artifacts/release-demo
	uv run purpleloop attest-bundle "$$(ls -d artifacts/release-demo/*/ | tail -1)" \
		--builder "local-release" --commit "$$(git rev-parse HEAD)"
	uv run purpleloop verify-bundle "$$(ls -d artifacts/release-demo/*/ | tail -1)" --attestation
	uv run purpleloop audit-export "$$(ls -d artifacts/release-demo/*/ | tail -1)" \
		artifacts/release-audit.json
