FROM python:3.12-slim
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.11.7 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev && useradd --uid 10001 --no-create-home fixture
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/app/.venv/bin/python", "-m", "purpleloop.fixture.app"]
