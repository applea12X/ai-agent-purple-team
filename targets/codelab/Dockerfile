# The codelab fixture application (WP5.5, ADR 0015). Same pinned base and uv as supportlab. The
# dependency layer is installed before the source is copied, so a source change rebuilds only
# the last layer. This image never runs a snippet; the sandbox image does.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.11.7@sha256:240fb85ab0f263ef12f492d8476aa3a2e4e1e333f7d67fbdd923d00a506a516a /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv pip install --python /app/.venv/bin/python --no-deps . \
    && useradd --uid 10004 --no-create-home codelab \
    && mkdir /ipc && chown 10004:10004 /ipc && chmod 0755 /ipc
USER 10004:10004
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/app/.venv/bin/python", "-m", "purpleloop.fixture.codelab.app"]
