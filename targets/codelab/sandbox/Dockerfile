# The codelab sandbox (WP5.5, ADR 0015). The same pinned base as every fixture image, the
# standard library only, and one file: the supervisor. Nothing from the purpleloop package is
# installed here, so no fixture or harness code exists inside the container that runs snippets.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
COPY targets/codelab/sandbox/supervisor.py /sandbox/supervisor.py
RUN useradd --uid 10003 --no-create-home --shell /usr/sbin/nologin sandbox \
    && mkdir /scratch && chmod 0555 /sandbox /sandbox/supervisor.py
USER 10003:10003
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["/usr/local/bin/python3", "-I", "-S", "-B", "/sandbox/supervisor.py"]
