FROM python:3.12-alpine@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a

RUN addgroup -S purpleloop && adduser -S -G purpleloop purpleloop
WORKDIR /app
COPY --chown=purpleloop:purpleloop app.py /app/app.py
USER purpleloop
EXPOSE 8080
CMD ["python", "/app/app.py"]
