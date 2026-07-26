FROM python:3.12-alpine

RUN addgroup -S purpleloop && adduser -S -G purpleloop purpleloop
WORKDIR /app
COPY --chown=purpleloop:purpleloop app.py /app/app.py
USER purpleloop
EXPOSE 8080
CMD ["python", "/app/app.py"]
