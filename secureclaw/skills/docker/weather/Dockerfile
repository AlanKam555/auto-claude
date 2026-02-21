# SecureClaw — Weather Skill Container
# Minimal image for OpenWeather API calls in an isolated sandbox.

FROM python:3.11-slim

RUN pip install --no-cache-dir httpx==0.28.* && \
    rm -rf /root/.cache

RUN useradd --no-create-home --shell /bin/false runner
USER runner
WORKDIR /app

COPY weather.py /app/weather.py

ENTRYPOINT ["python", "/app/weather.py"]
