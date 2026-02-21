# SecureClaw — URL Summarize Skill Container
# Minimal image for fetching and extracting text from URLs.

FROM python:3.11-slim

RUN pip install --no-cache-dir httpx==0.28.* && \
    rm -rf /root/.cache

RUN useradd --no-create-home --shell /bin/false runner
USER runner
WORKDIR /app

COPY summarize.py /app/summarize.py

ENTRYPOINT ["python", "/app/summarize.py"]
