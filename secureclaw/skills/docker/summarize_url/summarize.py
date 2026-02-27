"""Sandboxed URL summarization skill — runs inside a Docker container."""

import json
import os
import re
import sys

import httpx


def main():
    url = os.environ.get("SUMMARIZE_URL", "")

    if not url:
        print(json.dumps({"error": "No URL provided"}))
        sys.exit(1)

    try:
        with httpx.Client(
            timeout=15,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            resp = client.get(
                url,
                headers={"User-Agent": "SecureClaw/1.0 (URL Summarizer)"},
            )
            resp.raise_for_status()

            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type and "text/plain" not in content_type:
                print(json.dumps({"error": f"Unsupported content type: {content_type}"}))
                sys.exit(1)

            body = resp.text

        # Strip HTML tags
        body = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", body, flags=re.DOTALL | re.IGNORECASE)
        body = re.sub(r"<[^>]+>", " ", body)
        body = re.sub(r"\s+", " ", body).strip()

        if len(body) > 2000:
            body = body[:2000] + "..."

        print(json.dumps({"url": url, "text": body}))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
