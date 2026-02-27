"""Sandboxed web search skill — runs inside a Docker container."""

import json
import os
import sys

import httpx


def main():
    query = os.environ.get("SEARCH_QUERY", "")
    api_key = os.environ.get("TAVILY_API_KEY", "")

    if not query:
        print(json.dumps({"error": "No query provided"}))
        sys.exit(1)

    if not api_key:
        print(json.dumps({"error": "TAVILY_API_KEY not set"}))
        sys.exit(1)

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                "https://api.tavily.com/search",
                json={
                    "api_key": api_key,
                    "query": query,
                    "max_results": 5,
                    "include_answer": True,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        print(json.dumps({
            "answer": data.get("answer"),
            "results": [
                {
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "content": r.get("content", "")[:200],
                }
                for r in data.get("results", [])[:5]
            ],
        }))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
