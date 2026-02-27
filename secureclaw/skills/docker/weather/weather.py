"""Sandboxed weather skill — runs inside a Docker container."""

import json
import os
import sys

import httpx


def main():
    location = os.environ.get("WEATHER_LOCATION", "")
    api_key = os.environ.get("OPENWEATHER_API_KEY", "")

    if not location:
        print(json.dumps({"error": "No location provided"}))
        sys.exit(1)

    if not api_key:
        print(json.dumps({"error": "OPENWEATHER_API_KEY not set"}))
        sys.exit(1)

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                "https://api.openweathermap.org/data/2.5/weather",
                params={
                    "q": location,
                    "appid": api_key,
                    "units": "metric",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        weather = data.get("weather", [{}])[0]
        main_data = data.get("main", {})
        wind = data.get("wind", {})

        print(json.dumps({
            "city": data.get("name", location),
            "country": data.get("sys", {}).get("country", ""),
            "description": weather.get("description", ""),
            "temp": main_data.get("temp"),
            "feels_like": main_data.get("feels_like"),
            "humidity": main_data.get("humidity"),
            "wind_speed": wind.get("speed"),
        }))

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print(json.dumps({"error": f"Location not found: {location}"}))
        else:
            print(json.dumps({"error": f"API error: {e.response.status_code}"}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
