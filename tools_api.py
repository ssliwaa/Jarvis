"""Minimalny klient HTTP do lokalnego Jarvisa (omija problemy z nagłówkami w bashu)."""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:4700"
ORIGIN = "http://127.0.0.1:4700"


def call(path, payload=None, timeout=380):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data,
                                     {"Content-Type": "application/json", "Origin": ORIGIN})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        try:
            return error.code, json.loads(body)
        except ValueError:
            return error.code, {"raw": body}


if __name__ == "__main__":
    path = sys.argv[1]
    payload = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
    status, body = call(path, payload)
    print(status)
    print(json.dumps(body, ensure_ascii=False, indent=2)[:3000])
