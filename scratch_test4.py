import asyncio
from fastapi.testclient import TestClient
from api.main import app

def test():
    with TestClient(app) as client:
        payload = {
            "host": "BSTOLL-L",
            "event_type": "credential_access_attempt",
            "raw_event": "rundll32.exe accessed lsass.exe"
        }
        response = client.post("/api/v1/trigger", json=payload)
        print(f"Status: {response.status_code}")
        print(response.json())

test()
