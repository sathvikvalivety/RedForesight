import asyncio
from fastapi.testclient import TestClient
from api.main import app

def test():
    with TestClient(app) as client:
        payload = {
            "episode_id": "ep-123",
            "confirmed_technique_id": "T1000",
            "outcome_confirmed": True
        }
        response = client.post("/api/v1/feedback", json=payload)
        print(f"Status: {response.status_code}")
        print(response.json())

test()
