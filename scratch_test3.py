import asyncio
from fastapi.testclient import TestClient
from api.main import app

def test():
    with TestClient(app) as client:
        response = client.get("/health")
        print(response.json())

test()
