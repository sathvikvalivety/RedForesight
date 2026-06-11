import httpx
import asyncio
import json

async def main():
    with open(".env", "r") as f:
        lines = f.readlines()
        token = ""
        for line in lines:
            if line.startswith("MCP_TOKEN="):
                token = line.strip().split("=", 1)[1]
                break

    url = "https://localhost:8089/services/mcp"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(url, headers=headers, json=payload, timeout=30)
        with open("mcp_tools.json", "w") as out:
            json.dump(response.json(), out, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
