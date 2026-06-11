import sys
from pathlib import Path
import asyncio

sys.path.insert(0, str(Path(__file__).parent))
from splunk.mcp_client import SplunkMCPClient

async def run():
    client = SplunkMCPClient()
    ok = await client.health_check()
    if not ok:
        print("MCP health check failed")
        return
    res = await client.search("search index=* | stats count by index, host | head 10", earliest="0", latest="now")
    print(res)
    await client.close()

if __name__ == "__main__":
    asyncio.run(run())
