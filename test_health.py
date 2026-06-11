import asyncio
from splunk.mcp_client import SplunkMCPClient

async def test():
    c = SplunkMCPClient()
    ok = await c.health_check()
    print(f'health_check={ok}')
    await c.close()

asyncio.run(test())
