import asyncio
from splunk.alert_writer import AlertWriter

async def test():
    w = AlertWriter()
    await w.write_brief({'test': 'test'})
    print(f'Write method: {w.write_method}')

asyncio.run(test())
