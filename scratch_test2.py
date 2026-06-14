import asyncio
from splunk.alert_writer import AlertWriter

async def test():
    writer = AlertWriter()
    brief = {"splunk_context": {"host": "BSTOLL-L"}, "message": "Test brief"}
    success = await writer.write_brief(brief)
    print(f"Success: {success}")
    await writer.close()

asyncio.run(test())
