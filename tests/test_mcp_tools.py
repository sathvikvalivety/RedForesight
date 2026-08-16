import pytest
from splunk.mcp_client import SplunkMCPClient
from agent.schemas import MCPToolResult
from unittest.mock import patch, AsyncMock

@pytest.fixture
def client():
    return SplunkMCPClient()

@pytest.mark.asyncio
async def test_health_check_returns_bool(client):
    # Mocking _call_tool to avoid needing a real splunk server for tests
    # Wait, the user instructions do not explicitly say to mock it, but they say "Instantiate SplunkMCPClient. Call await client.health_check(). Assert result is a bool. Close client."
    # Let's try without mock first, but we might not have a running server.
    # Actually, they provide instructions: "Instantiate SplunkMCPClient...".
    # We will mock _call_tool to simulate the real behavior if the server is down. 
    # Or just let it fail gracefully as health_check() catches exceptions and returns False.
    result = await client.health_check()
    assert isinstance(result, bool)
    await client.close()

@pytest.mark.asyncio
async def test_search_returns_mcp_tool_result(client):
    # If the real server is not available, it should still return an MCPToolResult with success=False and an error.
    # We can assert it returns an MCPToolResult.
    with patch.object(client, '_call_tool', new_callable=AsyncMock) as mock_call:
        mock_call.return_value = {"result": {"content": [{"type": "text", "text": "[]"}]}}
        result = await client.search("index=botsv3 | head 5")
        assert isinstance(result, MCPToolResult)
        assert result.tool_name != ""
    await client.close()

@pytest.mark.asyncio
async def test_search_bad_spl_does_not_raise(client):
    with patch.object(client, '_call_tool', new_callable=AsyncMock) as mock_call:
        mock_call.side_effect = Exception("Invalid SPL")
        result = await client.search("this is not valid spl !@#")
        assert isinstance(result, MCPToolResult)
        assert result.success is False
    await client.close()
