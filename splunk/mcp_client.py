import os
import json
import time
import httpx
import asyncio
from typing import Dict, List, Any, Optional
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from agent.schemas import MCPToolResult
from splunk.spl_templates import build_context_queries

class SplunkMCPClient:
    def __init__(self):
        # Load environment variables manually to avoid python-dotenv dependency requirement if not present
        env_vars = {}
        if os.path.exists(".env"):
            with open(".env", "r") as f:
                for line in f:
                    if "=" in line and not line.startswith("#"):
                        key, val = line.strip().split("=", 1)
                        env_vars[key] = val
        
        self.url = env_vars.get("MCP_SERVER_URL", os.environ.get("MCP_SERVER_URL", ""))
        self.token = env_vars.get("MCP_TOKEN", os.environ.get("MCP_TOKEN", ""))
        timeout_sec = int(env_vars.get("MCP_TIMEOUT_SECONDS", os.environ.get("MCP_TIMEOUT_SECONDS", "30")))
        
        verify_ssl_str = env_vars.get("SPLUNK_VERIFY_SSL", os.environ.get("SPLUNK_VERIFY_SSL", "False"))
        verify_ssl = verify_ssl_str.lower() in ("true", "1", "yes")
        
        self.client = httpx.AsyncClient(
            verify=verify_ssl,
            timeout=timeout_sec,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
        )

    @retry(
        retry=retry_if_exception_type(httpx.TimeoutException),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        stop=stop_after_attempt(3)
    )
    async def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }
        response = await self.client.post(self.url, json=payload)
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise Exception(f"MCP JSON-RPC Error: {data['error'].get('message', str(data['error']))}")
        return data

    def _parse_content(self, result_dict: dict) -> List[Dict]:
        parsed_results = []
        if "result" in result_dict and "content" in result_dict["result"]:
            for block in result_dict["result"]["content"]:
                if block.get("type") == "text":
                    text_content = block.get("text", "")
                    try:
                        parsed = json.loads(text_content)
                        if isinstance(parsed, list):
                            parsed_results.extend(parsed)
                        elif isinstance(parsed, dict):
                            # Sometimes data is nested inside 'results', 'data', or 'rows'
                            for key in ["results", "data", "rows"]:
                                if key in parsed and isinstance(parsed[key], list):
                                    parsed_results.extend(parsed[key])
                                    break
                            else:
                                parsed_results.append(parsed)
                    except json.JSONDecodeError:
                        parsed_results.append({"raw": text_content})
        return parsed_results

    async def health_check(self) -> bool:
        try:
            result = await self._call_tool("splunk_get_info", {})
            content = self._parse_content(result)
            if content:
                return True
            return False
        except Exception as e:
            print(f"Health check failed: {e}. Check token audience, if Splunk is running, and if port 8089 is accessible.")
            return False

    async def search(self, spl_query: str, earliest: str = "-15m", latest: str = "now", max_results: int = 100) -> MCPToolResult:
        start_time = time.monotonic()
        try:
            args = {
                "query": spl_query,
                "earliest_time": earliest,
                "latest_time": latest,
                "row_limit": max_results
            }
            result_dict = await self._call_tool("splunk_run_query", args)
            rows = self._parse_content(result_dict)
            duration_ms = (time.monotonic() - start_time) * 1000
            
            return MCPToolResult(
                tool_name="splunk_run_query",
                success=True,
                data=rows,
                duration_ms=duration_ms,
                rows_returned=len(rows)
            )
        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            return MCPToolResult(
                tool_name="splunk_run_query",
                success=False,
                error=str(e),
                duration_ms=duration_ms,
                rows_returned=0
            )

    async def lookup(self, lookup_name: str, key_field: str, key_value: str) -> MCPToolResult:
        spl_query = f'| inputlookup {lookup_name} | where {key_field}="{key_value}" | head 1'
        # lookups are not time-bounded, so use earliest="-1s" as a dummy
        return await self.search(spl_query, earliest="-1s", latest="now", max_results=1)

    async def create_alert(self, alert_name: str, description: str, severity: str, custom_fields: Dict[str, Any]) -> MCPToolResult:
        return MCPToolResult(
            tool_name="create_alert",
            success=False,
            error="Not supported by Splunk MCP Server — no write tools exposed. Phase 4 will use Splunk REST API directly.",
            duration_ms=0.0,
            rows_returned=0
        )

    async def get_metadata(self, meta_type: str, index: str = "*", earliest: str = "-24h", latest: str = "now") -> MCPToolResult:
        start_time = time.monotonic()
        try:
            args = {
                "type": meta_type,
                "index": index,
                "earliest_time": earliest,
                "latest_time": latest,
                "row_limit": 100
            }
            result_dict = await self._call_tool("splunk_get_metadata", args)
            rows = self._parse_content(result_dict)
            duration_ms = (time.monotonic() - start_time) * 1000
            
            return MCPToolResult(
                tool_name="splunk_get_metadata",
                success=True,
                data=rows,
                duration_ms=duration_ms,
                rows_returned=len(rows)
            )
        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            return MCPToolResult(
                tool_name="splunk_get_metadata",
                success=False,
                error=str(e),
                duration_ms=duration_ms,
                rows_returned=0
            )

    async def pull_host_context(self, host: str, window_minutes: int = 30) -> Dict[str, MCPToolResult]:
        queries = build_context_queries(host, window_minutes)
        
        # Fire the 4 event queries concurrently
        keys = ["host_summary", "auth_events", "process_events", "network_events"]
        earliest_time = "0" if window_minutes == 0 else f"-{window_minutes}m"
        tasks = [
            self.search(queries[k], earliest=earliest_time, latest="now")
            for k in keys
        ]
        results = await asyncio.gather(*tasks)
        
        return dict(zip(keys, results))

    async def close(self):
        await self.client.aclose()


