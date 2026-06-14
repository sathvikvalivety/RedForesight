import os
import json
import logging
import httpx
from datetime import datetime
from pydantic import BaseModel
from typing import Any, Dict

logger = logging.getLogger(__name__)

class AlertWriter:
    def __init__(self):
        from dotenv import load_dotenv
        load_dotenv()
        self.hec_url = f"https://{os.getenv('SPLUNK_HOST', 'localhost')}:{os.getenv('HEC_PORT', '8088')}/services/collector/event"
        self.hec_token = os.getenv("HEC_TOKEN", "")
        self.rest_url = f"https://{os.getenv('SPLUNK_HOST', 'localhost')}:{os.getenv('SPLUNK_PORT', '8089')}/services/receivers/simple"
        self.username = os.getenv("SPLUNK_USERNAME", "admin")
        self.password = os.getenv("SPLUNK_PASSWORD", "")
        self.client = httpx.AsyncClient(verify=False, timeout=10.0)
        self.fallback_file = "failed_alerts.log"
        self.write_method = None

    async def write_brief(self, brief: Any) -> bool:
        # Convert DefenderBrief to dictionary
        if isinstance(brief, BaseModel):
            data = brief.model_dump(mode="json")
        else:
            data = brief
            
        event_payload = {
            "time": datetime.utcnow().timestamp(),
            "host": data.get("splunk_context", {}).get("host", "unknown"),
            "source": "redforesight_agent",
            "sourcetype": "_json",
            "index": "main",
            "event": data
        }
        
        # Try HEC first
        if self.hec_token and self.hec_token != "your_hec_token_here":
            try:
                resp = await self.client.post(
                    self.hec_url,
                    headers={"Authorization": f"Splunk {self.hec_token}"},
                    json=event_payload
                )
                if resp.status_code == 200:
                    logger.info("Successfully wrote brief to Splunk via HEC.")
                    self.write_method = "hec"
                    return True
                else:
                    logger.warning(f"HEC write failed with status {resp.status_code}: {resp.text}")
            except Exception as e:
                logger.warning(f"HEC write exception: {e}")
                
        # Try REST fallback
        try:
            params = {
                "source": "redforesight_agent",
                "sourcetype": "_json",
                "index": "main"
            }
            resp = await self.client.post(
                self.rest_url,
                auth=(self.username, self.password),
                params=params,
                json=data
            )
            if resp.status_code == 200:
                logger.info("Successfully wrote brief to Splunk via REST API.")
                self.write_method = "rest"
                return True
            else:
                logger.warning(f"REST write failed with status {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.warning(f"REST write exception: {e}")
            
        # Fallback to local JSON file
        try:
            with open(self.fallback_file, "a") as f:
                f.write(json.dumps(event_payload) + "\n")
            logger.info(f"Wrote brief to fallback file: {self.fallback_file}")
            self.write_method = "file"
            return True
        except Exception as e:
            logger.error(f"Failed to write brief to fallback file: {e}")
            return False

    async def close(self):
        await self.client.aclose()
