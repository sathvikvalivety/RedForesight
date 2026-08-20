import os
import json
import logging
import httpx
from typing import List
from dotenv import load_dotenv
from agent.schemas import ObservedSignal, SplunkContext, PredictedMove

logger = logging.getLogger(__name__)

class LLMClient:
    def __init__(self):
        load_dotenv()
        self.provider = os.getenv("LLM_PROVIDER")
        self.gemini_model = os.getenv("GEMINI_MODEL")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL")
        self.ollama_model = os.getenv("OLLAMA_MODEL")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")

        if not self.provider:
            raise ValueError("LLM_PROVIDER must be configured in .env")

        self.client = httpx.AsyncClient(timeout=120.0)

        self.system_prompt = """You are a red team operator simulating an advanced persistent threat actor.
You observe an attack technique and assess which follow-on techniques the attacker will execute next.

Return ONLY a valid JSON array with one entry per technique_id provided.
Each entry must have: technique_id, llm_probability (0.0-1.0), llm_reasoning, llm_explanation, llm_mitigation.

llm_explanation: 2-3 plain English sentences explaining what the attacker will do and why.
llm_mitigation: 1-2 concrete actions the security team should take.

Use the EXACT technique_id values provided. Return ALL candidates."""

    async def score_moves(self, signal: ObservedSignal, context: SplunkContext, candidate_moves: List[PredictedMove]) -> List[PredictedMove]:
        if not candidate_moves:
            return []

        moves_list = "\n".join([f"{m.technique_id}: {m.technique_name} ({m.tactic}, score={m.probability:.3f})" for m in candidate_moves])

        user_prompt = (
            f"Observed signal on {signal.host}:\n"
            f"  Event: {signal.raw_event}\n"
            f"  Type: {signal.event_type}\n"
            f"  Severity: {signal.severity}\n\n"
            f"Candidate next moves to score (return one entry for EACH):\n{moves_list}\n\n"
            f"Return ONLY a JSON array with entries for each technique_id above."
        )

        try:
            if self.provider == "gemini":
                return await self._score_with_gemini(self.system_prompt, user_prompt, candidate_moves)
            elif self.provider == "ollama":
                return await self._score_with_ollama(self.system_prompt, user_prompt, candidate_moves)
            elif self.provider == "anthropic":
                return await self._score_with_anthropic(self.system_prompt, user_prompt, candidate_moves)
            else:
                logger.warning(f"Unknown LLM_PROVIDER '{self.provider}'. Falling back.")
                return candidate_moves
        except Exception as e:
            logger.warning(f"LLM scoring failed ({self.provider}): {e}. Returning original moves.")
            return candidate_moves

    async def _score_with_gemini(self, system_prompt, user_prompt, original_moves):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent"
        payload = {"contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}], "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8000, "responseMimeType": "application/json"}}
        resp = await self.client.post(url, headers={"x-goog-api-key": api_key}, json=payload)
        resp.raise_for_status()
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        return self._parse_llm_response(text, original_moves)

    async def _score_with_ollama(self, system_prompt, user_prompt, original_moves):
        if not self.ollama_base_url or not self.ollama_model:
            raise ValueError("OLLAMA_BASE_URL and OLLAMA_MODEL must be set.")
        url = f"{self.ollama_base_url}/api/chat"
        payload = {"model": self.ollama_model, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}], "stream": False, "options": {"temperature": 0.3, "num_ctx": 4096, "num_predict": 1024}}
        resp = await self.client.post(url, json=payload)
        resp.raise_for_status()
        text = resp.json()["message"]["content"]
        return self._parse_llm_response(text, original_moves)

    async def _score_with_anthropic(self, system_prompt, user_prompt, original_moves):
        if not self.anthropic_key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": self.anthropic_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        payload = {"model": "claude-3-5-haiku-20241022", "max_tokens": 2000, "system": system_prompt, "messages": [{"role": "user", "content": user_prompt}]}
        resp = await self.client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"]
        return self._parse_llm_response(text, original_moves)

    def _parse_llm_response(self, text, original_moves):
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            if len(lines) > 1 and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        start_idx = text.find("[")
        end_idx = text.rfind("]")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            text = text[start_idx:end_idx+1]

        try:
            data = json.loads(text)
            # Build lookup by technique_id and also by technique name
            id_map = {}
            for item in data:
                tid = item.get("technique_id", "")
                id_map[tid] = item

            for move in original_moves:
                update = id_map.get(move.technique_id)
                if not update:
                    # Try fuzzy match by technique name in reasoning
                    for item in data:
                        if move.technique_name.lower() in str(item.get("llm_reasoning", "")).lower():
                            update = item
                            break
                if update:
                    if "llm_probability" in update:
                        try:
                            move.probability = float(update["llm_probability"])
                        except (ValueError, TypeError):
                            pass
                    if "llm_reasoning" in update:
                        move.reasoning = str(update["llm_reasoning"])
                    if "llm_explanation" in update:
                        move.defender_action = str(update["llm_explanation"])
                    if "llm_mitigation" in update:
                        move.splunk_hunting_query = "MITIGATION: " + str(update["llm_mitigation"])

            return original_moves
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON from LLM: {text[:200]}")
            return original_moves

    async def close(self):
        await self.client.aclose()
