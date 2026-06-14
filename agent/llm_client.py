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
        self.provider = os.getenv("LLM_PROVIDER", "gemini").lower()
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        
        # Initialize Google GenAI SDK if using Gemini
        # We use direct HTTP calls now as per spec
        pass
        self.client = httpx.AsyncClient(timeout=60.0)
        
        self.system_prompt = """You are a red team operator simulating an advanced persistent threat actor.
You have just observed an attack technique being executed against a target
environment. Your goal is to assess which follow-on techniques the attacker
is most likely to execute next, based on the observed signal, environmental
context, and standard adversarial tradecraft.

Think like an attacker. Consider:
- What credentials or access has the attacker likely gained?
- What is the path of least resistance to their objective?
- Which techniques leave the least forensic evidence?
- Which techniques are most commonly chained after the observed one?

Return ONLY a valid JSON array. No preamble, no explanation, no markdown
code fences. The array must contain objects with exactly these fields:
technique_id, llm_probability (float 0.0-1.0), llm_reasoning (string)."""

    async def score_moves(self, signal: ObservedSignal, context: SplunkContext, candidate_moves: List[PredictedMove]) -> List[PredictedMove]:
        if not candidate_moves:
            return []
            
        moves_list = "\n".join([f"- {m.technique_id} | {m.technique_name} | {m.tactic} | current_score={m.probability:.3f}" for m in candidate_moves])
        
        user_prompt = f"""Observed signal:
  Host: {signal.host}
  Event: {signal.raw_event}
  Type: {signal.event_type}
  Severity: {signal.severity}

Environment context:
  Process events in last 30 min: {len(context.process_events)}
  Auth events in last 30 min: {len(context.auth_events)}
  Network events in last 30 min: {len(context.network_events)}
  Asset criticality: {context.asset_criticality or 'unknown'}

Candidate next moves to score:
{moves_list}

For each technique_id above, return your adversarial probability assessment.
Focus on what an attacker would realistically do next given this specific signal.

Return ONLY this JSON array with no other text:
[
  {{"technique_id": "T1069.001", "llm_probability": 0.82, "llm_reasoning": "After credential dumping, local group enumeration identifies privilege boundaries and targets for lateral movement."}}
]"""

        try:
            if self.provider == "gemini":
                return await self._score_with_gemini(self.system_prompt, user_prompt, candidate_moves)
            elif self.provider == "ollama":
                return await self._score_with_ollama(self.system_prompt, user_prompt, candidate_moves)
            elif self.provider == "anthropic":
                return await self._score_with_anthropic(self.system_prompt, user_prompt, candidate_moves)
            else:
                logger.warning(f"Unknown LLM_PROVIDER '{self.provider}'. Falling back to original moves.")
                return candidate_moves
        except Exception as e:
            logger.warning(f"LLM scoring failed ({self.provider}): {e}. Returning original moves.")
            return candidate_moves

    async def _score_with_gemini(self, system_prompt: str, user_prompt: str, original_moves: List[PredictedMove]) -> List[PredictedMove]:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set.")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent?key={api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": f"{system_prompt}\n\n---\n\n{user_prompt}"
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 8000,
                "responseMimeType": "application/json"
            }
        }
        resp = await self.client.post(url, json=payload)
        resp.raise_for_status()
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        return self._parse_llm_response(text, original_moves)

    async def _score_with_ollama(self, system_prompt: str, user_prompt: str, original_moves: List[PredictedMove]) -> List[PredictedMove]:
        url = f"{self.ollama_base_url}/api/chat"
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "stream": False,
            "options": {"temperature": 0.3}
        }
        resp = await self.client.post(url, json=payload)
        resp.raise_for_status()
        text = resp.json()["message"]["content"]
        return self._parse_llm_response(text, original_moves)

    async def _score_with_anthropic(self, system_prompt: str, user_prompt: str, original_moves: List[PredictedMove]) -> List[PredictedMove]:
        if not self.anthropic_key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.anthropic_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1000,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt}
            ]
        }
        resp = await self.client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"]
        return self._parse_llm_response(text, original_moves)

    def _parse_llm_response(self, text: str, original_moves: List[PredictedMove]) -> List[PredictedMove]:
        print(f"DEBUG: raw text: {repr(text)}")
        # Strip markdown fences
        text = text.strip()
        if text.startswith("```"):
            lines = text.split('\n')
            if len(lines) > 1 and lines[0].startswith("```"):
                lines = lines[1:]
            if len(lines) > 0 and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()
            
        # Find JSON array
        start_idx = text.find('[')
        end_idx = text.rfind(']')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            text = text[start_idx:end_idx+1]
            
        try:
            data = json.loads(text)
            updates = {item["technique_id"]: item for item in data if "technique_id" in item}
            
            # Update the original moves (do not re-sort here)
            for move in original_moves:
                if move.technique_id in updates:
                    update_data = updates[move.technique_id]
                    if "llm_probability" in update_data:
                        try:
                            move.probability = float(update_data["llm_probability"])
                        except ValueError:
                            pass
                    if "llm_reasoning" in update_data:
                        move.reasoning = str(update_data["llm_reasoning"])
                        
            return original_moves
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON from LLM: {text}")
            return original_moves

    async def close(self):
        await self.client.aclose()
