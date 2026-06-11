from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
from uuid import UUID

class ObservedSignal(BaseModel):
    signal_id: str
    timestamp: str
    host: str
    source_ip: str
    raw_event: str
    event_type: str
    severity: Literal["low", "medium", "high", "critical"]
    splunk_index: str
    additional_context: Dict[str, Any]

class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    tactic_id: str
    description: str
    detection: str
    platforms: List[str]
    procedure_examples: List[str]
    sub_techniques: List[str]

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        if not v.startswith("T"):
            raise ValueError("technique_id must start with 'T'")
        return v

class PredictedMove(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    probability: float
    confidence_tier: Optional[Literal["high", "medium", "low"]] = None
    reasoning: str
    prerequisite_met: bool
    defender_action: str
    splunk_hunting_query: str

    @model_validator(mode="after")
    def derive_confidence_tier(self) -> "PredictedMove":
        if self.confidence_tier is None:
            if self.probability >= 0.60:
                self.confidence_tier = "high"
            elif self.probability >= 0.30:
                self.confidence_tier = "medium"
            else:
                self.confidence_tier = "low"
        return self

class IncidentEpisode(BaseModel):
    episode_id: UUID
    signal: ObservedSignal
    predictions: List[PredictedMove]
    confirmed_technique_id: Optional[str] = None
    outcome_confirmed: Optional[bool] = None
    created_at: datetime
    closed_at: Optional[datetime] = None

class SplunkContext(BaseModel):
    host: str
    query_window_minutes: int
    process_events: List[Dict[str, Any]]
    auth_events: List[Dict[str, Any]]
    network_events: List[Dict[str, Any]]
    host_summary: List[Dict[str, Any]]
    asset_vulnerability_score: Optional[float] = None
    asset_criticality: Optional[str] = None
    asset_owner: Optional[str] = None
    raw_results: Dict[str, Any]

    @property
    def total_events(self) -> int:
        return len(self.process_events) + len(self.auth_events) + len(self.network_events)

    @property
    def has_data(self) -> bool:
        return self.total_events > 0

class MCPToolResult(BaseModel):
    tool_name: str
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: float
    rows_returned: int

    @property
    def failed(self) -> bool:
        return not self.success

class DefenderBrief(BaseModel):
    brief_id: UUID
    signal_summary: str
    tactic_classification: str
    tactic_id: str
    ranked_predictions: List[PredictedMove]
    top_prediction: Optional[PredictedMove] = None
    context_summary: str
    splunk_context: Optional[SplunkContext] = None
    generated_at: datetime

    @property
    def prediction_count(self) -> int:
        return len(self.ranked_predictions)

    @property
    def top_probability(self) -> float:
        if self.top_prediction:
            return self.top_prediction.probability
        elif self.ranked_predictions:
            return max(p.probability for p in self.ranked_predictions)
        return 0.0
