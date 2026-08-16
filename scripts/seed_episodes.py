import asyncio
import sys
import os
from uuid import uuid4
from datetime import datetime, timezone

# Add project root to PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.memory import AgentMemory
from agent.schemas import ObservedSignal, IncidentEpisode, PredictedMove

async def seed():
    memory = AgentMemory()
    print("Seeding episodic memory with synthetic incidents...")
    
    # 1. Credential Access (LSASS) -> Lateral Movement (WinRM)
    for _ in range(5):
        signal = ObservedSignal(
            signal_id=str(uuid4()),
            timestamp=str(datetime.now(timezone.utc)),
            host="WIN-SERVER-01",
            source_ip="10.0.0.5",
            raw_event="lsass.exe memory dump accessed by unknown process",
            event_type="credential_access",
            severity="high",
            splunk_index="botsv3",
            additional_context={}
        )
        moves = [
            PredictedMove(
                technique_id="T1021.006",
                technique_name="Windows Remote Management",
                tactic="Lateral Movement",
                probability=0.8,
                reasoning="Historical data shows WinRM is used after LSASS dumps",
                confidence_tier="high",
                prerequisite_met=True,
                defender_action="Block port 5985",
                splunk_hunting_query="index=main EventCode=4624 LogonType=3"
            )
        ]
        ep = IncidentEpisode(
            episode_id=uuid4(),
            signal=signal,
            predictions=moves,
            outcome_confirmed=True,
            confirmed_technique_id="T1021.006",
            created_at=datetime.now(timezone.utc)
        )
        await memory.store_episode(ep)

    # 2. Phishing -> PowerShell Execution
    for _ in range(5):
        signal = ObservedSignal(
            signal_id=str(uuid4()),
            timestamp=str(datetime.now(timezone.utc)),
            host="WIN-DESKTOP-05",
            source_ip="192.168.1.10",
            raw_event="Email attachment invoice.doc opened with macros enabled",
            event_type="initial_access",
            severity="medium",
            splunk_index="botsv3",
            additional_context={}
        )
        moves = [
            PredictedMove(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="Execution",
                probability=0.9,
                reasoning="Macros frequently drop PowerShell payloads",
                confidence_tier="high",
                prerequisite_met=True,
                defender_action="Enable Script Block Logging",
                splunk_hunting_query="index=main EventCode=4104"
            )
        ]
        ep = IncidentEpisode(
            episode_id=uuid4(),
            signal=signal,
            predictions=moves,
            outcome_confirmed=True,
            confirmed_technique_id="T1059.001",
            created_at=datetime.now(timezone.utc)
        )
        await memory.store_episode(ep)

    # 3. Discovery -> Privilege Escalation
    for _ in range(5):
        signal = ObservedSignal(
            signal_id=str(uuid4()),
            timestamp=str(datetime.now(timezone.utc)),
            host="WIN-DESKTOP-02",
            source_ip="192.168.1.15",
            raw_event="net user /domain executed by non-admin user",
            event_type="discovery",
            severity="low",
            splunk_index="botsv3",
            additional_context={}
        )
        moves = [
            PredictedMove(
                technique_id="T1548.002",
                technique_name="Bypass User Account Control",
                tactic="Privilege Escalation",
                probability=0.7,
                reasoning="Discovery often precedes attempts to escalate privileges",
                confidence_tier="medium",
                prerequisite_met=True,
                defender_action="Monitor UAC bypass techniques",
                splunk_hunting_query="index=main EventCode=4688 UAC"
            )
        ]
        ep = IncidentEpisode(
            episode_id=uuid4(),
            signal=signal,
            predictions=moves,
            outcome_confirmed=True,
            confirmed_technique_id="T1548.002",
            created_at=datetime.now(timezone.utc)
        )
        await memory.store_episode(ep)

    print("Successfully seeded 15 episodes into ChromaDB.")

if __name__ == "__main__":
    asyncio.run(seed())
