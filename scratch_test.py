import asyncio
from agent.llm_client import LLMClient
from agent.schemas import ObservedSignal, SplunkContext, PredictedMove
from datetime import datetime

async def test():
    client = LLMClient()
    print(f'Provider: {client.provider}')
    signal = ObservedSignal(
        signal_id='sig-001',
        timestamp=datetime.utcnow().isoformat(),
        source_ip='10.0.0.1',
        splunk_index='main',
        additional_context={},
        host='BSTOLL-L',
        raw_event='rundll32.exe accessed lsass.exe memory GrantedAccess 0x1010',
        event_type='credential_access_attempt',
        severity='high'
    )
    context = SplunkContext(
        host='BSTOLL-L', 
        query_window_minutes=30,
        process_events=[],
        auth_events=[],
        network_events=[],
        host_summary=[],
        raw_results={}
    )
    moves = [
        PredictedMove(
            technique_id='T1069.001',
            technique_name='Local Groups',
            tactic='Discovery',
            probability=0.224,
            reasoning='original reasoning',
            prerequisite_met=True,
            defender_action='check local groups',
            splunk_hunting_query='index=main'
        ),
        PredictedMove(
            technique_id='T1021.006',
            technique_name='Windows Remote Management',
            tactic='Lateral Movement',
            probability=0.179,
            reasoning='original reasoning',
            prerequisite_met=True,
            defender_action='check winrm',
            splunk_hunting_query='index=main'
        ),
    ]
    scored = await client.score_moves(signal, context, moves)
    for m in scored:
        print(f'{m.technique_id} p={m.probability:.3f} - {m.reasoning[:80]}')
    await client.close()

asyncio.run(test())
