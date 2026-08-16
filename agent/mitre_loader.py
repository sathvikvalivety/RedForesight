import json
import re
from typing import List, Dict, Any

from agent.schemas import MitreTechnique

TACTIC_MAP = {
    "credential-access": ("Credential Access", "TA0006"),
    "lateral-movement": ("Lateral Movement", "TA0008"),
    "initial-access": ("Initial Access", "TA0001"),
    "execution": ("Execution", "TA0002"),
    "persistence": ("Persistence", "TA0003"),
    "privilege-escalation": ("Privilege Escalation", "TA0004"),
    "defense-evasion": ("Defense Evasion", "TA0005"),
    "discovery": ("Discovery", "TA0007"),
    "collection": ("Collection", "TA0009"),
    "exfiltration": ("Exfiltration", "TA0010"),
    "command-and-control": ("Command and Control", "TA0011"),
    "impact": ("Impact", "TA0040"),
    "reconnaissance": ("Reconnaissance", "TA0043"),
    "resource-development": ("Resource Development", "TA0042"),
    "stealth": ("Defense Evasion", "TA0005"),
    "defense-impairment": ("Defense Evasion", "TA0005")
}

TECHNIQUE_ID_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")

def load_bundle(filepath: str) -> List[Dict[str, Any]]:
    with open(filepath, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    return bundle.get("objects", [])

def extract_techniques(objects: List[Dict[str, Any]]) -> List[MitreTechnique]:
    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue

        name = obj.get("name", "").strip()
        if not name:
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                if ext_id.startswith("T") and TECHNIQUE_ID_REGEX.match(ext_id):
                    technique_id = ext_id
                    break
        
        if not technique_id:
            continue

        description = obj.get("description", "")
        detection = obj.get("x_mitre_detection", "")
        platforms = obj.get("x_mitre_platforms", [])
        sub_techniques = obj.get("x_mitre_subtechniques", [])

        # Default tactic
        tactic = "Unknown"
        tactic_id = "TA0000"

        # Get first tactic if available
        kill_chain_phases = obj.get("kill_chain_phases", [])
        if kill_chain_phases:
            phase_name = kill_chain_phases[0].get("phase_name", "")
            if phase_name in TACTIC_MAP:
                tactic, tactic_id = TACTIC_MAP[phase_name]
            else:
                tactic = phase_name.replace("-", " ").title()
                tactic_id = "TA0000"
        
        procedure_examples = [description[:500]] if description else []

        try:
            tech = MitreTechnique(
                technique_id=technique_id,
                name=name,
                tactic=tactic,
                tactic_id=tactic_id,
                description=description,
                detection=detection,
                platforms=platforms,
                procedure_examples=procedure_examples,
                sub_techniques=sub_techniques
            )
            techniques.append(tech)
        except Exception as e:
            print(f"Failed to parse technique {technique_id}: {e}")
            
    return techniques

def load_all_techniques(filepath: str) -> List[MitreTechnique]:
    objects = load_bundle(filepath)
    return extract_techniques(objects)
