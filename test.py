import json

with open("data/mitre_attack.json") as f:
    bundle = json.load(f)

print(f"STIX bundle loaded - {len(bundle['objects'])} objects")