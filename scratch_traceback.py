import re
with open(r"C:\Users\dell9\.gemini\antigravity-ide\brain\12230c5a-5102-4eb0-aa59-43be4550e190\.system_generated\tasks\task-490.log", "r") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "The truth value of an array" in line:
        start = max(0, i - 15)
        end = min(len(lines), i + 15)
        for j in range(start, end):
            print(lines[j], end="")
        break
