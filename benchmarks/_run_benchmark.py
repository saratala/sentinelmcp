import sys, json
sys.path.insert(0, '.')
from app.detection.patterns import detect_injection, detect_dangerous_args, detect_pii, detect_encoded_injection
from app.gateway.output_layer import _scan_output

dh = [json.loads(l) for l in open('benchmarks/data/attacker_cases_dh.jsonl').read().splitlines() if l.strip()]
ds = [json.loads(l) for l in open('benchmarks/data/attacker_cases_ds.jsonl').read().splitlines() if l.strip()]

det, total = 0, len(dh) + len(ds)
lines = []

for cat, cases in [('DH', dh), ('DS', ds)]:
    for i, case in enumerate(cases):
        instr = case.get('Attacker Instruction', '')
        tools = str(case.get('Attacker Tools', ''))
        text = instr + ' ' + tools
        hit = (detect_injection(text) or detect_encoded_injection(text) or
               detect_dangerous_args(text) or _scan_output(instr) or detect_pii(instr))
        if hit:
            det += 1
            lyr = hit[0].threat_type if isinstance(hit, list) and hit else (hit.get('pattern', '?') if isinstance(hit, dict) else '?')
            lines.append(f'V {cat}-{i:02d} [{case.get("Attack Type","?")}] -> {lyr}: {instr[:55]}')
        else:
            lines.append(f'X {cat}-{i:02d} [{case.get("Attack Type","?")}] -> MISSED: {instr[:55]}')

lines.append(f'\nDetection: {det}/{total} = {det/total*100:.1f}%')
out = '\n'.join(lines)
open('benchmarks/results/quick_score.txt', 'w').write(out)
print(out)
