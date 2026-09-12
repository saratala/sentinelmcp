import sys, json
sys.path.insert(0, '.')
from app.detection.patterns import detect_injection, detect_dangerous_args, detect_pii, detect_encoded_injection
from app.gateway.output_layer import _scan_output

dh = [json.loads(l) for l in open('benchmarks/data/attacker_cases_dh.jsonl').read().splitlines() if l.strip()]
ds = [json.loads(l) for l in open('benchmarks/data/attacker_cases_ds.jsonl').read().splitlines() if l.strip()]

detected = 0
total = len(dh) + len(ds)

for cat, cases in [('DH', dh), ('DS', ds)]:
    for i, case in enumerate(cases):
        instr = case.get('Attacker Instruction', '')
        tools = str(case.get('Attacker Tools', ''))
        text = instr + ' ' + tools
        hit = detect_injection(text) or detect_encoded_injection(text) or detect_dangerous_args(text) or _scan_output(instr) or detect_pii(instr)
        if hit:
            detected += 1
            lyr = hit[0].threat_type if isinstance(hit, list) and hit else (hit.get('pattern', '?') if isinstance(hit, dict) else '?')
            print(f'V {cat}-{i:02d} [{lyr}]')
        else:
            print(f'X {cat}-{i:02d}: {instr[:65]}')

print(f'\nDetection: {detected}/{total} = {detected/total*100:.1f}%')
