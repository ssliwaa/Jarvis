"""Verify real persona replies and real allowlisted action receipts over HTTP."""
import json
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.request import HTTPCookieProcessor, Request, build_opener

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'artifacts/persona-verification.json'
QUESTIONS = [
    'Explain the 80/20 running rule without pretending I enjoy restraint.',
    'Why does Kino need ffmpeg on Linux? Spare me the release notes.',
    'Count my indexed notes, please.',
    'Clear our conversation history; discretion is part of your salary.',
    'What number am I thinking of right now?',
]
client = build_opener(HTTPCookieProcessor(CookieJar()))
results = []
for question in QUESTIONS + ['Please brew me a cup of tea.']:
    request = Request('http://127.0.0.1:4700/chat', data=json.dumps({'question': question}).encode(), headers={'Content-Type': 'application/json'})
    with client.open(request, timeout=195) as response:
        result = json.load(response)
        assert response.status == 200
    results.append({'question': question, 'response': result})
    print(json.dumps(results[-1], ensure_ascii=False), flush=True)
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=2))

with client.open('http://127.0.0.1:4700/graph-data.js') as response:
    graph = json.loads(response.read().decode().removeprefix('const GRAPH = ').strip().removesuffix(';'))
for row in results[:2]:
    assert row['response']['nodes'], row
    assert all(type(index) is int and 0 <= index < len(graph['nodes']) for index in row['response']['nodes'])
count, cleared, missing, unsupported = [row['response'] for row in results[2:]]
assert count['receipt']['status'] == 'completed' and count['receipt']['details']['count'] == len(graph['nodes'])
assert cleared['receipt']['status'] == 'completed' and cleared['receipt']['details']['history_cleared']
assert missing['nodes'] == [] and 'notes do not cover' in missing['answer']
assert unsupported['receipt']['status'] == 'unavailable' and unsupported['receipt']['details']['performed'] is False
print('Live persona, sources, real note count, history clear and honest refusals: passed')
