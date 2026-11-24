"""Real HTTP + WebGL capture QA in an isolated vault; production notes untouched.

The follow-up uses the configured live model. Speech/recognition are event doubles
so no microphone is opened and no actual sound is emitted by automation.
"""
import json
import os
import shutil
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from playwright.sync_api import sync_playwright

import build
import server

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'artifacts'
OUT.mkdir(exist_ok=True)
DOUBLES = r"""
window.__voice = {spoken:[]};
Object.defineProperty(window,'speechSynthesis',{value:{getVoices:()=>[{lang:'en-GB'}],cancel(){},speak(u){__voice.spoken.push(u.text);u.onstart?.();}},configurable:true});
window.SpeechSynthesisUtterance=class{constructor(text){this.text=text;}};
window.webkitSpeechRecognition=class{constructor(){__voice.recognition=this;this.results=[];}start(){this.results=[];this.onstart?.();}abort(){this.onend?.();}emit(text){const i=this.results.length;this.results.push(Object.assign([{transcript:text}],{isFinal:true}));this.onresult({resultIndex:i,results:this.results});}};
"""
report = {}
with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temp:
    fixture = Path(temp)
    notes = fixture / 'notes'
    (notes / 'ideas').mkdir(parents=True)
    (notes / 'ideas/Speech.md').write_text('Speech recognition uses a finish window to buffer pauses. [[Window]]')
    (notes / 'ideas/Window.md').write_text('A finish window measures the pause at the end of a sentence. [[Speech]]')
    (fixture / 'viewer').mkdir()
    for name in ('index.html','style.css','voice.css','app.js','voice.js'):
        shutil.copy2(ROOT / 'viewer' / name, fixture / 'viewer' / name)
    build.write_graph(build.make_graph(notes), fixture / 'viewer/graph-data.js')
    httpd = server.create_server(root=fixture, notes_root=notes, port=0,
                                 state_root=fixture / 'state',
                                 enable_agent=False, enable_scheduler=False,
                                 enable_memory_capture=False)
    # Reuse private settings via the production reader; never copy or print a key.
    httpd.app.read_settings = server.Application(
        ROOT, state_root=fixture / 'settings-state').read_settings
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{httpd.server_port}/'
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=['--enable-unsafe-swiftshader','--use-angle=swiftshader'])
            context = browser.new_context(viewport={'width':1440,'height':900})
            context.add_init_script(DOUBLES)
            page = context.new_page()
            errors=[]
            page.on('pageerror',lambda error: errors.append(str(error)))
            page.goto(url,wait_until='networkidle',timeout=90000)
            page.locator('#graph canvas').wait_for(state='visible')
            assert page.evaluate('galaxy.ready && !!galaxy.voice')
            page.locator('#note-search').click()
            page.evaluate('window.__pageNonce=crypto.randomUUID()')
            nonce=page.evaluate('__pageNonce')
            before=page.evaluate('galaxy.nodes.length')
            page.locator('#question').fill('remember that the finish window should be 900 milliseconds')
            with page.expect_response(lambda response:response.url.endswith('/remember'),timeout=30000) as pending:
                page.locator('#ask-button').click()
            response=pending.value
            capture=response.json()
            assert response.status==201,capture
            index=capture['index']
            page.locator('#node-count').filter(has_text=str(before+1)).wait_for()
            page.wait_for_timeout(50)
            assert page.evaluate('galaxy.lastBirth?.pulseActive && galaxy.sprites.has(galaxy.lastBirth.id)')
            pulse=page.evaluate('''() => {const b=galaxy.lastBirth,n=galaxy.nodes[b.id],s=galaxy.sprites.get(b.id);return {birth:b,node:{x:n.x,y:n.y,z:n.z},scale:s.scale.x,color:s.material.color.getHexString(),sprites:galaxy.sprites.size,renderCalls:galaxy.graph.renderer().info.render.calls}}''')
            assert pulse['node']==pulse['birth']['position'],pulse
            assert pulse['birth']['related']==capture['related'],pulse
            assert pulse['color']=='ffffff' and pulse['scale']>=24,pulse
            page.screenshot(path=str(OUT/'capture-birth.png'))
            page.locator('#ask-button:not([disabled])').wait_for(state='visible',timeout=10000)
            assert page.evaluate('!galaxy.busy && galaxy.selectedId === galaxy.nodes.length-1')
            assert page.evaluate('__pageNonce')==nonce,'capture must not reload the page'
            assert page.evaluate('galaxy.nodes.length')==before+1
            assert page.locator('#node-count').inner_text()==str(before+1)
            assert page.evaluate('(label)=>galaxy.searchNotes(label).some(n=>n.id===galaxy.selectedId)',capture['node']['label'])
            assert page.evaluate('galaxy.neighbourIds.length')>0
            assert page.evaluate('__voice.spoken.at(-1)')==server.CAPTURE_SUCCESS_REPLY
            body=(notes/capture['node']['path']).read_text()
            assert 'the finish window should be 900 milliseconds' in body
            assert datetime.now().astimezone().date().isoformat() in body
            assert httpd.app.load_graph()['nodes'][index]['path']==capture['node']['path']
            page.wait_for_timeout(1400)
            page.screenshot(path=str(OUT/'capture-selected.png'))
            page.locator('#question').fill('How long should the finish window be?')
            with page.expect_response(lambda response:response.url.endswith('/chat'),timeout=195000) as pending:
                page.locator('#ask-button').click()
            reply=pending.value.json()
            assert pending.value.status==200,reply
            page.locator('#ask-button:not([disabled])').wait_for(state='visible',timeout=10000)
            assert '900' in reply['answer'] and index in reply['nodes'],reply
            assert page.evaluate('(index)=>galaxy.sourceIds.includes(index)',index)
            report['typed_capture']={'index':index,'filename':capture['node']['path'],'birth':pulse,'no_reload':True,'written_and_indexed':True,'confirmation':server.CAPTURE_SUCCESS_REPLY,'immediate_live_answer':reply}

            # Same command through native recognition event shape and FINISH_MS.
            page.locator('#mic-button').click()
            with page.expect_response(lambda response:response.url.endswith('/remember'),timeout=30000) as pending:
                page.evaluate("__voice.recognition.emit('remember that a voice capture uses exactly the same door')")
            voice_capture=pending.value.json()
            assert pending.value.status==201,voice_capture
            page.locator('#ask-button:not([disabled])').wait_for(state='visible',timeout=10000)
            assert page.evaluate('galaxy.selectedId')==voice_capture['index']
            assert (notes/voice_capture['node']['path']).is_file()
            report['voice_capture']={'same_endpoint':True,'index':voice_capture['index'],'file_exists':True}

            # Fail actual graph publication after the markdown write, not a fake HTTP reply.
            count_before_failure=len(httpd.app.load_graph()['nodes'])
            files_before=set((notes/'captures').glob('*.md'))
            with patch('server.os.replace',side_effect=OSError('synthetic disk failure')):
                page.locator('#question').fill('remember that a failed capture must never remain silent')
                with page.expect_response(lambda response:response.url.endswith('/remember'),timeout=30000) as pending:
                    page.locator('#ask-button').click()
                failure=pending.value.json()
                assert pending.value.status==500 and failure['error']['code']=='CAPTURE_FAILED',failure
                page.locator('#ask-button:not([disabled])').wait_for(state='visible',timeout=10000)
            assert page.evaluate('__voice.spoken.at(-1)')==server.CAPTURE_FAILURE_REPLY
            assert len(httpd.app.load_graph()['nodes'])==count_before_failure
            assert set((notes/'captures').glob('*.md'))==files_before
            assert page.evaluate('galaxy.nodes.length')==count_before_failure
            report['write_index_failure']={'error':failure['error'],'spoken':True,'file_rolled_back':True,'no_false_star':True}
            assert not errors,errors
            report['page_errors']=errors
            browser.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()
report['production_vault_untouched']=True
(OUT/'capture-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
print(json.dumps(report,ensure_ascii=False,indent=2))
