"""No-build viewer contract. Run: python -m unittest discover -s tests -p test_viewer_contract.py -v."""
import json
import re
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path

from tests.node_support import node_binary

ROOT = Path(__file__).resolve().parents[1]

class Assets(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.scripts = []
        self.ids = set()
        self.feed(html)
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])

class ViewerContract(unittest.TestCase):
    def test_no_build_entrypoint_and_pinned_dependencies(self):
        for filename in ("index.html", "style.css", "app.js"):
            self.assertTrue((ROOT / "viewer" / filename).is_file(), f"Missing viewer/{filename}")
        html = (ROOT / "viewer/index.html").read_text()
        assets = Assets(html)
        # The viewer is offline-first: every library is vendored under
        # viewer/vendor/ with an exact-version manifest (audit fix P3), so no
        # remote CDN script may be referenced at all.
        remote = [src for src in assets.scripts if src.startswith(("https:", "http:"))]
        self.assertEqual(remote, [], "The viewer must not depend on remote CDNs")
        manifest = json.loads((ROOT / "viewer/vendor/vendor.manifest.json").read_text())
        vendored = [src for src in assets.scripts if src.startswith("vendor/")]
        self.assertEqual(
            {Path(src).name for src in vendored},
            {Path(asset["target"]).name for asset in manifest["assets"]},
            "Every manifest asset must be referenced by the viewer")
        for asset in manifest["assets"]:
            target = ROOT / asset["target"]
            self.assertTrue(target.is_file(), f"Missing vendored asset: {asset['target']}")
            self.assertRegex(asset["url"], r"@\d+\.\d+\.\d+/", "Vendored libraries must be exact-version pinned")
            self.assertRegex(
                html,
                rf'src="vendor/{Path(asset["target"]).name}"\s+'
                rf'integrity="{re.escape(asset["sri"])}"\s+crossorigin="anonymous"',
                f"{asset['target']} must carry its pinned integrity hash from the manifest")
        for src in vendored:
            self.assertRegex(
                html, rf'src="{re.escape(src)}"\s+integrity="sha384-[A-Za-z0-9+/=]+"\s+crossorigin="anonymous"',
                "Vendored libraries must carry a pinned SHA-384 integrity hash")
        self.assertIn("graph-data.js", assets.scripts)
        self.assertIn("app.js", assets.scripts)
        self.assertIn("studio.js", assets.scripts)
        self.assertIn("capabilities.js", assets.scripts)
        self.assertEqual(assets.scripts[-1], "capabilities.js")
        self.assertIn('href="style.css"', html)
        self.assertIn('href="studio.css"', html)
        self.assertIn('href="capabilities.css"', html)

    def test_the_graph_stops_rendering_when_nobody_touches_it(self):
        # An open, unfocused window kept the 3D loop running and spun the fan on an
        # i3. The loop now pauses on input idleness, which is the only signal that
        # works in Electron (hasFocus() stays true behind another window).
        source = (ROOT / 'viewer/app.js').read_text(encoding='utf-8')
        self.assertIn('GRAPH_IDLE_PAUSE_MS', source)
        self.assertIn('pauseAnimation', source)
        self.assertIn('resumeAnimation', source)
        self.assertIn("'pointermove', 'keydown', 'wheel'", source,
                      'any real interaction must resume the loop')
        self.assertIn('idle >= GRAPH_IDLE_PAUSE_MS', source)
        self.assertNotIn('!document.hasFocus()', source,
                         'hasFocus() is not a usable idle signal inside Electron')

    def test_agent_tiles_are_a_real_surface_not_a_dead_switch(self):
        html = (ROOT / 'viewer/index.html').read_text(encoding='utf-8')
        assets = Assets(html)
        source = (ROOT / 'viewer/agents.js').read_text(encoding='utf-8')
        self.assertIn('agents.js', assets.scripts)
        self.assertEqual(assets.scripts[-1], 'capabilities.js',
                         'agents.js must load before the capability map keeps the last slot')
        for required in ('agent-list', 'agents-refresh', 'settings-group'):
            self.assertIn(f'id="{required}"', html)
        # Settings are collapsed into one group instead of six loose sections.
        self.assertIn('<details class="settings-group"', html)
        # Every server value is rendered as text, never as markup (the dot form is
        # what would actually touch the property; the comment may name it).
        self.assertNotIn('.innerHTML', source)
        # Both consent routes exist: an explicit click and a spoken phrase.
        self.assertIn("'/agents/consent'", source)
        self.assertIn('MediaRecorder', source)
        self.assertIn("'/agents/run'", source)
        # A control the CLI does not have must be shown as unsupported, not wired.
        self.assertIn('niewspierane', source)

    def test_wake_word_has_opt_in_control_and_loads_before_app(self):
        assets = Assets((ROOT / 'viewer/index.html').read_text())
        self.assertIn('wake-toggle', assets.ids)
        self.assertIn('wake.js', assets.scripts)
        self.assertLess(assets.scripts.index('wake.js'), assets.scripts.index('app.js'))

    def test_selection_search_safe_text_and_same_origin_chat_without_webgl(self):
        node = node_binary()
        if node is None:
            self.skipTest("Node is used only as a test runner; set JARVIS_NODE or install Node")
        app = (ROOT / "viewer/app.js").read_text()
        harness = r'''
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(tag='div') { this.tagName=tag; this.children=[]; this.textContent=''; this.value=''; this.hidden=false; this.dataset={}; this.style={setProperty(){}}; this.listeners={}; this.classList={toggle(){},add(){},remove(){}}; }
  setAttribute(k,v) { this[k]=String(v); }
  append(...children) { this.children.push(...children); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children=children; }
  addEventListener(name,fn) { this.listeners[name]=fn; }
  focus() { this.focused=true; }
  matches(){return false;}
  get innerHTML(){return '';}
  set innerHTML(value){throw Error('Unsafe HTML assignment');}
}
const elements=new Map();
const document={getElementById(id){if(!elements.has(id)) elements.set(id,new Element());return elements.get(id);},createElement(tag){return new Element(tag);},addEventListener(){},activeElement:null};
let request;
const context={console,document,Set,Map,Math,JSON,Number,String,Array,Object,Promise,Error,AbortController,setTimeout,clearTimeout,requestAnimationFrame(){return 1;},cancelAnimationFrame(){},ResizeObserver:class{observe(){}},matchMedia(){return {matches:true,addEventListener(){}};},innerWidth:1024,innerHeight:768,addEventListener(){},fetch:async (url,options)=>{request={url,options};return {ok:true,json:async()=>({answer:'<img src=x onerror=evil()> a grounded answer',nodes:[1,2,999,1]})};}};
context.window=context;
vm.createContext(context);
vm.runInContext('const GRAPH={nodes:[{id:0,label:"<b>Atlas</b>",group:"Ideas",excerpt:"<script>evil()</script>",path:"Ideas/Atlas.md"},{id:1,label:"Linked note",group:"Ideas",excerpt:"An excerpt",path:"Ideas/Linked.md"},{id:2,label:"Other",group:"Work",excerpt:"Separate",path:"Work/Other.md"}],links:[{source:0,target:1}]};'+APP,context);
(async()=>{
  const g=context.galaxy;
  assert.ok(g,'window.galaxy must expose a testable runtime');
  assert.equal(g.ready,false,'No WebGL library must degrade to the searchable index');
  assert.ok(elements.get('notice-title').textContent.includes('3D'));
  g.selectNode(0);
  assert.equal(g.selectedId,0);
  assert.deepEqual(Array.from(g.neighbourIds),[1]);
  assert.equal(elements.get('note-title').textContent,'<b>Atlas</b>');
  assert.equal(elements.get('note-excerpt').textContent,'<script>evil()</script>');
  assert.equal(elements.get('note-panel').hidden,false);
  assert.deepEqual(Array.from(g.searchNotes('LINKED'),n=>n.id),[1]);
  g.setGroup('Work');
  assert.deepEqual(Array.from(g.searchNotes(''),n=>n.id),[2]);
  g.setGroup(null);
  await g.askQuestion('What connects these ideas?');
  assert.equal(request.url,'/chat');
  assert.equal(request.options.method,'POST');
  assert.equal(request.options.credentials,'same-origin');
  assert.equal(JSON.parse(request.options.body).question,'What connects these ideas?');
  assert.equal(elements.get('chat-answer').textContent,'<img src=x onerror=evil()> a grounded answer');
  assert.deepEqual(Array.from(g.sourceIds),[1,2]);
  assert.equal(elements.get('source-list').children.length,2);
  context.fetch=async()=>({ok:false,json:async()=>({answer:'Service unavailable. Please try again.',nodes:[],error:{code:'UNAVAILABLE',message:'Service unavailable. Please try again.'}})});
  await g.askQuestion('Try again');
  assert.equal(elements.get('chat-answer').textContent,'Service unavailable. Please try again.');
  assert.equal(g.sourceIds.length,0);
  context.fetch=async()=>{throw new Error('offline');};
  await g.askQuestion('Offline?');
  assert.match(elements.get('chat-answer').textContent,/connect|reach|offline/i);
  assert.equal(elements.get('ask-button').disabled,false);
  g.resetView();
  assert.equal(g.selectedId,null);
  assert.equal(elements.get('note-panel').hidden,true);
  console.log('Selection, adjacency, literal text, collection filter, success/error/offline chat: passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result = subprocess.run([node, "-e", "const APP=" + json.dumps(app) + ";\n" + harness],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_accessible_controls_reduced_motion_and_no_html_injection(self):
        html = (ROOT / "viewer/index.html").read_text()
        css = (ROOT / "viewer/style.css").read_text()
        app = (ROOT / "viewer/app.js").read_text()
        ids = Assets(html).ids
        for name in ("note-search", "note-results", "rotate-toggle", "reset-view", "note-panel", "chat-form", "question", "chat-answer", "source-list", "graph-notice"):
            self.assertIn(name, ids)
        self.assertIn("prefers-reduced-motion", css)
        self.assertIn("prefers-reduced-motion", app)
        self.assertNotRegex(app, r"\.(?:innerHTML|outerHTML)\s*=")
        self.assertNotIn("insertAdjacentHTML", app)
        self.assertIn(".nodeLabel(", app)
        self.assertIn("ResizeObserver", app)
        self.assertNotRegex(app, r'\.graphData\(\{\s*nodes\s*,\s*links\s*\}\)', 'The ticking physics engine must not share mutable public arrays with live births')

if __name__ == "__main__":
    unittest.main()
