'use strict';
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
class Element {
  constructor() { this.children=[]; this.textContent=''; this.value=''; this.hidden=false; this.dataset={}; this.style={setProperty(){}}; this.listeners={}; this.classList={toggle(){},add(){},remove(){}}; }
  setAttribute(k,v){this[k]=String(v);} append(...c){this.children.push(...c);} replaceChildren(...c){this.children=c;}
  addEventListener(name,fn){this.listeners[name]=fn;} focus(){} matches(){return false;}
  set innerHTML(_){throw Error('Unsafe markup');}
}
const elements=new Map(), events=new Map(), spoken=[], requests=[];
const document={hidden:false,activeElement:null,getElementById(id){if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},createElement(){return new Element();},addEventListener(name,fn){if(!events.has(name))events.set(name,[]);events.get(name).push(fn);}};
const original=[{id:0,label:'Finish window',group:'ideas',excerpt:'Speech pauses',path:'ideas/Finish window.md'},{id:1,label:'Other',group:'ideas',excerpt:'Other note',path:'ideas/Other.md'}];
const captured={id:2,label:'the-finish-window-should-be-900',group:'captures',excerpt:'the finish window should be 900 milliseconds',path:'captures/fixture.md'};
const payload={answer:'Filed and indexed, sir; this one is committed to more than conversation.',index:2,node:captured,nodes:[2],related:0,links:[{source:0,target:2}],graph:{nodes:[...original,captured],links:[{source:0,target:2}]},receipt:{id:'fixture-receipt',status:'completed'}};
let fail=false;
const context={console,document,URLSearchParams,location:{search:''},GALAXY_PERSONA:{greeting:'Hello, sir.'},crypto:require('node:crypto').webcrypto,
  Set,Map,Math,JSON,Number,String,Array,Object,Promise,Error,AbortController,setTimeout,clearTimeout,Date,
  requestAnimationFrame(){return 1;},ResizeObserver:class{observe(){}},matchMedia(){return {matches:true,addEventListener(){}};},innerWidth:1024,innerHeight:768,
  SpeechSynthesisUtterance:class{constructor(text){this.text=text;}},speechSynthesis:{getVoices(){return [{lang:'en-GB'}];},cancel(){},speak(u){spoken.push(u.text);u.onstart?.();}},
  fetch:async(url,options)=>{requests.push({url,options});if(url==='/chat/stream')return {ok:false,headers:{get:()=>'application/json'}};if(url==='/remember') {if(fail)return {ok:false,json:async()=>({answer:'I could not save and index that note; no successful capture receipt was issued.',error:{code:'CAPTURE_FAILED'},nodes:[]})};return {ok:true,json:async()=>payload};}return {ok:true,json:async()=>({answer:'900 milliseconds [2].',nodes:[2]})};}
};
context.window=context;vm.createContext(context);
vm.runInContext('const GRAPH='+JSON.stringify({nodes:original,links:[]})+';'+fs.readFileSync(root+'/viewer/voice.js','utf8')+fs.readFileSync(root+'/viewer/app.js','utf8'),context);
(async()=>{
 const g=context.galaxy;
 assert.equal(typeof g.addNote,'function','one addNote function must own birth/link/pulse/fly');
 for(const fn of events.get('click'))fn({isTrusted:true});spoken.length=0;
 g.nodes[0].x=25;g.nodes[0].y=40;g.nodes[0].z=-10;
 g.nodes[0].fx=25;g.nodes[0].fy=40;g.nodes[0].fz=-10;
 const save=g.askQuestion('remember that the finish window should be 900 milliseconds');
 const ask=g.askQuestion('What should the finish window be?');
 await Promise.all([save,ask]);
 const probes=requests.filter(r=>r.url==='/voice/status');
 assert.ok(probes.every(r=>!r.options||!r.options.method||r.options.method==='GET'),'the transcriber probe must be a read-only GET');
 const calls=requests.filter(r=>r.url!=='/voice/status');
 assert.deepEqual(calls.map(r=>r.url),['/remember','/chat/stream','/chat']);
 assert.equal(JSON.parse(calls[0].options.body).text,'the finish window should be 900 milliseconds');
 assert.equal(g.nodes.length,3);assert.equal(g.nodes[2].id,2);assert.equal(g.selectedId,2);
 assert.deepEqual([g.nodes[2].x,g.nodes[2].y,g.nodes[2].z],[25,40,-10]);
 assert.equal(g.nodes[0].fx,25,'a birth must not unpin an existing dragged node');
 assert.deepEqual(Array.from(g.neighbourIds),[0]);assert.equal(g.searchNotes('finish-window-should').length,1);
 assert.equal(elements.get('node-count').textContent,'3');
 assert.ok(spoken.some(s=>s.startsWith('Filed and indexed')));
 assert.equal(g.sourceIds[0],2,'the immediate answer can highlight the new source');
 await g.addNote(payload);assert.equal(g.nodes.length,3,'an idempotent response never duplicates a star');
 fail=true;spoken.length=0;
 await g.askQuestion('remember that a failing capture must announce its failure');
 assert.equal(g.nodes.length,3);
 assert.ok(spoken.some(s=>s.includes('could not save and index')),'capture failures must be spoken, not just logged');
 assert.equal(requests.at(-1).url,'/remember');
 console.log('Capture UI: typed route, queue, live index, same-position birth, neighbour links, duplicate safety and spoken failure passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
