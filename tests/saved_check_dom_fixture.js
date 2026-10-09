/* Minimal DOM contract for executing the actual dashboard check callbacks. */
class Node {
  constructor(tag="div") {
    this.tag=tag;this.children=[];this.dataset={};this.attributes={};this.listeners={};this._text="";this._open=false;
    this.classes=new Set();this.classList={contains:n=>this.classes.has(n),toggle:(n,on)=>{if(on)this.classes.add(n);else this.classes.delete(n);}};
  }
  set textContent(value){this._text=String(value);this.children=[];}
  get textContent(){return this._text;}
  append(...nodes){nodes.forEach(n=>{n.parentElement=this;this.children.push(n);});}
  replaceChildren(...nodes){this._text="";this.children=[];this.append(...nodes);}
  setAttribute(name,value){this.attributes[name]=value;}
  addEventListener(name,fn){this.listeners[name]=fn;}
  contains(node){return this===node||this.children.some(n=>n.contains(node));}
  focus(){document.activeElement=this;}
  querySelectorAll(selector){return this.children.flatMap(n=>[...(matches(n,selector)?[n]:[]),...n.querySelectorAll(selector)]);}
  set open(value){if(this._open===Boolean(value))return;this._open=Boolean(value);queueMicrotask(()=>{if(this.listeners.toggle)this.listeners.toggle();});}
  get open(){return this._open;}
}
function matches(node,selector){
  const attrs=[...selector.matchAll(/\[data-([a-z-]+)(?:="([^"]*)")?\]/g)];
  return attrs.length>0&&attrs.every(m=>{const key=m[1].replace(/-([a-z])/g,(_,c)=>c.toUpperCase());return Object.hasOwn(node.dataset,key)&&(m[2]===undefined||node.dataset[key]===m[2]);});
}
const ids=new Map(),buttons=[];
const document={activeElement:null,createElement:tag=>new Node(tag),getElementById(id){if(!ids.has(id))ids.set(id,new Node());return ids.get(id);},
 querySelectorAll:selector=>buttons.filter(n=>matches(n,selector)),querySelector:selector=>buttons.find(n=>matches(n,selector))||null};
for(const type of ['dns','web','web-active','web-nikto']){
 const refresh=new Node('button');refresh.dataset.refreshCheck=type;buttons.push(refresh);
 for(const field of ['runs','changes']){
  const button=type==='web-nikto'?document.getElementById('older-nikto'):new Node('button');
  if(type==='web-active')button.dataset.loadOlderActive=field;
  else if(type!=='web-nikto'){button.dataset.loadOlderChecks=type;button.dataset.pageKind=field;}
  if(type==='web-nikto'&&field==='changes')continue;
  buttons.push(button);
 }
}
const orgId=1,role='admin',controlsEnabled=true;
const externalCheckHistory=Object.create(null),savedCheckHistories=Object.create(null),activeExposureHistory={runs:[],changes:[]},niktoHistory={runs:[],changes:[],busy:false};
const text=(node,value)=>{if(node)node.textContent=value;};
const dateLabel=String;
const appendEmpty=(host,value)=>{const n=new Node();n.textContent=value;host.append(n);};
function flatten(node){return node.textContent+' '+node.children.map(flatten).join(' ');}
function renderCheckHistory(type,body){const host=document.getElementById(type+'-priorities');host.replaceChildren();appendEmpty(host,'Saved run '+body.latest_snapshot_run_id);}
function renderActiveExposure(body){const host=document.getElementById('web-exposure-review');host.replaceChildren();appendEmpty(host,'Saved exposure '+body.latest_snapshot_run_id);}
function renderWebsiteAuditOutcome(id,label,run){text(document.getElementById(id),label+' '+(run?run.status:'unavailable'));}
function makeBody(type,runs,changes){return {check_type:type,domain:'example.org',
 runs:runs.map(id=>({id,status:'completed',completed_at:'2026-10-01T00:00:00Z',snapshot:{findings:[]}})),changes:changes.map(id=>({id})),
 runs_has_more:false,runs_next_before:null,changes_has_more:false,changes_next_before:null,
 latest_snapshot:{findings:[]},latest_snapshot_run:{id:runs[0]||1,status:'completed',completed_at:'2026-10-01T00:00:00Z'},latest_snapshot_run_id:runs[0]||1};}
