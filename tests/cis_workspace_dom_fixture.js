/* Small DOM fixture for actual endpoint refresh/render/action callbacks. */
class Node {
  constructor(tag='div') {this.tag=tag;this.children=[];this.dataset={};this.attributes={};this.listeners={};this.style={};this._text='';this.open=false;this.value='';this.disabled=false;}
  get textContent(){return this._text+this.children.map(n=>n.textContent).join('');}
  set textContent(value){this.textWrites=(this.textWrites||0)+1;this.replaceChildren();this._text=String(value);}
  append(...nodes){for(const n of nodes){if(n.parentElement){const children=n.parentElement.children;children.splice(children.indexOf(n),1);}n.parentElement=this;this.children.push(n);}}
  replaceChildren(...nodes){for(const n of this.children)n.parentElement=null;this.children=[];this._text='';this.append(...nodes);}
  setAttribute(name,value){this.attributes[name]=String(value);}
  getAttribute(name){return this.attributes[name]??null;}
  addEventListener(name,fn){this.listeners[name]=fn;}
  async emit(name,event={}){if(this.listeners[name])return this.listeners[name](event);}
  contains(node){return this===node||this.children.some(n=>n.contains(node));}
  focus(){document.activeElement=this;}
  remove(){if(this.parentElement){const rows=this.parentElement.children;rows.splice(rows.indexOf(this),1);this.parentElement=null;}}
  click(){return this.emit('click');}
  querySelectorAll(selector){return this.children.flatMap(n=>[...(matches(n,selector)?[n]:[]),...n.querySelectorAll(selector)]);}
  querySelector(selector){return this.querySelectorAll(selector)[0]||null;}
}
function matches(n,selector){
 const cls=selector.match(/\.([\w-]+)/);if(cls&&!String(n.className||'').split(' ').includes(cls[1]))return false;
 if(selector.includes('[open]')&&!n.open)return false;
 const attr=selector.match(/\[data-([a-z-]+)(?:="([^"]*)")?\]/);
 if(attr){const key=attr[1].replace(/-([a-z])/g,(_,c)=>c.toUpperCase());if(!Object.hasOwn(n.dataset,key)||(attr[2]!==undefined&&String(n.dataset[key])!==attr[2]))return false;}
 if(selector==="[type='submit']")return n.type==='submit';
 return Boolean(cls||attr||selector==="[type='submit']");
}
const ids=new Map();
const document={activeElement:null,body:new Node('body'),getElementById(id){if(!ids.has(id))ids.set(id,new Node());return ids.get(id);},createElement:tag=>new Node(tag),createTextNode:value=>{const n=new Node('#text');n.textContent=value;return n;}};
const form=document.getElementById('cis-profile-form'),submit=new Node('button');submit.type='submit';form.append(submit);
form.elements={profile_file:{files:[]},name:{value:'Typed profile'},version:{value:'2.0'},platform:{value:'macos'},description:{value:'Typed notes'}};form.reset=()=>{form.resetCalled=true;};
let orgId='1',role='admin';
const cisWorkspaceRead={bodies:null,sequence:0,loading:false,error:null,invalidated:false,mutationBusy:false,controller:null};
const text=(n,value)=>{if(n)n.textContent=value;},dateLabel=String;
const appendEmpty=(host,value)=>{const n=new Node();n.textContent=value;host.append(n);};
const makeAuditMetric=(label,value)=>{const n=new Node();n.textContent=label+' '+value;return n;};
function fixtures(){return [
 {organization_id:1,observed_at:'2026-10-09T02:00:00Z',key_configured:true,key_hint:'test',can_manage:true,device_count:1,devices_truncated:false,
  assessment_counts:{current:1,stale:0,unknown:0,missing:0},devices:[{id:1,name:'Endpoint fixture',platform:'macos',os_version:'26.6',last_seen_at:'2026-10-09T01:00:00Z',client_state:'online',last_client_heartbeat_at:'2026-10-09T02:00:00Z',assessment_state:'current',last_collected_at:'2026-10-09T01:00:00Z',latest_assessment_summary:{total:4,pass:1,fail:1,manual:2,error:0,score:25}}]},
 {organization_id:1,profiles:['level-1','level-2'].map((slug,i)=>({id:i+1,slug,name:slug,version:'1.0',platform:'macos',check_count:4,checksum:'fixture',download_url:'/api/cis/profiles/'+(i+1)+'/download'}))},
 {organization_id:1,reports:[report(2)]},
 {organization_id:1,changes:[{id:1,report_id:2,device_name:'Endpoint fixture',check_id:'one',previous_status:'pass',current_status:'fail',detected_at:'2026-10-09T01:00:00Z'}]}
 ];}
function report(id){return {id,device_name:'Endpoint fixture',platform:'macos',os_version:'26.6',profile_slug:'level-2',profile_version:'1.0',collected_at:'2026-10-09T01:00:00Z',summary:{total:4,pass:1,fail:1,manual:2,error:0,score:25}};}
let bodies=fixtures(),readFailure=false,calls=[];
const endpoints=['status','profiles','reports','changes'];
function normalFetch(path,options){calls.push({path,options});
 if(path.startsWith('/api/cis/reports/'))return Promise.resolve({ok:true,json:async()=>({results:[{id:'one',description:'Saved literal evidence',status:'fail',category:'macos'}]})});
 const index=endpoints.indexOf(path.split('/').at(-1));assert.ok(index>=0);
 if(readFailure&&index===2)return Promise.reject(new Error('Read connection unavailable'));
 return Promise.resolve({ok:true,json:async()=>structuredClone(bodies[index])});
}
global.fetch=normalFetch;
const timers=new Map();let timerId=0;
const window={setTimeout(fn){timers.set(++timerId,fn);return timerId;},clearTimeout(id){timers.delete(id);}};
let mutations=[];
let postJson=async(path,body)=>{mutations.push({path,body});return {installed_count:2,domain:'fixture.example',report_endpoint:'https://fixture.example/api/cis/report',profiles_endpoint:'https://fixture.example/api/cis/client/profiles',api_key:'fixture-only',rotated:true};};
const requestJson=async(path,method)=>{mutations.push({path,method});return {};};
