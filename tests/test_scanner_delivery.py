"""Upload observations, durable save intent, and normal scoped API flows."""
from datetime import timedelta
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4
from types import SimpleNamespace
import httpx
from sqlalchemy import create_engine, inspect, select
from concurrent.futures import ThreadPoolExecutor
import threading
from daedalus import server
from daedalus.agent import NmapUIBridge
from daedalus.models import Agent, AuditLog, ScanEvent, WorkspaceNotification
from daedalus.scanner_delivery import DeliveryJournal, needs_review, unknown_delivery, validated_delivery
try:
    from . import test_cis_pdf_flow as fixtures
except ImportError:
    import test_cis_pdf_flow as fixtures


def observed(pending=0, review=0, failed=False):
    return {'schema_version':1, 'state':'observed', 'pending_events':pending,
            'review_events':review, 'preservation_failed':failed, 'last_acknowledged_at':None}


class DeliveryContractTests(unittest.TestCase):
    def test_unknown_counts_are_distinct_from_a_measured_empty_queue(self):
        self.assertEqual(validated_delivery(unknown_delivery()), unknown_delivery())
        self.assertEqual(validated_delivery(unknown_delivery(True)), unknown_delivery(True))
        self.assertTrue(needs_review(unknown_delivery(True)))
        self.assertEqual(validated_delivery(observed()), observed())
        self.assertFalse(needs_review(observed()))
        self.assertTrue(needs_review(observed(review=1)))
        self.assertTrue(needs_review(observed(failed=True)))
        self.assertFalse(needs_review(observed(pending=4)))

    def test_bad_types_bounds_dates_and_extra_private_fields_are_rejected(self):
        for fields in ({'schema_version':True}, {'pending_events':True}, {'pending_events':10001}, {'review_events':-1},
                       {'preservation_failed':1}, {'last_acknowledged_at':'yesterday'}, {'last_acknowledged_at':'2026-10-08T12:00:00'},
                       {'last_acknowledged_at':{'private':'value'}}, {'payload':'private'}, {'state':[]}):
            with self.subTest(fields=fields): self.assertIsNone(validated_delivery({**observed(),**fields}))
        for fields in ({'pending_events':0}, {'preservation_failed':False}, {'preservation_failed':1}):
            self.assertIsNone(validated_delivery({**unknown_delivery(),**fields}))
        body={**observed(), 'last_acknowledged_at':'2026-10-08T12:00:00+00:00'}
        self.assertEqual(validated_delivery(body)['last_acknowledged_at'], '2026-10-08T12:00:00Z')
        result=validated_delivery(body);result['pending_events']=9;self.assertEqual(body['pending_events'],0)


class DeliveryBridgeTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='daedalus-delivery-')
        self.addCleanup(temporary.cleanup);self.root=Path(temporary.name)
        self.bridge=self.make_bridge()

    def make_bridge(self):
        bridge=NmapUIBridge({'agent_id':7,'server':'https://fixture.invalid','agent_token':'synthetic'},
                            'http://127.0.0.1:9000',spool_dir=self.root)
        self.addCleanup(bridge.http.close);return bridge

    def test_outage_restart_and_durable_ack_update_counts_without_changing_identity_or_time(self):
        identifier=str(uuid4());collected='2026-10-08T12:00:00+00:00'
        self.bridge._forward_event('scan_results',{'hosts':[]},client_event_id=identifier,occurred_at=collected)
        self.assertEqual(self.bridge._read_delivery(),observed(pending=1))
        self.bridge._request=Mock(side_effect=httpx.ConnectError('offline'));self.bridge._flush_events()
        restarted=self.make_bridge();self.assertEqual(restarted._read_delivery()['pending_events'],1)
        restarted._request=Mock(return_value=httpx.Response(202,json={'ok':True}));restarted._flush_events()
        self.assertEqual(restarted._read_delivery()['pending_events'],1)
        restarted.next_upload_at=0;restarted._request=Mock(return_value=httpx.Response(200,json={'ok':True,'event_id':42}));restarted._flush_events()
        delivered=restarted._request.call_args.kwargs['json']
        self.assertEqual(delivered['client_event_id'],identifier);self.assertEqual(delivered['occurred_at'],collected)
        result=restarted._read_delivery();self.assertEqual(result['pending_events'],0);self.assertIsNotNone(result['last_acknowledged_at'])
        again=self.make_bridge();self.assertEqual(again._read_delivery()['last_acknowledged_at'],result['last_acknowledged_at'])
        local=json.loads((self.root/'upload.status').read_text());self.assertIn('observed_at',local)
        self.assertNotIn(identifier,json.dumps(local));self.assertEqual((self.root/'upload.status').stat().st_mode&0o777,0o600)

    def test_failed_save_survives_restart_and_only_matching_replay_resolves_it(self):
        identifier=str(uuid4())
        with patch.object(Path,'open',side_effect=OSError('storage denied')):
            self.bridge._forward_event('scan_results',{'hosts':[]},client_event_id=identifier)
        result=self.bridge._read_delivery();self.assertTrue(result['preservation_failed']);self.assertEqual(result['pending_events'],0)
        restarted=self.make_bridge();self.assertTrue(restarted._read_delivery()['preservation_failed'])
        restarted._forward_event('scan_results',{})
        restarted._request=Mock(return_value=httpx.Response(200,json={'ok':True,'event_id':42}));restarted._flush_events()
        self.assertTrue(restarted._read_delivery()['preservation_failed'])
        restarted._forward_event('scan_results',{'hosts':[]},client_event_id=identifier)
        self.assertFalse(restarted._read_delivery()['preservation_failed'])
        self.assertEqual(restarted._read_delivery()['pending_events'],1)

    def test_save_intent_survives_process_interruption_until_that_event_is_acknowledged(self):
        identifier=str(uuid4());self.bridge.delivery_journal.begin(identifier)
        path=self.root/f'00000000000000000001-{identifier}.json'
        path.write_text(json.dumps({'client_event_id':identifier,'occurred_at':'2026-10-08T12:00:00Z','event_name':'scan_results','payload':[]}))
        restarted=self.make_bridge();self.assertTrue(restarted._read_delivery()['preservation_failed'])
        restarted._request=Mock(return_value=httpx.Response(200,json={'ok':True,'event_id':42}));restarted._flush_events()
        self.assertFalse(restarted._read_delivery()['preservation_failed'])

    def test_review_files_are_visible_and_other_events_keep_uploading(self):
        self.bridge._forward_event('scan_results',{});self.bridge._forward_event('scan_results',{})
        self.bridge._request=Mock(side_effect=[httpx.Response(413),httpx.Response(200,json={'ok':True,'event_id':42})]);self.bridge._flush_events()
        result=self.bridge._read_delivery();self.assertEqual(result['pending_events'],0);self.assertEqual(result['review_events'],1)
        (self.root/'interrupted.json.tmp').write_text('broken')
        self.assertEqual(self.bridge._read_delivery()['review_events'],2)
        self.assertTrue(needs_review(result))

    def test_corrupt_journal_and_failed_intent_write_cannot_report_a_clean_capture(self):
        (self.root/'delivery.journal').write_text('{broken')
        restarted=self.make_bridge();self.assertEqual(restarted._read_delivery(),unknown_delivery())
        restarted._forward_event('scan_results',{})
        self.assertEqual(restarted._read_delivery(),unknown_delivery(True))
        self.assertEqual(list(self.root.glob('*.json')),[])
        self.assertEqual((self.root/'delivery.journal').read_text(),'{broken')

    def test_journal_write_failure_blocks_capture_and_surfaces_known_failed_save(self):
        with patch('daedalus.scanner_delivery._atomic_private_json',side_effect=OSError('disk full')):
            self.bridge._forward_event('scan_results',{})
            self.assertEqual(self.bridge._read_delivery(),unknown_delivery(True))
        self.assertEqual(list(self.root.glob('*.json')),[])

    def test_symlink_non_regular_and_oversized_queues_are_unknown_without_following_targets(self):
        private=self.root/'private';private.write_text('private contents')
        link=self.root/'event.json';link.symlink_to(private)
        self.assertEqual(self.bridge._read_delivery(),unknown_delivery());self.assertEqual(private.read_text(),'private contents')
        link.unlink();link.mkdir();self.assertEqual(self.bridge._read_delivery(),unknown_delivery());link.rmdir()
        with patch('daedalus.scanner_delivery.MAX_ENTRIES',0):self.assertEqual(self.bridge._read_delivery(),unknown_delivery())
        with patch('daedalus.scanner_delivery.time.monotonic',side_effect=[0,1]):self.assertEqual(self.bridge._read_delivery(),unknown_delivery())

    def test_journal_overflow_is_latched_across_restart_and_unrelated_ack(self):
        with patch('daedalus.scanner_delivery.MAX_UNRESOLVED',1):
            self.bridge.delivery_journal.begin(str(uuid4()));self.bridge.delivery_journal.begin(str(uuid4()))
        restarted=self.make_bridge();restarted.delivery_journal.unresolved.clear();restarted.delivery_journal.acknowledged(str(uuid4()))
        self.assertTrue(restarted._read_delivery()['preservation_failed'])

    def test_unmeasurable_queue_keeps_known_unfinished_save_visible(self):
        self.bridge.delivery_journal.begin(str(uuid4()))
        with patch('daedalus.scanner_delivery.os.scandir',side_effect=OSError('unreadable')):
            self.assertEqual(self.bridge._read_delivery(),unknown_delivery(True))
        with patch('daedalus.scanner_delivery.MAX_ENTRIES',0):
            self.assertEqual(self.bridge._read_delivery(),unknown_delivery(True))
        (self.root/'event.json').symlink_to(self.root/'private')
        self.assertEqual(self.bridge._read_delivery(),unknown_delivery(True))


class DeliveryAPITests(unittest.TestCase):
    setUp=fixtures.CISReportPDFFlowTests.setUp
    tearDown=fixtures.CISReportPDFFlowTests.tearDown
    create_scanner=fixtures.CISReportPDFFlowTests.create_scanner

    def heartbeat(self,agent_id,value):
        body={'nmapui_ready':False,'nmapui_connected':False}
        if value is not None:body['upload_delivery']=value
        return self.client.post(f'/api/agents/{agent_id}/heartbeat',headers={'Authorization':'Bearer test-scanner-token'},json=body)

    def test_fresh_delivery_is_independent_of_engine_readiness_and_legacy_becomes_unknown(self):
        agent_id,_=self.create_scanner();self.assertEqual(self.heartbeat(agent_id,observed(pending=3)).status_code,200)
        row=next(a for a in self.client.get('/api/dashboard').json()['agents'] if a['id']==agent_id)
        self.assertFalse(row['nmapui_ready']);self.assertEqual(row['upload_delivery']['pending_events'],3)
        status=self.client.get(f'/api/agents/{agent_id}/client-status',headers={'Authorization':'Bearer test-scanner-token'})
        self.assertEqual(status.json()['upload_delivery'],row['upload_delivery']);self.assertEqual(status.headers['cache-control'],'no-store')
        self.heartbeat(agent_id,None);row=next(a for a in self.client.get('/api/dashboard').json()['agents'] if a['id']==agent_id)
        self.assertEqual(row['upload_delivery'],{**unknown_delivery(),'observed_at':None})

    def test_stale_future_offline_and_revoked_observations_are_unknown(self):
        agent_id,_=self.create_scanner();self.heartbeat(agent_id,observed(pending=4))
        with self.session_factory() as db:
            agent=db.get(Agent,agent_id)
            for fields in ({'upload_delivery_at':server.utcnow()-timedelta(seconds=46)}, {'upload_delivery_at':server.utcnow()+timedelta(seconds=20)}, {'enabled':False}, {'last_seen_at':server.utcnow()-timedelta(seconds=46)}):
                current=SimpleNamespace(enabled=agent.enabled,last_seen_at=agent.last_seen_at,upload_delivery_at=agent.upload_delivery_at,upload_delivery=agent.upload_delivery)
                for key,value in fields.items():setattr(current,key,value)
                self.assertEqual(server.scanner_delivery_projection(current),{**unknown_delivery(),'observed_at':None})

    def test_review_episodes_are_persistent_deduplicated_and_unknown_does_not_clear(self):
        agent_id,_=self.create_scanner()
        for value in (observed(review=1),observed(review=2),None,unknown_delivery(),observed(review=2)):
            self.assertEqual(self.heartbeat(agent_id,value).status_code,200)
        notices=self.client.get('/api/notifications').json()['notifications'];self.assertEqual(len(notices),1)
        self.assertEqual(notices[0]['tab'],'scanners');self.assertEqual(notices[0]['reason'],'upload_review')
        self.heartbeat(agent_id,observed(pending=5));self.heartbeat(agent_id,observed(pending=3))
        notices=self.client.get('/api/notifications').json()['notifications'];self.assertEqual(len(notices),2)
        self.assertEqual(notices[0]['reason'],'upload_review_cleared');self.assertIn('5 upload(s) remain queued',notices[0]['summary'])
        self.heartbeat(agent_id,unknown_delivery(True));self.heartbeat(agent_id,unknown_delivery(True))
        notices=self.client.get('/api/notifications').json()['notifications'];self.assertEqual(len(notices),3)
        self.assertIn('count is unavailable',notices[0]['summary'])
        with self.session_factory() as db:
            self.assertTrue(db.get(Agent,agent_id).upload_review_open)
            audits=db.scalars(select(AuditLog).where(AuditLog.action.in_(['scanner.delivery_review_required','scanner.delivery_review_cleared']))).all()
            self.assertEqual(len(audits),3);self.assertEqual({row.source_id for row in db.scalars(select(WorkspaceNotification))},{row.id for row in audits})

    def test_bad_payloads_are_rejected_and_device_access_remains_scoped(self):
        agent_id,_=self.create_scanner();self.heartbeat(agent_id,observed(pending=3))
        for fields in ({'pending_events':True},{'review_events':-1},{'payload':'private'}):
            self.assertEqual(self.heartbeat(agent_id,{**observed(),**fields}).status_code,422)
        path=f'/api/agents/{agent_id}/client-status'
        self.assertEqual(self.client.get(path).status_code,401)
        self.assertEqual(self.client.get(path,headers={'Authorization':'Bearer wrong'}).status_code,401)

    def test_additive_migration_preserves_existing_scope_and_receipts(self):
        engine=create_engine('sqlite:///:memory:')
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql("CREATE TABLE agents (id INTEGER PRIMARY KEY, authorized_networks JSON, token_hash TEXT)")
                connection.exec_driver_sql("INSERT INTO agents VALUES (1, '[\"127.0.0.1/32\"]', 'protected-fixture')")
                server.ensure_agent_telemetry_columns(connection)
                server.ensure_agent_telemetry_columns(connection)
                self.assertEqual(connection.exec_driver_sql('SELECT upload_delivery,upload_delivery_at,upload_review_open,authorized_networks,token_hash FROM agents').one(),
                    (None,None,0,'["127.0.0.1/32"]','protected-fixture'))
                self.assertTrue({'upload_delivery','upload_delivery_at','upload_review_open'}.issubset({c['name'] for c in inspect(connection).get_columns('agents')}))
        finally:engine.dispose()

    def test_concurrent_review_and_clear_each_create_one_notice(self):
        agent_id,_=self.create_scanner()
        def concurrent(value):
            barrier=threading.Barrier(2)
            def worker():
                with self.session_factory() as db:
                    agent=db.get(Agent,agent_id)
                    barrier.wait(timeout=5)
                    changed=server.record_delivery_review(db,agent,value)
                    db.commit()
                    return changed
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures=[executor.submit(worker) for _ in range(2)]
                return sorted(f.result(timeout=10) for f in futures)
        self.assertEqual(concurrent(observed(review=1)),[False,True])
        self.assertEqual(concurrent(unknown_delivery()),[False,False])
        self.assertEqual(concurrent(observed(pending=3)),[False,True])
        with self.session_factory() as db:
            self.assertFalse(db.get(Agent,agent_id).upload_review_open)
            self.assertEqual(len(db.scalars(select(AuditLog).where(AuditLog.action.like('scanner.delivery_review_%'))).all()),2)
            self.assertEqual(len(db.scalars(select(WorkspaceNotification).where(WorkspaceNotification.source_type=='scanner_delivery_review')).all()),2)

    def test_overview_counts_only_fresh_queues_and_keeps_unresolved_review(self):
        agent_id,_=self.create_scanner()
        self.heartbeat(agent_id,observed(pending=4,review=1))
        def area():return next(a for a in self.client.get('/api/workspace-posture').json()['areas'] if a['key']=='scanners')
        self.assertEqual(area()['upload_delivery'],{'queued_uploads_observed':4,'review_scanners':1,'unknown_queues':0})
        self.assertEqual(area()['state'],'attention')
        self.heartbeat(agent_id,unknown_delivery())
        self.assertEqual(area()['upload_delivery'],{'queued_uploads_observed':0,'review_scanners':1,'unknown_queues':1})
        self.heartbeat(agent_id,observed(pending=2))
        self.assertEqual(area()['upload_delivery'],{'queued_uploads_observed':2,'review_scanners':0,'unknown_queues':0})
        with self.session_factory() as db:
            db.get(Agent,agent_id).last_seen_at=server.utcnow()-timedelta(minutes=2)
            db.commit()
        self.assertEqual(area()['upload_delivery'],{'queued_uploads_observed':0,'review_scanners':0,'unknown_queues':1})


class DeliveryWorkflowTests(unittest.TestCase):
    setUp=fixtures.CISReportPDFFlowTests.setUp
    tearDown=fixtures.CISReportPDFFlowTests.tearDown
    create_scanner=fixtures.CISReportPDFFlowTests.create_scanner

    def test_outage_restart_lost_ack_duplicate_replay_saved_run_and_original_pdf(self):
        agent_id,_=self.create_scanner()
        spool=self.root/'event-spool';job_id=str(uuid4());collected='2026-10-08T12:00:00+00:00'
        config={'agent_id':agent_id,'server':'https://fixture.invalid','agent_token':'test-scanner-token'}
        def bridge():
            result=NmapUIBridge(config,'http://127.0.0.1:9000',spool_dir=spool)
            self.addCleanup(result.http.close)
            result._read_nmapui_health=Mock(return_value={'nmapui_ready':True})
            result._read_nmapui_activity=Mock(return_value=__import__('daedalus.scanner_activity',fromlist=['unknown_activity']).unknown_activity())
            result._detected_networks=[];result._network_inventory_due=float('inf')
            return result
        first=bridge()
        xml=b'<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1" version="7.98"><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="9000"><state state="open"/><service name="http"/></port></ports></host><runstats><finished elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        source=[('quickscan_results',{'total_ips':1,'hosts_up':1,'time_taken':.4}),
                ('deep_scan_results',[{'ip':'127.0.0.1','ports':[{'port':9000,'state':'open','service':'http'}]}]),
                ('scan_xml_chunk',{'target':'127.0.0.1','sha256':hashlib.sha256(xml).hexdigest(),'byte_count':len(xml),'chunk_count':1,'chunk_index':0,'xml':xml.decode()}),
                ('job_status',{'status':'completed','job_type':'scan','details':{'target':'127.0.0.1'}})]
        identities=[]
        for name,payload in source:
            identity=str(uuid4());identities.append(identity)
            first._forward_event(name,payload,client_event_id=identity,occurred_at=collected,source_job_id=job_id,source_job_type='scan')
        headers={'Authorization':'Bearer test-scanner-token'}
        def request(method,path,**kwargs):
            response=self.client.request(method,path,headers=headers,**kwargs)
            return httpx.Response(response.status_code,content=response.content,request=httpx.Request(method,'https://fixture.invalid'+path))
        first._request=request;first._heartbeat()
        dashboard=self.client.get('/api/dashboard').json()
        self.assertEqual(next(row for row in dashboard['agents'] if row['id']==agent_id)['upload_delivery']['pending_events'],4)
        first._request=Mock(side_effect=httpx.ConnectError('outage'));first._flush_events()
        with self.session_factory() as db:self.assertEqual(len(db.scalars(select(ScanEvent)).all()),0)
        restarted=bridge();self.assertEqual(restarted._read_delivery()['pending_events'],4)
        lose_ack=True
        def uncertain_request(method,path,**kwargs):
            nonlocal lose_ack
            response=request(method,path,**kwargs)
            if lose_ack:
                lose_ack=False;raise httpx.ReadError('response lost after commit')
            return response
        restarted._request=uncertain_request;restarted._flush_events()
        self.assertEqual(restarted._read_delivery()['pending_events'],4)
        with self.session_factory() as db:self.assertEqual(len(db.scalars(select(ScanEvent)).all()),1)
        final=bridge();final._request=request;final._flush_events();final._heartbeat()
        self.assertEqual(final._read_delivery()['pending_events'],0)
        with self.session_factory() as db:
            rows=db.scalars(select(ScanEvent).order_by(ScanEvent.id)).all()
            self.assertEqual(len(rows),4);self.assertEqual([row.client_event_id for row in rows],identities)
            self.assertTrue(all(server.iso_utc(row.occurred_at)=='2026-10-08T12:00:00Z' for row in rows))
        detail=self.client.get(f'/api/agents/{agent_id}/runs/{job_id}').json()
        self.assertEqual(detail['run']['status'],'completed');self.assertEqual(detail['run']['event_count'],4)
        report=self.client.post(f'/api/agents/{agent_id}/runs/{job_id}/pdf')
        self.assertEqual(report.status_code,200,report.text)
        report_id=report.json()['id']
        with self.session_factory() as db:
            saved=db.get(server.ReportJob,report_id)
            self.assertEqual(saved.status,'completed',saved.error_summary)
            self.assertEqual(saved.report_snapshot['scanner_report_template']['stylesheet_sha256'],'687e6ff1522e99a77ba03ddfe367fd098c7eb0c57eb231f3aa370fcf5ad31537')
        download=self.client.get(f'/api/reports/{report_id}/download')
        self.assertEqual(download.status_code,200);self.assertTrue(download.content.startswith(b'%PDF-'))
        self.assertEqual(self.client.get(f'/api/agents/{agent_id}/client-status',headers=headers).json()['upload_delivery']['pending_events'],0)

class DeliveryUIContracts(unittest.TestCase):
    def test_actual_delivery_renderer_expires_unknowns_and_preserves_edited_controls(self):
        import shutil
        import subprocess
        if not shutil.which('node'):self.skipTest('Node required')
        source=(Path(__file__).parents[1]/'src/daedalus/static/js/dashboard.js').read_text()
        helper=source[source.index('  function appendScannerActivity('):source.index('  function makeEventRow(')]
        script=r'''
const assert=require('node:assert/strict');
const now=Date.parse('2026-10-08T12:00:00Z'); Date.now=()=>now;
class Node {
 constructor(tag){this.tag=tag;this.children=[];this.style={};this.attributes={};this.dataset={};this.className='';this.classList={add:value=>{this.className+=' '+value;}};}
 append(...nodes){for(const n of nodes){if(n.parent)n.parent.children=n.parent.children.filter(x=>x!==n);n.parent=this;this.children.push(n);}}
 setAttribute(k,v){this.attributes[k]=v;}
 querySelector(selector){return this.children.find(x=>x.className.split(' ').includes(selector.slice(1)));}
 replaceWith(other){const parent=this.parent;parent.children=parent.children.filter(x=>x!==other);const i=parent.children.indexOf(this);parent.children.splice(i,1,other);other.parent=parent;}
}
let agentList=null;
const document={createElement:tag=>new Node(tag),getElementById:id=>id==='agent-list'?agentList:null};
function flatten(n){return [n,...n.children.flatMap(flatten)];}
function texts(n){return flatten(n).map(x=>x.textContent||'').join(' ');}
''' + helper + r'''
const delivered={schema_version:1,state:'observed',pending_events:0,review_events:0,preservation_failed:false,last_acknowledged_at:null,observed_at:new Date(now).toISOString()};
const agent={id:2,enabled:true,status:'online',bridge_online:true,nmapui_ready:false,upload_delivery:delivered};
function render(value=delivered,extra={}){const node=new Node('article');appendScannerDelivery(node,{...agent,upload_delivery:value,...extra});return node;}
assert.ok(texts(render()).includes('0 upload(s) queued'));assert.ok(texts(render()).includes('An empty queue does not prove scan completeness'));
assert.ok(texts(render({...delivered,pending_events:3})).includes('retried automatically'));
const rejected=render({...delivered,review_events:2});assert.ok(rejected.children[0].className.includes('upload-needs-review'));assert.ok(texts(rejected).includes('Keep local evidence'));
const failure=render({...delivered,preservation_failed:true});assert.ok(texts(failure).includes('local event save did not finish'));
const unmeasured={...delivered,state:'unknown',pending_events:null,review_events:null,preservation_failed:true};
assert.ok(texts(render(unmeasured)).includes('Upload queue unknown'));assert.ok(render(unmeasured).children[0].className.includes('upload-needs-review'));
for (const invalid of [undefined,{...delivered,pending_events:true},{...delivered,review_events:-1},{...delivered,pending_events:10001},{...delivered,preservation_failed:1},{...delivered,last_acknowledged_at:'<script>private</script>'},{...delivered,private:'secret'},{...delivered,observed_at:new Date(now+1).toISOString()},{...delivered,observed_at:new Date(now-45001).toISOString()}]) {
 const result=render(invalid===undefined?null:invalid);assert.ok(texts(result).includes('Current upload queue unknown'));assert.ok(!texts(result).includes('0 upload(s) queued'));assert.ok(!texts(result).includes('private'));
}
for(const extra of [{enabled:false},{bridge_online:false},{status:'disabled'}])assert.ok(texts(render(delivered,extra)).includes('unknown'));
assert.ok(texts(render({...delivered,last_acknowledged_at:new Date(now-1000).toISOString()})).includes('Last upload acknowledged'));
assert.ok(!texts(render({...delivered,last_acknowledged_at:new Date(now+1000).toISOString()})).includes('Last upload acknowledged'));
agentList=new Node('div');const card=new Node('article');card.dataset.agentId='2';const input=new Node('input');input.value='127.0.0.1';document.activeElement=input;card.append(input);agentList.append(card);
appendScannerActivity(card,agent);appendScannerDelivery(card,agent);
refreshScannerActivities([{...agent,upload_delivery:{...delivered,pending_events:4}}]);
assert.ok(texts(card).includes('4 upload(s) queued'));assert.equal(card.children.filter(x=>x.className.includes('scanner-upload-delivery')).length,1);assert.equal(document.activeElement,input);assert.equal(input.value,'127.0.0.1');
Date.now=()=>now+46000;refreshScannerActivities();assert.ok(texts(card).includes('Current upload queue unknown'));assert.equal(document.activeElement,input);assert.equal(input.value,'127.0.0.1');
'''
        result=subprocess.run(['node','-e',script],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
