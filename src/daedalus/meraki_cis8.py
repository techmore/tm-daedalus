"""CIS Controls v8 evidence review, derived from immutable Meraki observations.

This is a control-level evidence index, not a safeguard compliance assessment.
"""
from collections import Counter
from typing import Any

SOURCE_URL = 'https://www.cisecurity.org/controls/cis-controls-navigator/v8'
TITLES = (
    'Inventory and Control of Enterprise Assets', 'Inventory and Control of Software Assets',
    'Data Protection', 'Secure Configuration of Enterprise Assets and Software', 'Account Management',
    'Access Control Management', 'Continuous Vulnerability Management', 'Audit Log Management',
    'Email and Web Browser Protections', 'Malware Defenses', 'Data Recovery',
    'Network Infrastructure Management', 'Network Monitoring and Defense',
    'Security Awareness and Skills Training', 'Service Provider Management',
    'Application Software Security', 'Incident Response Management', 'Penetration Testing',
)
ACTIONS = (
    'Reconcile assigned Meraki inventory with the enterprise inventory, ownership and unmanaged assets.',
    'Review endpoint software inventories, authorization and support status with the software owner.',
    'Validate data classification, encryption, retention and access policies; network settings alone are insufficient.',
    'Review the observed settings and exceptions against approved secure configuration baselines.',
    'Review administrator accounts, SSO/MFA, authorization and inactive-account removal in the identity systems.',
    'Validate guest isolation, segmentation, 802.1X and approved access policies using configuration and operational evidence.',
    'Review firmware support, update schedules, vulnerability scans and remediation records with the network owner.',
    'Review syslog destinations, event collection, retention, time synchronization and log review records.',
    'Review web filtering and threat settings alongside email and endpoint browser protection evidence.',
    'Review network malware protection alongside endpoint prevention, detection and response coverage.',
    'Validate protected backups and documented restore tests for all required systems.',
    'Reconcile observed topology with the approved network design, management access and configuration procedures.',
    'Review monitoring coverage, alert destinations and SIEM correlation using collected events and response records.',
    'Review training participation, role-specific skills and awareness exercises.',
    'Review provider inventory, contracts, security responsibilities and periodic assessments.',
    'Review application inventory, secure development practices, dependency management and security testing.',
    'Review incident plans, responsible contacts, exercises and lessons learned.',
    'Review authorized penetration-test scope, results, remediation and retesting evidence.',
)


def build_cis8_assessment(snapshot: dict[str, Any]) -> dict[str, Any]:
    devices = snapshot.get('devices') if isinstance(snapshot.get('devices'), list) else []
    devices = [d for d in devices if isinstance(d, dict)]
    controls = snapshot.get('security_controls') if isinstance(snapshot.get('security_controls'), list) else []
    controls = [c for c in controls if isinstance(c, dict)]
    findings = snapshot.get('findings') if isinstance(snapshot.get('findings'), list) else []
    review_count = sum(isinstance(f, dict) and f.get('status') == 'Review' for f in findings)
    ports = snapshot.get('switch_ports') if isinstance(snapshot.get('switch_ports'), list) else []
    port_reviews = sum(row['data'].get('review_port_count', 0) for row in ports if isinstance(row,dict)
                       and row.get('status')=='complete' and isinstance(row.get('data'),dict)
                       and type(row['data'].get('review_port_count')) is int and row['data']['review_port_count']>=0)
    configuration_titles = {'Wireless SSID security', 'Switch port configuration', 'Switch access policies',
        'L3 firewall rules', 'L7 firewall rules', 'Inbound firewall rules', 'Content filtering', 'Intrusion protection', 'Malware protection'}
    groups = {
        3: {'Switch port configuration','L3 firewall rules','Content filtering'},
        4: configuration_titles,
        6: {'Wireless SSID security','Switch access policies','Switch port configuration'},
        9: {'Content filtering','Intrusion protection','Malware protection'},
        10: {'Malware protection'},
        12: {'Switch port configuration','Switch port status','Managed link-layer topology'},
        13: {'Intrusion protection'},
    }
    rows = []
    for control_id, title in enumerate(TITLES,1):
        status='not_assessed'; evidence=[]; observation='This Meraki snapshot does not assess this control. External evidence and human review are required.'
        if control_id==1:
            evidence=['meraki.devices'];status='partial' if devices else 'not_assessed'
            observation=f'{len(devices)} assigned Meraki device records saved. Unmanaged assets, enterprise-wide completeness and ownership are not established.'
        elif control_id==7:
            firmware_count=sum(isinstance(d.get('firmware'),str) and bool(d['firmware']) for d in devices)
            evidence=['meraki.devices'];status='partial' if firmware_count else 'not_assessed'
            observation=f'{firmware_count}/{len(devices)} assigned devices have saved firmware strings. Support/EOL status, update windows, vulnerability exposure and remediation are not assessed.'
        elif control_id in groups:
            selected=[c for c in controls if c.get('control') in groups[control_id]]
            complete=sum(c.get('status')=='complete' and c.get('data') is not None for c in selected)
            unavailable=sum(c.get('status')!='complete' or c.get('data') is None for c in selected)
            evidence=['meraki.security_controls: '+name for name in sorted(groups[control_id])]
            status='partial' if complete else 'not_assessed'
            observation=f'{complete} saved observation(s) read; {unavailable} selected observation(s) unavailable/unsupported. Collection is not evidence that settings satisfy a control or safeguard.'
            disabled=sum(c.get('status')=='complete' and isinstance(c.get('data'),dict) and
                str(c['data'].get('mode','')).casefold()=='disabled' for c in selected if c.get('control') in {'Intrusion protection','Malware protection'})
            open_ssids=sum(isinstance(s,dict) and s.get('enabled') is True and s.get('authMode')=='open'
                for c in selected if c.get('control')=='Wireless SSID security' and c.get('status')=='complete' and isinstance(c.get('data'),list) for s in c['data'])
            if control_id==4 and (review_count or port_reviews):
                status='review';observation+=f' {review_count} saved Review observations and {port_reviews} ports with review prompts require investigation.'
                evidence+=['meraki.findings','meraki.switch_ports']
            elif disabled or open_ssids:
                status='review';observation+=f' {disabled} selected threat settings report disabled; {open_ssids} enabled open SSIDs require policy review.'
            if control_id==3: observation+=' Data classification, endpoint/cloud encryption and DLP are not assessed.'
            if control_id==9: observation+=' Email and endpoint browser policies are not assessed.'
            if control_id==10: observation+=' Endpoint malware defenses are not assessed.'
            if control_id==13: observation+=' Syslog, SIEM, event retention and actual alert delivery are not assessed.'
        rows.append({'control_id':control_id,'title':title,'status':status,'observation':observation,
                     'evidence_references':evidence,'next_action':ACTIONS[control_id-1]})
    counts=Counter(row['status'] for row in rows)
    return {'schema_version':1,'framework':'CIS Controls v8','source_url':SOURCE_URL,
        'collected_at':snapshot.get('collected_at'),'rows':rows,
        'summary':{key:counts[key] for key in ('partial','review','not_assessed')},
        'scope':'Control-level index of saved Meraki evidence and review actions. No CIS safeguard compliance, implementation group coverage, certification or overall score is asserted. Partial evidence still requires external evidence and human assessment. This is separate from endpoint CIS benchmark results.'}


def project_cis8_assessment(value: Any) -> dict | None:
    if not isinstance(value,dict) or type(value.get('schema_version')) is not int or value['schema_version']!=1 or value.get('framework')!='CIS Controls v8':return None
    rows=value.get('rows') if isinstance(value.get('rows'),list) else []
    clean=[];seen=set()
    for row in rows[:18]:
        if not isinstance(row,dict):continue
        identifier=row.get('control_id')
        if type(identifier) is not int or not 1<=identifier<=18 or identifier in seen:continue
        seen.add(identifier)
        status=row.get('status') if row.get('status') in ('partial','review','not_assessed') else 'not_assessed'
        refs=row.get('evidence_references') if isinstance(row.get('evidence_references'),list) else []
        clean.append({'control_id':identifier,'title':TITLES[identifier-1],'status':status,
            'observation':row['observation'][:2000] if isinstance(row.get('observation'),str) else '',
            'next_action':row['next_action'][:1000] if isinstance(row.get('next_action'),str) else '',
            'evidence_references':[r[:200] for r in refs[:12] if isinstance(r,str)]})
    counts=Counter(r['status'] for r in clean)
    return {'schema_version':1,'framework':'CIS Controls v8','source_url':SOURCE_URL,'rows':clean,
        'summary':{key:counts[key] for key in ('partial','review','not_assessed')},
        'scope':value['scope'][:1000] if isinstance(value.get('scope'),str) else '',
        'collected_at':value['collected_at'][:80] if isinstance(value.get('collected_at'),str) else ''}
