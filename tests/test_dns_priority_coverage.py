import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js required")
def test_lookup_priority_distinguishes_no_errors_from_published_records():
    source = (Path(__file__).parents[1] / "src/daedalus/static/js/dashboard.js").read_text()
    helper = source[source.index("  function renderTopicPriorities("):source.index("  function renderDnsSnapshot(")]
    script = """
const assert = require('node:assert/strict');
function node(){return {children:[],textContent:'',append(...items){this.children.push(...items);},replaceChildren(){this.children=[];},setAttribute(){}};}
const container=node();
const document={getElementById(){return container;},createElement(){return node();}};
function content(n){return [n.textContent,...n.children.map(content)].join(' ');}
""" + helper + """
const snapshot={records:{A:[],AAAA:[]},resolver_errors:{},email_authentication_assessment:{guidance:[{level:'good',area:'DMARC',text:'Observed'}]}};
renderTopicPriorities('dns',snapshot);
assert.ok(content(container).includes('No DNS lookup errors were recorded'));
assert.ok(content(container).includes('Empty answers can still mean no record was found'));
assert.ok(!content(container).includes('Every lookup was answered'));
renderTopicPriorities('dns',{...snapshot,resolver_errors:{WWW_A:'SERVFAIL'}});
assert.ok(content(container).includes('failed and are unknown: WWW_A'));
"""
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
