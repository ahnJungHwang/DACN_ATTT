import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def test_workflow_contract_and_secret_free_export():
    workflow=json.loads((ROOT/'workflows/windows-log-slm.json').read_text(encoding='utf-8'))
    names={node['name'] for node in workflow['nodes']}
    assert {'Manual Trigger','Edit Fields','Submit','Wait','Poll','NORMAL','ALERT','UNKNOWN',
            'HTTP Error','Schema Error','Polling Limit'} <= names
    assert not workflow['active']
    for node in workflow['nodes']:
        assert 'credentials' not in node
        assert node['type'].startswith('n8n-nodes-base.')
        if node['type']=='n8n-nodes-base.httpRequest':
            assert node['parameters']['genericAuthType']=='httpHeaderAuth'
            assert node['retryOnFail'] is False
            assert node['parameters']['options']['followRedirect'] is False
    assert workflow['settings']['saveManualExecutions'] is True


def test_response_validation_boundaries_in_javascript():
    source=(ROOT/'workflows/classify-response.js').read_text(encoding='utf-8')
    source+='''
const assert=require('node:assert/strict');
const c={request_id:'11111111-1111-4111-8111-111111111111',result_id:null,poll_count:0,deadline_ms:600000};
const b={request_id:c.request_id,result_id:'22222222-2222-4222-8222-222222222222',state:'running'};
assert.equal(classifyResponse({statusCode:202,body:b},c,599999).route,'POLL');
assert.equal(classifyResponse({statusCode:200,body:b},c,600000).error_kind,'POLL_LIMIT');
assert.equal(classifyResponse({statusCode:200,body:b},{...c,poll_count:120},1).error_kind,'POLL_LIMIT');
assert.equal(classifyResponse({error:'timeout'},c,1).error_kind,'HTTP_ERROR');
assert.equal(classifyResponse({statusCode:503,body:{}},c,1).error_kind,'HTTP_ERROR');
assert.equal(classifyResponse({statusCode:200,body:{...b,request_id:'wrong'}},c,1).error_kind,'SCHEMA_ERROR');
assert.equal(classifyResponse({statusCode:200,body:{...b,label:'NORMAL'}},c,1).error_kind,'SCHEMA_ERROR');
for(const label of ['NORMAL','ALERT','UNKNOWN']){
 const complete={...b,state:'completed',result:{label,reason:'test',evidence_refs:['E001'],technical_error:null}};
 assert.equal(classifyResponse({statusCode:200,body:complete},c,1).route,label);
 delete complete.result.label;
 assert.equal(classifyResponse({statusCode:200,body:complete},c,1).error_kind,'SCHEMA_ERROR');
}
'''
    result=subprocess.run(['node','-e',source],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
