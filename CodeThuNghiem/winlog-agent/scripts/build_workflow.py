"""Build a secret-free n8n workflow for the installed 2.44.6 core nodes."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER = (ROOT / 'workflows/classify-response.js').read_text(encoding='utf-8')


def build():
    nodes, connections = [], {}
    def node(name, kind, version, parameters, x, y, **extra):
        nodes.append(dict(id=name.lower().replace(' ', '-'), name=name,
                          type='n8n-nodes-base.'+kind, typeVersion=version,
                          position=[x,y], parameters=parameters, **extra))
    def link(source, target, output=0):
        branches=connections.setdefault(source, {'main':[]})['main']
        while len(branches)<=output: branches.append([])
        branches[output].append({'node':target,'type':'main','index':0})
    def code(name, source, x, y): node(name,'code',2,{'jsCode':source},x,y)
    def switch(name, expr, x, y): node(name,'switch',1,{'mode':'expression','output':expr},x,y)
    def http(name, method, url, x, y):
        parameters={'authentication':'genericCredentialType','genericAuthType':'httpHeaderAuth',
                    'requestMethod':method,'url':url,'responseFormat':'json','jsonParameters':True,
                    'options':{'fullResponse':True,'ignoreResponseCode':True,'timeout':30000,
                               'followRedirect':False,'followAllRedirects':False}}
        if method=='POST':
            parameters.update(bodyParametersJson='={{ JSON.stringify({case_id:$json.case_id, model:$json.model}) }}',
                headerParametersJson='={{ JSON.stringify({"Idempotency-Key":$json.request_id}) }}')
        node(name,'httpRequest',2,parameters,x,y,continueOnFail=True,retryOnFail=False)
    node('Manual Trigger','manualTrigger',1,{},0,0)
    node('Edit Fields','set',1,{'keepOnlySet':True,'values':{'string':[
        {'name':'base_url','value':'http://host.docker.internal:8000'},
        {'name':'case_id','value':'REPLACE_WITH_CASE_ID'},
        {'name':'model','value':'qwen2.5:3b-instruct-q4_K_M'},
        {'name':'request_id','value':'REPLACE_WITH_UUID_KEEP_FOR_RETRY'}]}},220,0)
    code('Prepare', """const c=$input.first().json;
if(!/^http:\/\/(host\.docker\.internal|127\.0\.0\.1|localhost):[0-9]+$/.test(c.base_url)) throw new Error('Only local API URLs allowed');
if(!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(c.request_id)) throw new Error('Set request_id to a UUID and keep it when retrying');
if(!c.case_id || c.case_id.startsWith('REPLACE_')) throw new Error('Set case_id from the local app');
if(!['qwen2.5:3b-instruct-q4_K_M','llama3.2:3b-instruct-q4_K_M'].includes(c.model)) throw new Error('Unsupported model');
return [{json:{...c,poll_count:0,deadline_ms:Date.now()+600000,result_id:null}}];""",440,0)
    http('Submit','POST','={{ $json.base_url + "/analyze" }}',660,0)
    code('Check Submit',CLASSIFIER+"\nreturn [{json:classifyResponse($input.first().json,$('Prepare').first().json)}];",880,0)
    switch('Route State','={{ $json.route === "POLL" ? 0 : ($json.route === "ERROR" ? 1 : 2) }}',1100,0)
    node('Wait','wait',1.1,{'resume':'timeInterval','amount':5,'unit':'seconds'},1100,300,webhookId='winlog-local-poll')
    code('Poll Context',"const c=$input.first().json; return [{json:{...c,poll_count:c.poll_count+1,expired:Date.now()>=c.deadline_ms}}];",880,300)
    switch('Check Deadline','={{ $json.expired ? 1 : 0 }}',660,300)
    http('Poll','GET','={{ $json.base_url + "/results/" + $json.result_id }}',440,300)
    code('Check Poll',CLASSIFIER+"\nreturn [{json:classifyResponse($input.first().json,$('Poll Context').item.json)}];",440,520)
    code('Polling Expired',"return [{json:{...$input.first().json,route:'ERROR',error_kind:'POLL_LIMIT',summary:'600 seconds elapsed. Keep IDs and query again; no new job was submitted.'}}];",880,550)
    switch('Switch Label','={{ ["NORMAL","ALERT","UNKNOWN"].indexOf($json.label) }}',1320,0)
    for i,name in enumerate(['NORMAL','ALERT','UNKNOWN']):
        code(name,'return $input.all();',1540,(i-1)*180)
        link('Switch Label',name,i)
    switch('Switch Error','={{ $json.error_kind === "SCHEMA_ERROR" ? 1 : ($json.error_kind === "POLL_LIMIT" ? 2 : 0) }}',1320,480)
    for i,name in enumerate(['HTTP Error','Schema Error','Polling Limit']):
        code(name,'return $input.all();',1540,360+i*160)
        link('Switch Error',name,i)
    for a,b in [('Manual Trigger','Edit Fields'),('Edit Fields','Prepare'),('Prepare','Submit'),
                ('Submit','Check Submit'),('Check Submit','Route State'),('Wait','Poll Context'),
                ('Poll Context','Check Deadline'),('Check Deadline','Poll'),('Poll','Check Poll'),
                ('Check Poll','Route State'),('Polling Expired','Switch Error')]: link(a,b)
    link('Route State','Wait'); link('Route State','Switch Error',1); link('Route State','Switch Label',2)
    link('Check Deadline','Polling Expired',1)
    return {'name':'Windows Log SLM - Local analysis','nodes':nodes,'connections':connections,
            'active':False,'settings':{'executionOrder':'v1','saveManualExecutions':True,
            'saveDataSuccessExecution':'all','saveDataErrorExecution':'all','executionTimeout':660},
            'pinData':{}}


if __name__=='__main__':
    path=ROOT/'workflows/windows-log-slm.json'
    path.write_text(json.dumps(build(),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(path)
