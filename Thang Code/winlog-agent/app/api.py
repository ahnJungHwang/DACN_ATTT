"""Local authenticated HTTP API for UI and n8n; one Uvicorn worker only."""
import asyncio
from contextlib import asynccontextmanager
import csv
import hmac
import io
import json
from pathlib import Path
import secrets
from uuid import uuid4
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse, Response
from itsdangerous import URLSafeTimedSerializer, BadSignature
from pydantic import BaseModel, ConfigDict
from .cases import create_cases
from .config import Settings, load_settings
from .context_tokens import ContextGuard
from .import_logs import import_files, import_report
from .inference import Inference
from .ollama import Ollama
from .service import Service, ServiceError
from .storage import Store, DuplicateSource, canonical


class AnalysisBody(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    case_id:str
    model:str


class CaseBody(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    import_id:str
    start:str|None=None
    end:str|None=None
    user:str|None=None
    group_ids:list[str]|None=None
    mixed:bool=False


class LoginBody(BaseModel):
    token:str


def secret_file(path):
    path.parent.mkdir(parents=True,exist_ok=True)
    try:
        with path.open('x',encoding='utf-8') as handle: handle.write(secrets.token_urlsafe(32))
    except FileExistsError: pass
    value=path.read_text(encoding='utf-8').strip()
    if len(value)<32: raise ValueError('Local secret too short')
    return value


def create_app(settings=None,service=None,token=None):
    settings=settings or Settings()
    store=service.store if service else Store(settings.data_root)
    token=token or secret_file(store.root/'secrets/api-token.txt')
    signer=URLSafeTimedSerializer(secret_file(store.root/'secrets/session-key.txt'),salt='winlog-ui')
    service=service or Service(store,settings,Inference(Ollama(),ContextGuard(store.root/'tokenizers')))
    @asynccontextmanager
    async def lifespan(app):
        service.start()
        try: yield
        finally: service.close()
    app=FastAPI(lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
    app.state.service=service
    @app.exception_handler(ServiceError)
    async def service_error(request,exc): return JSONResponse({'error':exc.code},status_code=exc.status)
    @app.exception_handler(KeyError)
    async def missing(request,exc): return JSONResponse({'error':'NOT_FOUND'},status_code=404)
    @app.exception_handler(DuplicateSource)
    async def duplicate(request,exc): return JSONResponse({'error':'SOURCE_EXISTS','source_id':exc.source_id},status_code=409)
    @app.exception_handler(ValueError)
    async def invalid(request,exc): return JSONResponse({'error':str(exc)},status_code=422)

    @app.middleware('http')
    async def authenticate(request,call_next):
        if request.url.path in ('/','/health','/login') or request.url.path.startswith('/static/'):
            return await call_next(request)
        bearer=request.headers.get('authorization','')
        if bearer.startswith('Bearer ') and hmac.compare_digest(bearer[7:],token):
            return await call_next(request)
        try: session=signer.loads(request.cookies.get('winlog_session',''),max_age=3600)
        except BadSignature: return JSONResponse({'error':'UNAUTHORIZED'},status_code=401)
        request.state.csrf=session['csrf']
        if request.method not in ('GET','HEAD','OPTIONS'):
            if not hmac.compare_digest(request.headers.get('x-csrf-token',''),session['csrf']):
                return JSONResponse({'error':'CSRF_REQUIRED'},status_code=403)
        return await call_next(request)

    @app.get('/health')
    def health(): return {'status':'degraded' if service.degraded or service.runtime.degraded else 'ok'}

    assets=Path(__file__).resolve().parent.parent
    app.mount('/static',StaticFiles(directory=assets/'static'),name='static')
    templates=Jinja2Templates(directory=assets/'templates')
    @app.get('/')
    def home(request:Request):
        return templates.TemplateResponse(request=request,name='index.html',context={})

    @app.post('/login')
    def login(body:LoginBody):
        if not hmac.compare_digest(body.token,token): raise HTTPException(401,'Invalid token')
        csrf=secrets.token_urlsafe(32)
        response=JSONResponse({'csrf_token':csrf})
        response.set_cookie('winlog_session',signer.dumps({'csrf':csrf}),httponly=True,samesite='strict',max_age=3600)
        return response

    @app.get('/session')
    def session(request:Request): return {'csrf_token':getattr(request.state,'csrf',None)}

    @app.get('/models')
    def models():
        items=[]
        for model in settings.allowed_models:
            try: items.append(dict(service.runtime.client.inspect(model),available=True))
            except Exception: items.append({'model':model,'available':False})
        return {'models':items}

    @app.get('/cases')
    def cases():
        with store.connect() as db:
            return {'cases':[dict(r) for r in db.execute('SELECT case_id,created_at,version FROM cases ORDER BY created_at DESC')]}

    @app.get('/cases/{case_id}')
    def case(case_id:str):
        with store.connect() as db: row=db.execute('SELECT * FROM cases WHERE case_id=?',(case_id,)).fetchone()
        if row is None: raise KeyError(case_id)
        return dict(row,snapshot=json.loads(row['snapshot']))

    @app.post('/cases')
    def make_cases(body:CaseBody):
        return create_cases(store,body.import_id,settings,**body.model_dump(exclude={'import_id'}))

    @app.post('/analyze')
    async def analyze(body:AnalysisBody,request:Request):
        envelope=await asyncio.to_thread(service.submit,body.case_id,body.model,request.headers.get('idempotency-key'))
        deadline=asyncio.get_running_loop().time()+settings.response_wait_seconds
        while envelope['state']!='completed' and asyncio.get_running_loop().time()<deadline:
            await asyncio.sleep(.05)
            envelope=await asyncio.to_thread(service.status,envelope['request_id'])
        return JSONResponse(envelope,status_code=200 if envelope['state']=='completed' else 202)

    @app.get('/requests/{request_id}')
    def request_status(request_id:str): return service.status(request_id)

    @app.get('/results/{result_id}')
    def result_status(result_id:str): return service.result_status(result_id)

    @app.post('/imports')
    async def upload(security:UploadFile|None=File(default=None),powershell:UploadFile|None=File(default=None),synthetic:bool=Form(default=False)):
        if not security and not powershell: raise HTTPException(422,'No files supplied')
        files={}; created=[]
        try:
            for name,item in (('Security',security),('PowerShell',powershell)):
                if item:
                    content=await item.read(settings.upload_max_bytes+1)
                    if len(content)>settings.upload_max_bytes: raise HTTPException(413,'File too large')
                    path=store.root/'staging'/(str(uuid4())+'.upload')
                    path.write_bytes(content); created.append(path); files[name]=path
            return await asyncio.to_thread(import_files,store,files,settings,
                synthetic=synthetic,
                original_names={name:item.filename for name,item in (('Security',security),('PowerShell',powershell)) if item})
        finally:
            for path in created: path.unlink(missing_ok=True)

    @app.get('/imports/{import_id}')
    def imported(import_id:str): return import_report(store,import_id)

    @app.get('/sources/{source_id}')
    def source(source_id:str):
        with store.connect() as db: row=db.execute('SELECT source_id,import_id,source_name,original_name FROM sources WHERE source_id=?',(source_id,)).fetchone()
        if row is None: raise KeyError(source_id)
        return dict(row)

    @app.get('/events/{event_ref}')
    def event(event_ref:str): return store.event(event_ref)

    @app.get('/results/{result_id}/export')
    def export(result_id:str,format:str='jsonl'):
        envelope=service.result_status(result_id)
        if envelope['state']!='completed': raise HTTPException(409,'Result not completed')
        result=envelope['result']
        if format=='jsonl': return Response(canonical(result)+'\n',media_type='application/x-ndjson')
        if format!='csv': raise HTTPException(422,'Unsupported format')
        buffer=io.StringIO(newline=''); writer=csv.writer(buffer)
        fields=('label','reason','evidence_refs','technical_error')
        writer.writerow(fields)
        values=[]
        for field in fields:
            value=result.get(field)
            text=canonical(value) if isinstance(value,(dict,list)) else str(value or '')
            if text.lstrip().startswith(('=','+','-','@')): text="'"+text
            values.append(text)
        writer.writerow(values)
        return Response(buffer.getvalue(),media_type='text/csv')
    return app


if __name__=='__main__':
    import argparse
    import uvicorn
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',type=Path,default=Path('config.local.toml'))
    args=parser.parse_args()
    settings=load_settings(args.config)
    uvicorn.run(create_app(settings),host=settings.host,port=settings.port,workers=1)
