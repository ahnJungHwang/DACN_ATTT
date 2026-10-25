"""Preview only a generated synthetic report, with a test token and mock runtime."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uvicorn
from app.api import create_app
from app.config import Settings
from app.service import Service
from app.storage import Store
from test_evaluation import Runtime

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('data_root',type=Path); args=parser.parse_args()
    store=Store(args.data_root)
    with store.connect() as db: manifests=[json.loads(r[0]) for r in db.execute('SELECT manifest FROM evaluations')]
    if not manifests or not all(m['synthetic'] for m in manifests): raise ValueError('Synthetic evaluation store required')
    settings=Settings(data_root=str(store.root))
    app=create_app(settings,Service(store,settings,Runtime()),'synthetic-report-preview-only-0001')
    uvicorn.run(app,host='127.0.0.1',port=18083)
