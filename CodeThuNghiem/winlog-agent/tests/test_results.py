import pytest
from app.results import save_result, read_result
from app.storage import Store, canonical


def test_result_snapshots_survive_configuration_change(tmp_path):
    store=Store(tmp_path)
    case=store.create_case([])
    with store.connect() as db:
        db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                   ('req',None,case,'test-model','hash','{}','running','res','now','now',None))
    doc={'label':'UNKNOWN','technical_error':None,'raw_output':'{}',
         'payload':{'messages':['original']},'options':{'num_ctx':4096},
         'metadata':{'digest':'old'},'wall_seconds':0.5}
    save_result(store,'req',doc)
    doc['options']['num_ctx']=8192
    doc['metadata']['digest']='new'
    assert read_result(Store(tmp_path),'res')['options']['num_ctx']==4096
    assert read_result(store,'res')['metadata']['digest']=='old'
    with pytest.raises(ValueError): save_result(store,'req',doc)
