import json
from pathlib import Path
from uuid import uuid4
import pytest
from app.storage import digest
from app.verify_collection import verify_collection,instant


def fixture(root):
    xml=(Path(__file__).parent/'fixtures/synthetic-security.xml').read_bytes()
    empty=b'<Events></Events>'
    (root/'security.xml').write_bytes(xml); (root/'powershell.xml').write_bytes(empty)
    time='2026-01-01T00:00:00Z'
    data={'schema_version':1,'run_id':str(uuid4()),'computer':'synthetic-vm','interval':'inclusive',
          'start_utc':time,'end_utc':time,'start_input':'2026-01-01T07:00:00+07:00','end_input':time,
          'status':'complete','sources':[
              {'source':'Security','channel':'Security','event_ids':[4624,4625,4688],'status':'success',
               'file':'security.xml','sha256':digest(xml).upper(),'count':1,'counts_by_id':{'4624':1,'4625':0,'4688':0},
               'first_event_utc':time,'last_event_utc':time},
              {'source':'PowerShell','channel':'Microsoft-Windows-PowerShell/Operational','event_ids':[4104],
               'status':'no_events','file':'powershell.xml','sha256':digest(empty),'count':0,'counts_by_id':{'4104':0},
               'first_event_utc':None,'last_event_utc':None}]}
    return data


def save(root,data): (root/'manifest.json').write_text(json.dumps(data),encoding='utf-8')


def test_collection_readonly_valid_and_missing_ids(tmp_path):
    data=fixture(tmp_path); save(tmp_path,data)
    before={p.name:p.read_bytes() for p in tmp_path.iterdir()}
    report=verify_collection(tmp_path)
    assert report['ready_for_manual_review'] and len(report['warnings'])==2
    assert before=={p.name:p.read_bytes() for p in tmp_path.iterdir()}


@pytest.mark.parametrize('field,value',[('sha256','bad'),('count',2),('counts_by_id',{'4624':2}),
                                      ('file','../security.xml'),('first_event_utc','2026-01-01T00:01:00Z'),
                                      ('status','no_events')])
def test_collection_mismatch(tmp_path,field,value):
    data=fixture(tmp_path); data['sources'][0][field]=value; save(tmp_path,data)
    assert not verify_collection(tmp_path)['integrity_ok']


def test_partial_collection_not_ready(tmp_path):
    data=fixture(tmp_path); data['status']='partial'; data['sources'][1]['status']='permission_denied'; save(tmp_path,data)
    report=verify_collection(tmp_path)
    assert report['integrity_ok'] and not report['collection_complete'] and not report['ready_for_manual_review']


def test_host_interval_and_seventh_fraction_digit(tmp_path):
    assert instant('2026-01-01T00:00:00.0000001Z')>instant('2026-01-01T00:00:00Z')
    data=fixture(tmp_path); data['computer']='wrong-machine'; save(tmp_path,data)
    assert not verify_collection(tmp_path)['integrity_ok']
    data=fixture(tmp_path); data['start_utc']=data['start_input']='2026-01-01T00:00:00.0000001Z'
    data['end_utc']=data['end_input']='2026-01-01T00:00:01Z'; save(tmp_path,data)
    assert not verify_collection(tmp_path)['integrity_ok']
