import codecs
import pytest
from app.config import Settings
from app.xml_logs import read_xml, LogFormatError, NS


@pytest.mark.parametrize('encoding,bom', [('utf-8', b''), ('utf-8', codecs.BOM_UTF8),
    ('utf-16-le', codecs.BOM_UTF16_LE), ('utf-16-be', codecs.BOM_UTF16_BE)])
def test_encodings_namespace(encoding, bom):
    text = f'<Events><Event xmlns="{NS}"><System/><EventData><Data Name="X">Tiếng Việt</Data></EventData></Event></Events>'
    _, events = read_xml(bom + text.encode(encoding), Settings())
    assert len(events) == 1
    assert 'Tiếng Việt' in ''.join(events[0].itertext())


@pytest.mark.parametrize('xml', [b'<Events>', b'<Wrong/>', b'<Events><Wrong/></Events>',
    b'<!DOCTYPE Events><Events/>', b'<!DOCTYPE Events [<!ENTITY a "test">]><Events>&a;</Events>',
    b'<!DOCTYPE Events SYSTEM "http://example.invalid/x"><Events/>',
    b'<Event><Event/></Event>', b'<Events><Event xmlns="urn:wrong"/></Events>'])
def test_invalid(xml):
    with pytest.raises(LogFormatError):
        read_xml(xml, Settings())


@pytest.mark.parametrize('content,code', [
    (b'[{"Id":4625,"LogName":"Security"}]', 'UNSUPPORTED_FORMAT_JSON'),
    (b'  \r\n[\r\n  {\r\n    "Id": 4625\r\n  }\r\n]\r\n', 'UNSUPPORTED_FORMAT_JSON'),
    (codecs.BOM_UTF8 + b'{"Id":4625}', 'UNSUPPORTED_FORMAT_JSON'),
    (codecs.BOM_UTF16_LE + '[{"Id":4625}]'.encode('utf-16-le'), 'UNSUPPORTED_FORMAT_JSON'),
    (b'{"event_id":4625}\n{"event_id":4624}\n', 'UNSUPPORTED_FORMAT_JSONL'),
    (b'{"event_id":4625}\n\n{"event_id":4624}', 'UNSUPPORTED_FORMAT_JSONL'),
    (b'{"event_id":4625}\nnot json\n', 'UNSUPPORTED_FORMAT_JSON'),
    (b'TimeCreated,Id,Message\n2026-10-27,4625,x\n', 'UNSUPPORTED_FORMAT_NOT_XML'),
    (b'ElfFile\x00' + b'\x00' * 32, 'UNSUPPORTED_FORMAT_EVTX'),
])
def test_names_unsupported_formats(content, code):
    with pytest.raises(LogFormatError) as error:
        read_xml(content, Settings())
    assert str(error.value) == code


def test_format_check_keeps_xml_with_leading_whitespace():
    _, events = read_xml(b'\r\n  <Events><Event/></Events>\r\n', Settings())
    assert len(events) == 1


def test_format_check_runs_after_size_limit():
    content = b'[{"Id":4625}]'
    with pytest.raises(LogFormatError, match='FILE_TOO_LARGE'):
        read_xml(content, Settings(upload_max_bytes=len(content) - 1))


def test_limits_are_inclusive():
    content = b'<Events><Event><System/></Event></Events>'
    assert len(read_xml(content, Settings(upload_max_bytes=len(content), import_max_events=1, xml_max_depth=3))[1]) == 1
    for settings in (Settings(upload_max_bytes=len(content)-1), Settings(xml_max_depth=2)):
        with pytest.raises(LogFormatError):
            read_xml(content, settings)
    with pytest.raises(LogFormatError, match='TOO_MANY_EVENTS'):
        read_xml(b'<Events><Event/><Event/></Events>', Settings(import_max_events=1))


def test_unsupported_encoding():
    with pytest.raises(LogFormatError):
        read_xml(b'<?xml version="1.0" encoding="iso-8859-1"?><Events/>', Settings())
    with pytest.raises(LogFormatError):
        read_xml('<Events/>'.encode('utf-16-le'), Settings())
