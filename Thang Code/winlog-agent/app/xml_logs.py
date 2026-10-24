"""Bounded Windows XML reader. Never interprets log content as instructions."""
import codecs
from io import StringIO
import re
from xml.etree import ElementTree as ET
from defusedxml.ElementTree import iterparse
from defusedxml.common import DefusedXmlException
from .config import Settings

NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


class LogFormatError(ValueError):
    pass


def local(tag):
    return tag.rsplit('}', 1)[-1]


def read_xml(content: bytes, settings: Settings):
    if len(content) > settings.upload_max_bytes:
        raise LogFormatError('FILE_TOO_LARGE')
    encoding = 'utf-8-sig'
    if content.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = 'utf-16'
    try:
        text = content.decode(encoding)
    except UnicodeError as exc:
        raise LogFormatError('UNSUPPORTED_ENCODING') from exc
    if '\x00' in text:
        raise LogFormatError('UNSUPPORTED_ENCODING_OR_NUL')
    declaration = re.match(r'\s*<\?xml[^?]*encoding=[\"\x27]([^\"\x27]+)', text, re.I)
    if declaration and declaration[1].lower().replace('_', '-') not in (
        ('utf-16', 'utf-16le', 'utf-16be') if encoding == 'utf-16' else ('utf-8', 'utf8')
    ):
        raise LogFormatError('ENCODING_MISMATCH')
    events, stack = [], []
    root = None
    try:
        for action, element in iterparse(StringIO(text), events=('start', 'end'),
                                         forbid_dtd=True, forbid_entities=True, forbid_external=True):
            if action == 'start':
                stack.append(element.tag)
                if len(stack) > settings.xml_max_depth:
                    raise LogFormatError('XML_TOO_DEEP')
                if len(stack) == 1:
                    root = element
                    if element.tag not in ('Events', f'{{{NS}}}Events', 'Event', f'{{{NS}}}Event'):
                        raise LogFormatError('EXPECTED_EVENTS_OR_EVENT')
                elif len(stack) == 2 and local(stack[0]) == 'Events':
                    if element.tag not in ('Event', f'{{{NS}}}Event'):
                        raise LogFormatError('EXPECTED_EVENT_CHILD')
                elif local(element.tag) == 'Event':
                    raise LogFormatError('NESTED_EVENT')
            else:
                if local(element.tag) == 'Event':
                    events.append(element)
                    if len(events) > settings.import_max_events:
                        raise LogFormatError('TOO_MANY_EVENTS')
                stack.pop()
    except (ET.ParseError, DefusedXmlException) as exc:
        raise LogFormatError(f'INVALID_OR_UNSAFE_XML: {type(exc).__name__}') from exc
    if root is None:
        raise LogFormatError('EMPTY_XML')
    return encoding, events
