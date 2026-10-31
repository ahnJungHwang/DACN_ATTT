// Pure response validation shared by the n8n Code nodes and regression tests.
function classifyResponse(response, context, now = Date.now()) {
  const out = {...context, route: 'ERROR', error_kind: null, summary: null};
  const fail = (kind, detail) => ({...out, error_kind: kind, summary: detail});
  if (response.error || !Number.isInteger(response.statusCode))
    return fail('HTTP_ERROR', 'Response unknown. Keep request_id and query /requests/{request_id}; do not create a new key.');
  if (![200, 202].includes(response.statusCode))
    return fail('HTTP_ERROR', `HTTP ${response.statusCode}; keep request_id for recovery.`);
  const b = response.body;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!b || b.request_id !== context.request_id || !uuid.test(b.result_id || '') ||
      !['queued', 'running', 'completed'].includes(b.state) ||
      (context.result_id && b.result_id !== context.result_id))
    return fail('SCHEMA_ERROR', 'Invalid request/result identity or state.');
  out.result_id = b.result_id;
  out.state = b.state;
  if (b.state !== 'completed') {
    if (b.result !== undefined || b.label !== undefined)
      return fail('SCHEMA_ERROR', 'Pending response must not contain a verdict.');
    if (context.poll_count >= 120 || now >= context.deadline_ms)
      return {...out, route: 'ERROR', error_kind: 'POLL_LIMIT', summary: 'Polling limit reached; request may still run. Keep both IDs and query again.'};
    return {...out, route: 'POLL'};
  }
  const r = b.result;
  if (!r || !['NORMAL', 'ALERT', 'UNKNOWN'].includes(r.label) ||
      typeof r.reason !== 'string' || !r.reason.trim() || !Array.isArray(r.evidence_refs) ||
      !r.evidence_refs.every(ref => typeof ref === 'string' && ref.length > 0) ||
      (r.label === 'ALERT' && !r.evidence_refs.length) ||
      !(r.technical_error === null || typeof r.technical_error === 'string') ||
      (r.technical_error !== null && r.label !== 'UNKNOWN'))
    return fail('SCHEMA_ERROR', 'Missing/invalid label, reason, evidence_refs or technical_error.');
  if (response.statusCode !== 200)
    return fail('SCHEMA_ERROR', 'Completed result requires HTTP 200.');
  return {...out, route: r.label, label: r.label, reason: r.reason,
    evidence_refs: r.evidence_refs, technical_error: r.technical_error,
    summary: `${r.label}${r.technical_error ? ' / '+r.technical_error : ''}: ${r.reason}`};
}
