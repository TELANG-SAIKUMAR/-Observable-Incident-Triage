'use strict';
// Local simulation: mock LLM + simulated grader. Run: node sim.js
const http = require('http');
const assert = require('assert');
const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'ia-'));
process.env.LLM_BASE_URL = 'http://127.0.0.1:9101';
process.env.LLM_API_KEY = 'test';
process.env.LLM_MODEL = 'mock-model';
const { makeServer } = require('./server');

let llmCalls = 0;
const llm = http.createServer((req, res) => {
  req.resume(); req.on('end', () => {
    llmCalls++;
    const plan = {
      rootCause: 'bad_deploy', evidence: ['ev_3', 'ev_7'],
      diagnostics: [
        { toolName: 'query_metrics', arguments: { service: 'checkout', window: '15m', junk: 1 }, evidence: ['ev_3'] },
        { toolName: 'get_deploy_history', arguments: { service: 'checkout' }, evidence: ['ev_7'] },
      ],
      effect: { toolName: 'rollback_deployment', arguments: { deployment_id: 'dep_42' }, evidence: ['ev_7'] },
    };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(plan) } }], usage: { prompt_tokens: 10, completion_tokens: 5 } }));
  });
});

const SECRET = 'CANARY-' + crypto.randomUUID();
function body(runId, marker) {
  return {
    profile: 'ga5-incident-agent/v2', runId, agentName: 'incident-response', publicMarker: marker,
    sensitive: { accessToken: SECRET, privateNote: 'note-' + SECRET },
    incident: { incidentId: 'inc1', title: 't', service: 'checkout', severity: 'SEV-1', allowedRootCauses: ['bad_deploy', 'db_saturation'],
      transcript: Array.from({ length: 12 }, (_, i) => `[ev_${i + 1}] line ${i + 1}`).join('\n') },
    toolCatalog: [
      { name: 'query_metrics', description: 'd', inputSchema: { properties: { service: {}, window: {} } } },
      { name: 'get_deploy_history', description: 'd', inputSchema: { properties: { service: {} } } },
      { name: 'rollback_deployment', description: 'd', inputSchema: { properties: { deployment_id: {} } } },
    ],
    policy: { maximumDiagnostics: 3, effectTools: ['rollback_deployment', 'scale_service'], approvalRequiredFor: ['rollback_deployment', 'disable_feature'], doNotExport: ['accessToken'] },
  };
}

async function main() {
  await new Promise(r => llm.listen(9101, r));
  const srv = makeServer(); await new Promise(r => srv.listen(9100, r));
  const B = 'http://127.0.0.1:9100';
  const post = async (u, b, h = {}) => { const r = await fetch(B + u, { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: JSON.stringify(b) }); return { s: r.status, j: await r.json(), t: null }; };
  const get = async u => { const r = await fetch(B + u); return { s: r.status, j: await r.json() }; };
  const uuid = () => crypto.randomUUID();

  // ---- scenario 1: 503 retry, join, approval, completion
  const tid = 'a'.repeat(32), psid = 'b'.repeat(16);
  const b1 = body('run-aaaaaaaa-1', 'marker-1');
  let r = await post('/v2/incidents', b1, { traceparent: `00-${tid}-${psid}-01`, tracestate: 'vendor=x' });
  assert.equal(r.s, 200); assert.equal(r.j.status, 'waiting');
  assert.equal(r.j.dispatches.length, 2);
  assert.deepEqual(r.j.dispatches[0].arguments, { service: 'checkout', window: '15m' });
  assert(r.j.dispatches.every(d => d.traceparent.startsWith(`00-${tid}-`) && d.tracestate === 'vendor=x'));
  const [d1, d2] = r.j.dispatches;
  const out = (d, status, extra = {}) => ({ actionId: d.actionId, callId: d.callId, attempt: d.attempt, status, resultClass: 'ok', nonce: uuid(), ...extra });
  const runPath = '/v2/incidents/' + b1.runId;
  r = await post(runPath + '/receipts', { receiptId: 'rcpt-0000001', outcomes: [out(d1, 503), out(d2, 200)] });
  assert.equal(r.j.dispatches.length, 1); assert.equal(r.j.dispatches[0].attempt, 2); assert.deepEqual(r.j.approvals, []);
  assert.equal(r.j.dispatches[0].actionId, d1.actionId);
  assert.notEqual(r.j.dispatches[0].traceparent, d1.traceparent);
  const retry = r.j.dispatches[0];
  const rc1 = { receiptId: 'rcpt-0000002', outcomes: [out(retry, 200)] };
  r = await post(runPath + '/receipts', rc1);
  assert.equal(r.j.dispatches.length, 0); assert.equal(r.j.approvals.length, 1);
  const ap = r.j.approvals[0];
  assert.equal(ap.argumentsDigest, crypto.createHash('sha256').update('{"deployment_id":"dep_42"}').digest('hex'));
  // bad receipts change nothing
  assert.equal((await post(runPath + '/receipts', { receiptId: 'rcpt-bad', approvals: [{ approvalId: 'nope', decision: 'approved', nonce: 'x' }] })).s, 422);
  const apNonce = uuid();
  const rc2 = { receiptId: 'rcpt-0000003', approvals: [{ approvalId: ap.approvalId, decision: 'approved', nonce: apNonce }] };
  r = await post(runPath + '/receipts', rc2);
  const eff = r.j.dispatches[0];
  assert.equal(eff.actionId, ap.actionId); assert.equal(eff.approvalId, ap.approvalId); assert.equal(eff.approvalNonce, apNonce);
  r = await post(runPath + '/receipts', { receiptId: 'rcpt-0000004', outcomes: [out(eff, 200)] });
  assert.equal(r.j.status, 'completed'); assert.equal(r.j.chosenEffect, 'rollback_deployment');
  assert(!('dispatches' in r.j));
  const fin = r.j;
  assert.equal(fin.actionLog.length, 4); assert.equal(fin.receiptLog.length, 5);
  // trace checks
  const spans = fin.otlp.resourceSpans[0].scopeSpans[0].spans;
  const byName = n => spans.filter(s => s.name === n || s.name.startsWith(n));
  assert(spans.every(s => s.traceId === tid));
  assert.equal(new Set(spans.map(s => s.spanId)).size, spans.length);
  assert.equal(byName('POST /v2/incidents')[0].parentSpanId, psid);
  assert.equal(byName('chat incident-plan').length, 1);
  assert.equal(byName('execute_tool').length, 3);
  assert.equal(byName('POST tool/').length, 4);
  assert.equal(byName('incident.join').length, 1); assert.equal(byName('incident.join')[0].links.length, 2);
  assert.equal(byName('approval_gate').length, 1);
  for (const d of fin.actionLog) assert(spans.some(s => s.name.startsWith('POST tool/') && d.traceparent.split('-')[2] === s.spanId));
  const attr = (s, k) => (s.attributes.find(a => a.key === k) || {}).value;
  const c503 = spans.find(s => s.name.startsWith('POST tool/') && attr(s, 'error.type'));
  assert.equal(attr(c503, 'error.type').stringValue, '503'); assert.equal(c503.status.code, 2); assert.equal(attr(c503, 'http.request.resend_count').intValue, 0);
  assert(spans.every(s => attr(s, 'ga5.run.id').stringValue === b1.runId && attr(s, 'ga5.public.marker').stringValue === 'marker-1'));
  assert(!JSON.stringify(fin).includes(SECRET));
  // replay / conflicts
  const calls = llmCalls;
  assert.deepEqual((await post('/v2/incidents', b1)).j, fin);
  assert.deepEqual((await post(runPath + '/receipts', rc2)).j.dispatches[0], eff);
  assert.deepEqual((await get(runPath)).j, fin);
  assert.equal((await post('/v2/incidents', { ...b1, publicMarker: 'changed' })).s, 409);
  assert.equal((await post(runPath + '/receipts', { ...rc2, approvals: [{ approvalId: ap.approvalId, decision: 'denied', nonce: apNonce }] })).s, 409);
  assert.equal((await post(runPath + '/receipts', { receiptId: 'rcpt-new-0001', outcomes: [out(eff, 200)] })).s, 422);
  assert.equal(llmCalls, calls);
  assert.equal((await post('/v2/incidents', { ...body('run-bad-profile', 'm'), profile: 'x' })).s, 400);
  assert.equal((await get('/v2/incidents/run-bad-profile')).s, 404);

  // ---- scenario 2: timeout suppresses effect
  const b2 = body('run-bbbbbbbb-2', 'marker-2');
  r = await post('/v2/incidents', b2);
  assert(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/.test(r.j.dispatches[0].traceparent)); assert(!('tracestate' in r.j.dispatches[0]));
  const [e1, e2] = r.j.dispatches;
  r = await post('/v2/incidents/' + b2.runId + '/receipts', { receiptId: 'rcpt-t-00001', outcomes: [out(e1, 200), { actionId: e2.actionId, callId: e2.callId, attempt: 1, status: 0, errorType: 'timeout', nonce: uuid() }] });
  assert.equal(r.j.status, 'failed'); assert.equal(r.j.suppressed.length, 1); assert.equal(r.j.actionLog.length, 2);
  const sp2 = r.j.otlp.resourceSpans[0].scopeSpans[0].spans;
  assert.equal(sp2.filter(s => s.name === 'approval_gate').length, 0);
  assert.equal(attr(sp2.find(s => attr(s, 'error.type')), 'error.type').stringValue, 'timeout');
  console.log('ALL SIM CHECKS PASSED (llm calls: ' + llmCalls + ')');
  srv.close(); llm.close(); process.exit(0);
}
main().catch(e => { console.error(e); process.exit(1); });
