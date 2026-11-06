import { createRequire } from "node:module";
import assert from "node:assert/strict";
import test from "node:test";

const require = createRequire(import.meta.url);
const { judgeLeak } = require("./judge.js");

test("private candidates are ignored and public mismatches leak", () => {
  const same = judgeLeak(["1.1.1.1"], ["candidate:1 1 udp 1 1.1.1.1 9 typ host", "192.168.1.5", "10.0.0.2"]);
  assert.equal(same.leak, false);
  assert.equal(same.candidate_count, 1);
  const leak = judgeLeak(["1.1.1.1"], ["8.8.8.8"]);
  assert.equal(leak.leak, true);
  assert.equal(leak.candidate_count, 1);
  const body = { leak: leak.leak, candidate_count: leak.candidate_count };
  assert.equal("candidate" in body, false);
  assert.equal(JSON.stringify(body).includes("8.8.8.8"), false);
});

const ai = require('./judge.js');
test('local AI collection tolerates no DOM, missing APIs and exceptions', () => {
  const empty = ai.collectLocalSignals({});
  assert.equal(empty.timezone, null);
  assert.equal(empty.languages, null);
  assert.ok(empty.fonts.every(f => f.available === null));
  const hostile = new Proxy({}, { get() { throw Error('denied'); } });
  assert.doesNotThrow(() => ai.collectLocalSignals(hostile));
  const got = ai.collectLocalSignals({ Intl, Date, navigator: { languages: ['en-US'], webdriver: false, userAgent: 'synthetic wv' } });
  assert.deepEqual(got.languages, ['en-US']);
  assert.equal(got.automation, false);
  assert.equal(got.webview, true);
});

const trace = (url, ip, extra = {}) => ({ url, ip, status: 'observed', evidence: 'synthetic trace', ...extra });
const report = traces => ({ data: { schema_version: 'ai-diagnosis-v1', traces, per_service: [{ service: 'claude', seen_ip: '192.0.2.99', status: 'no', evidence: 'synthetic denial' }] } });
test('explicit traces group by IP, retaining source and unknown time, never infer from seen_ip', () => {
  const r = ai.buildAIReview(report([
    trace('https://claude.ai/cdn-cgi/trace', '192.0.2.10'),
    trace('https://chatgpt.com/cdn-cgi/trace', '192.0.2.10'),
    trace('https://api.anthropic.com/cdn-cgi/trace', '192.0.2.11'),
    trace('https://statsigapi.net/cdn-cgi/trace', '192.0.2.12', { status: 'unknown' })
  ]), null);
  assert.equal(r.groups.length, 2);
  assert.equal(r.groups[0].observations.length, 2);
  assert.equal(r.groups[0].observations[0].observed_at, null);
  assert.ok(r.groups[0].observations.some(o => o.source.includes('claude')));
  assert.deepEqual(r.fixes.map(x => x.issue).slice(0, 2), ['evidence_missing', 'egress_mismatch']);
  assert.equal(ai.buildAIReview(report([]), null).groups.length, 0);
});
test('stable order and dual stack do not invent safety or mismatch', () => {
  const traces = [trace('https://claude.ai/cdn-cgi/trace', '192.0.2.10'), trace('https://chatgpt.com/cdn-cgi/trace', '2001:db8::1')];
  const a = ai.buildAIReview(report(traces), { timezone: 'Etc/UTC', languages: ['en'] });
  const b = ai.buildAIReview(report(traces.toReversed()), { timezone: 'Etc/UTC', languages: ['en'] });
  assert.deepEqual(a, b);
  assert.equal(a.fixes.some(f => f.issue === 'egress_mismatch'), false);
  assert.equal('verdict' in a, false);
  assert.ok(a.fixes.some(f => f.issue === 'locale_review'));
});

test('invalid/failed traces stay unknown and cached_at never becomes measurement time', () => {
  const rep = report([trace('synthetic', 'not an IP'), trace('synthetic', '192.0.2.1', { status: 'error' })]);
  rep.cached_at = '2026-01-01T00:00:00Z';
  const review = ai.buildAIReview(rep, null);
  assert.equal(review.groups.length, 0);
  assert.equal(review.unknown.length, 2);
  assert.ok(review.unknown.every(o => o.observed_at === null));
  assert.deepEqual(ai.buildAIReview(null, null), ai.buildAIReview({ data: { traces: rep.data.traces } }, null));
});
test('font probing is fixed, cleans up nodes even when measurement fails', () => {
  let removed = 0, created = 0;
  const document = { body: { appendChild() {} }, createElement(tag) {
    assert.equal(tag, 'span'); created++;
    return { style: {}, getBoundingClientRect() { throw Error('layout unavailable'); }, remove() { removed++; } };
  } };
  const r = ai.collectLocalSignals({ document });
  assert.equal(created, 3);
  assert.equal(removed, 3);
  assert.ok(r.fonts.every(f => f.available === null));
});

import vm from 'node:vm';
import { readFileSync } from 'node:fs';
test('page waits for clicks; collection/import make no request or storage writes; original query still works', async () => {
  const handlers = {}, nodes = {};
  const node = id => nodes[id] ||= { textContent: '', value: '', hidden: true, children: [], addEventListener(event, fn) { handlers[id + ':' + event] = fn; }, appendChild(n) { this.children.push(n); } };
  let probes = 0, requests = [];
  const noStorage = new Proxy({}, { get() { throw Error('storage touched'); }, set() { throw Error('storage touched'); } });
  const window = { Intl, Date, localStorage: noStorage, sessionStorage: noStorage };
  Object.defineProperty(window, 'navigator', { get() { probes++; return { languages: ['en'], webdriver: true }; } });
  const context = vm.createContext({ window, document: { getElementById: node, createElement: () => node('li') }, fetch(url, options) { requests.push([url, options]); return Promise.resolve({ json: () => ({ data: { ip: '192.0.2.1' } }) }); }, URL, Set, localStorage: noStorage, sessionStorage: noStorage });
  vm.runInContext(readFileSync(new URL('./judge.js', import.meta.url), 'utf8'), context);
  vm.runInContext(readFileSync(new URL('./app.js', import.meta.url), 'utf8'), context);
  assert.equal(probes, 0);
  assert.equal(requests.length, 0);
  handlers['ai-collect:click']();
  assert.equal(probes, 1);
  node('ai-report').value = JSON.stringify(report([trace('synthetic', '192.0.2.1')]));
  handlers['ai-import:click']();
  assert.match(node('ai-groups').textContent, /192.0.2.1/);
  assert.equal(probes, 1); // import does not collect private signals
  assert.equal(requests.length, 0);
  node('ai-report').value = '<bad>';
  handlers['ai-import:click']();
  assert.match(node('ai-status').textContent, /无法解析/);
  handlers['q:submit']({ preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests.length, 1);
  assert.equal(requests[0][0], '/v1/me');
  assert.equal(requests[0][1].body, undefined);
  assert.equal(node('out').hidden, false);
});
