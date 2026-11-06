// Local WebRTC judgment. Candidate addresses never leave the browser.
function judgeLeak(egressIPs, candidateIPs) {
  var egress = {};
  (egressIPs || []).forEach(function (ip) {
    var n = normalizeIP(ip);
    if (n) egress[n] = true;
  });
  var count = 0;
  var leak = false;
  (candidateIPs || []).forEach(function (raw) {
    var ip = extractIP(String(raw));
    if (!ip || isNonPublic(ip)) return;
    count++;
    if (!egress[ip]) leak = true;
  });
  return { leak: leak, candidate_count: count };
}

function normalizeIP(s) {
  return extractIP(String(s || ""));
}

function extractIP(s) {
  var v4 = s.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/);
  if (v4) return v4[1];
  var v6 = s.match(/((?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4})/);
  if (!v6) return "";
  return v6[1].toLowerCase();
}

function isNonPublic(ip) {
  if (ip.indexOf(":") >= 0) {
    return ip === "::1" || ip.indexOf("fe80:") === 0 || ip.indexOf("fc") === 0 || ip.indexOf("fd") === 0;
  }
  var p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(function (n) { return n !== n || n < 0 || n > 255; })) return true;
  if (p[0] === 10 || p[0] === 127) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] === 0 || p[0] >= 224) return true;
  return false;
}

// Explicit-click collection only. No network, storage, canvas, or font enumeration.
function attempt(fn) {
  try { var value = fn(); return value === undefined ? null : value; } catch (_) { return null; }
}
function collectLocalSignals(env) {
  env = env || {};
  var nav = attempt(function () { return env.navigator; });
  return {
    source: 'browser-local; not service egress evidence',
    collected_at: attempt(function () { return new env.Date().toISOString(); }),
    timezone: attempt(function () { return env.Intl.DateTimeFormat().resolvedOptions().timeZone || null; }),
    offset_minutes: attempt(function () { return -new env.Date().getTimezoneOffset(); }),
    languages: attempt(function () {
      var values = nav.languages;
      return Array.isArray(values) && values.length ? values.filter(function (s) { return typeof s === 'string'; }).slice(0, 10) : null;
    }),
    fonts: ['Arial', 'Times New Roman', 'Courier New'].map(function (name) {
      return { name: name, available: attempt(function () { return localFontAvailable(env.document, name); }) };
    }),
    webview: attempt(function () {
      if (typeof nav.userAgent !== 'string' || !nav.userAgent) return null;
      // Only positive UA hints; absence cannot rule out an embedded browser.
      return /\bwv\b|WebView/i.test(nav.userAgent) ? true : null;
    }),
    automation: attempt(function () { return typeof nav.webdriver === 'boolean' ? nav.webdriver : null; })
  };
}
function localFontAvailable(doc, name) {
  if (!doc || !doc.body || !doc.createElement) return null;
  var span = doc.createElement('span');
  span.textContent = 'mmmmmmmmmmWWWWiiii';
  span.style.cssText = 'position:absolute;visibility:hidden;white-space:nowrap;font-size:72px;font-weight:normal;font-style:normal';
  try {
    doc.body.appendChild(span);
    var widths = ['monospace', 'serif'].map(function (fallback) {
      span.style.fontFamily = fallback;
      var base = span.getBoundingClientRect().width;
      span.style.fontFamily = '"' + name + '",' + fallback;
      var width = span.getBoundingClientRect().width;
      return base > 0 && width > 0 ? width !== base : null;
    });
    return widths.indexOf(null) >= 0 ? null : widths.some(Boolean);
  } finally { span.remove(); }
}

// Strict literals only; never extract an apparent address from arbitrary evidence text.
function evidenceIP(raw) {
  if (typeof raw !== 'string') return '';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) {
    var parts = raw.split('.');
    return parts.every(function (p) { return Number(p) <= 255; }) ? parts.map(Number).join('.') : '';
  }
  if (!/^[0-9a-f:]+$/i.test(raw) || raw.indexOf(':') < 0) return '';
  return attempt(function () { return new URL('http:' + '//[' + raw + ']/').hostname.slice(1, -1); }) || '';
}
function buildAIReview(report, local) {
  var data = report && report.data;
  if (!data || data.schema_version !== 'ai-diagnosis-v1') data = {};
  var traces = Array.isArray(data.traces) ? data.traces : [];
  var groups = {};
  var unknown = [];
  traces.forEach(function (t) {
    if (!t || typeof t !== 'object') return;
    var ip = t.status === 'observed' && t.evidence ? evidenceIP(t.ip) : '';
    var row = {
      source: typeof t.url === 'string' ? t.url : 'unknown',
      scope: 'imported probe-process trace; not browser path or account evidence',
      observed_at: null, // v1 traces have no measurement timestamp; cached_at is not one.
      status: typeof t.status === 'string' ? t.status : 'unknown',
      evidence: typeof t.evidence === 'string' ? t.evidence : 'unknown'
    };
    if (ip && row.source !== 'unknown') {
      if (!groups[ip]) groups[ip] = { ip: ip, observations: [] };
      groups[ip].observations.push(row);
    } else unknown.push(row);
  });
  function compare(a, b) { a = JSON.stringify(a); b = JSON.stringify(b); return a < b ? -1 : a > b ? 1 : 0; }
  var list = Object.keys(groups).sort().map(function (ip) {
    groups[ip].observations.sort(compare);
    return groups[ip];
  });
  unknown.sort(compare);
  var services = (Array.isArray(data.per_service) ? data.per_service : []).filter(function (s) { return s && typeof s === 'object'; }).map(function (s) {
    return { service: s.service || 'unknown', status: s.status || 'unknown', evidence: s.evidence || 'unknown', availability: s.availability || 'unknown', observed_at: null };
  }).sort(compare);
  var fixes = [];
  function fix(priority, issue, how) { fixes.push({ priority: priority, issue: issue, how: how }); }
  var sources = new Set();
  list.forEach(function (g) { g.observations.forEach(function (o) { sources.add(o.source); }); });
  // The v1 contract has five trace targets. Coverage/time gaps remain explicit.
  if (['claude.ai', 'chatgpt.com', 'api.anthropic.com', 'statsigapi.net', 'browser.sentry.io'].some(function (host) { return !sources.has('https:' + '//' + host + '/cdn-cgi/trace'); }) || unknown.length || ['claude', 'chatgpt', 'gemini', 'grok', 'copilot', 'meta_ai', 'perplexity'].some(function (id) { return !services.some(function (s) { return s.service === id && s.availability !== 'unknown'; }); })) fix(10, 'evidence_missing', '先补测服务与出口来源；测量时间未知，需在预期代理路径复测。不要把缺测当作可用。');
  var v4 = list.filter(function (g) { return g.ip.indexOf(':') < 0; });
  var v6 = list.filter(function (g) { return g.ip.indexOf(':') >= 0; });
  if (v4.length > 1 || v6.length > 1) fix(20, 'egress_mismatch', '同地址族观察到不同出口；先核验分流或轮换并复测，不推断账号封禁。IPv4/IPv6 不同本身正常。');
  if (!local) fix(30, 'local_missing', '点击本地查看后再核对时区和语言；本地信息不是服务出口证据。');
  fix(40, 'locale_review', '时区/语言与预期使用环境需人工核验，不按国家机械匹配；一致也不代表安全或可用。');
  if (local && (local.automation === true || local.webview === true)) fix(50, 'browser_hint', 'WebView/automation 仅为可能受误报影响的提示；不作为唯一指纹、封禁原因或账号限制归因。');
  return { groups: list, unknown: unknown, services: services, fixes: fixes };
}
var ipdJudgeAPI = { judgeLeak: judgeLeak, collectLocalSignals: collectLocalSignals, buildAIReview: buildAIReview };
if (typeof module !== 'undefined' && module.exports) module.exports = ipdJudgeAPI;
if (typeof window !== 'undefined') window.ipdJudge = ipdJudgeAPI;
