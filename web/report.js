(function (root) {
  "use strict";
  var labels = {ok:"观察完成", safe:"观察完成 · 非安全保证", risky:"发现风险信号", bad:"发现风险信号", blocked:"观察到阻断", yes:"观察到可用", no:"观察到不可用", native:"原生证据", abstain:"无法判定", caveat:"证据有限", unknown:"未知"};
  function object(v) { return v && typeof v === "object" && !Array.isArray(v) ? v : {}; }
  function scalar(v) { return typeof v === "string" && v.length && v.length <= 120 ? v : typeof v === "number" && Number.isFinite(v) ? String(v) : "unknown"; }
  function model(rep) {
    rep = object(rep);
    var data = object(rep.data), geo = object(data.geo), asn = object(data.asn);
    var me = Object.hasOwn(data, "ipv4") || Object.hasOwn(data, "ipv6");
    var verdict = Object.hasOwn(labels, rep.verdict) ? rep.verdict : "unknown";
    var sources = Array.isArray(rep.sources) ? rep.sources.length : 0;
    var point = null;
    if (typeof geo.lat === "number" && Number.isFinite(geo.lat) && Math.abs(geo.lat) <= 90 &&
        typeof geo.lon === "number" && Number.isFinite(geo.lon) && Math.abs(geo.lon) <= 180 &&
        (geo.lat !== 0 || geo.lon !== 0) && Array.isArray(geo.sources) && geo.sources.length > 0) {
      point = {x:(geo.lon + 180) / 360 * 600, y:(90 - geo.lat) / 180 * 260};
    }
    var facts = [
      {label:"住宅分类", value:scalar(me ? data.type : object(data.residential).class)},
      {label:"原生 / 广播", value:scalar(object(data.native).verdict)},
      {label:"国家 / 地区", value:scalar(me ? data.cc : geo.cc)},
      {label:"ASN", value:scalar(me ? data.asn : asn.asn)}
    ];
    return {verdict:verdict, label:labels[verdict], sources:sources, facts:facts, point:point};
  }
  // The share artifact never accepts arbitrary report text, identifiers or coordinates.
  function shareSVG(rep) {
    var m = model(rep);
    return '<svg xmlns="http://www.w3.org/2000/svg" width="720" height="360" viewBox="0 0 720 360" role="img" aria-label="IP hidden evidence summary">' +
      '<rect width="720" height="360" rx="24" fill="#101e29"/><g font-family="system-ui,sans-serif" fill="#f3f6f8">' +
      '<text x="40" y="60" font-size="22">ipd / EVIDENCE</text><text x="40" y="128" font-size="38">IP HIDDEN</text>' +
      '<text x="40" y="184" font-size="24">' + m.label + '</text><text x="40" y="234" font-size="18">Sources: ' + m.sources + '</text>' +
      '<text x="40" y="290" font-size="15">Local observation only. Not an account safety guarantee.</text>' +
      '<text x="40" y="318" font-size="14">No IP, location, raw errors or account data included.</text></g></svg>';
  }
  root.ipdReport = {model:model, shareSVG:shareSVG};
})(typeof window === "undefined" ? globalThis : window);
