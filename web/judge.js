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

if (typeof module !== "undefined" && module.exports) {
  module.exports = { judgeLeak: judgeLeak };
}
if (typeof window !== "undefined") {
  window.ipdJudge = { judgeLeak: judgeLeak };
}
