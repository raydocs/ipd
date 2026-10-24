(function () {
  var form = document.getElementById("q");
  var out = document.getElementById("out");
  var verdict = document.getElementById("verdict");
  var summary = document.getElementById("summary");
  var detail = document.getElementById("detail");
  var local = document.getElementById("local");
  var localtext = document.getElementById("localtext");
  var lastEgress = [];

  function show(rep) {
    out.hidden = false;
    var v = rep.verdict || "abstain";
    verdict.textContent = "结论：" + v;
    verdict.className = "verdict " + (v === "ok" || v === "safe" || v === "native" || v === "yes" ? "ok" : v === "bad" || v === "blocked" || v === "risky" ? "bad" : "");
    summary.textContent = rep.summary_md || "";
    detail.textContent = JSON.stringify(rep.data || {}, null, 2);
    var ip = rep.data && (rep.data.ip || (rep.data.ipv4));
    if (ip) lastEgress = [ip];
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var ip = document.getElementById("ip").value.trim();
    var url = ip ? "/v1/ip/" + encodeURIComponent(ip) + "/risk" : "/v1/me";
    fetch(url, { headers: { Accept: "application/json" } })
      .then(function (r) { return r.json(); })
      .then(show)
      .catch(function (err) {
        out.hidden = false;
        verdict.textContent = "查询失败";
        summary.textContent = String(err);
      });
  });

  document.getElementById("tz").addEventListener("click", function () {
    var offset = -new Date().getTimezoneOffset() / 60;
    var zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    local.hidden = false;
    localtext.textContent = "本机时区 " + zone + "，UTC" + (offset >= 0 ? "+" : "") + offset + "。出口国家若是中国、香港或新加坡，应为 UTC+8。这个判断在浏览器里完成。";
  });

  document.getElementById("webrtc").addEventListener("click", function () {
    gather().then(function (cands) {
      var judged = window.ipdJudge.judgeLeak(lastEgress, cands);
      // Only the verdict is posted. Candidate strings stay in this function.
      return fetch("/v1/leak/webrtc", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ leak: judged.leak, candidate_count: judged.candidate_count })
      }).then(function () { return judged; });
    }).then(function (judged) {
      local.hidden = false;
      localtext.textContent = judged.leak
        ? "WebRTC 看到了与出口不一致的公网地址。候选地址没有上传。"
        : "没有发现与出口不一致的公网候选。候选地址没有上传。条数 " + judged.candidate_count + "。";
    }).catch(function (err) {
      local.hidden = false;
      localtext.textContent = "本机无法收集候选（" + err + "）。页面仍然不会上传地址。";
    });
  });

  function gather() {
    return new Promise(function (resolve, reject) {
      if (!window.RTCPeerConnection) {
        reject(new Error("no RTCPeerConnection"));
        return;
      }
      var pc = new RTCPeerConnection({ iceServers: [] });
      var found = [];
      var timer = setTimeout(function () { pc.close(); resolve(found); }, 1200);
      pc.onicecandidate = function (ev) {
        if (!ev.candidate) {
          clearTimeout(timer);
          pc.close();
          resolve(found);
          return;
        }
        found.push(ev.candidate.candidate);
      };
      pc.createDataChannel("ipd");
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(reject);
    });
  }
})();
