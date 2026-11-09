(function () {
  var form = document.getElementById("q");
  var out = document.getElementById("out");
  var verdict = document.getElementById("verdict");
  var summary = document.getElementById("summary");
  var detail = document.getElementById("detail");
  var local = document.getElementById("local");
  var localtext = document.getElementById("localtext");
  var lastEgress = [];
  var requestVersion = 0;
  var shareArtifact = null;
  function clearDerived() {
    shareArtifact = null;
    document.getElementById("location-panel").hidden = true;
    document.getElementById("share-controls").hidden = true;
    document.getElementById("share-opt-in").checked = false;
    document.getElementById("share-download").disabled = true;
    document.getElementById("geo-map").hidden = true;
    document.getElementById("report-facts").textContent = "";
    document.getElementById("map-note").textContent = "没有可核验坐标。不会用 (0,0) 代替未知。";
  }
  function clearReport() {
    clearDerived();
    verdict.textContent = ""; verdict.className = "verdict";
    summary.textContent = ""; detail.textContent = "";
    document.getElementById("comparison-results").hidden = true;
    document.getElementById("comparison-wrap").hidden = true;
    document.getElementById("comparison-scroll-note").hidden = true;
    document.getElementById("comparison-rows").textContent = "";
  }
  function renderEvidence(rep) {
    clearDerived();
    if (!window.ipdReport) return;
    var model = window.ipdReport.model(rep);
    var facts = document.getElementById("report-facts");
    model.facts.forEach(function (fact) {
      var card = document.createElement("div"); card.className = "fact";
      var label = document.createElement("p"); label.textContent = fact.label;
      var value = document.createElement("strong"); value.textContent = fact.value;
      if (fact.value === "unknown") card.className += " unknown";
      card.appendChild(label); card.appendChild(value); facts.appendChild(card);
    });
    if (model.point) {
      var marker = document.getElementById("geo-marker");
      marker.setAttribute("cx", model.point.x); marker.setAttribute("cy", model.point.y);
      document.getElementById("geo-map").hidden = false;
      document.getElementById("map-note").textContent = "数据库地理坐标示意，不是设备位置或精确定位；请在原始证据中核对来源与时效。";
    }
    document.getElementById("location-panel").hidden = false;
    document.getElementById("share-controls").hidden = false;
    shareArtifact = window.ipdReport.shareSVG(rep);
    verdict.textContent = model.label;
  }
  function requestReport(url, callerEgress) {
    var version = ++requestVersion;
    clearReport();
    out.hidden = false;
    verdict.textContent = "正在读取证据";
    summary.textContent = "未知或缺源不会被当作通过。";
    return fetch(url, { headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("request failed"); return r.json(); })
      .then(function (rep) { if (version === requestVersion) show(rep, callerEgress); })
      .catch(function () {
        if (version !== requestVersion) return;
        clearReport(); verdict.textContent = "查询失败"; summary.textContent = "未取得有效报告；请检查公网 IP 或稍后重试。";
        detail.textContent = ""; document.getElementById("comparison-results").hidden = true;
      });
  }
  document.getElementById("share-opt-in").addEventListener("change", function () {
    document.getElementById("share-download").disabled = !this.checked || !shareArtifact;
  });
  document.getElementById("share-download").addEventListener("click", function () {
    if (!document.getElementById("share-opt-in").checked || !shareArtifact) return;
    var url = URL.createObjectURL(new Blob([shareArtifact], {type:"image/svg+xml"}));
    var link = document.createElement("a"); link.href = url; link.download = "ipd-hidden-evidence.svg";
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });
  document.getElementById("lookup").addEventListener("click", function () {
    var ip = document.getElementById("ip").value.trim();
    if (!ip) { ++requestVersion; clearReport(); out.hidden = false; summary.textContent = "请先输入公网 IP；不会自动向第三方发起位置请求。"; return; }
    requestReport("/v1/ip/" + encodeURIComponent(ip), false);
  });

  function show(rep, callerEgress) {
    out.hidden = false;
    var v = rep.verdict || "abstain";
    verdict.textContent = "结论：" + v;
    verdict.className = "verdict " + (v === "ok" || v === "safe" || v === "native" || v === "yes" ? "ok" : v === "bad" || v === "blocked" || v === "risky" ? "bad" : "");
    summary.textContent = rep.summary_md || "";
    detail.textContent = JSON.stringify(rep.data || {}, null, 2);
    var rows = rep.data && rep.data.rows;
    document.getElementById("comparison-results").hidden = !Array.isArray(rows);
    document.getElementById("comparison-wrap").hidden = !Array.isArray(rows);
    document.getElementById("comparison-scroll-note").hidden = !Array.isArray(rows);
    var body = document.getElementById("comparison-rows");
    body.textContent = "";
    if (Array.isArray(rows)) rows.forEach(function (row) {
      var tr = document.createElement("tr");
      [row.id, [row.status, row.skipped, row.error].filter(Boolean).join(" / "),
        JSON.stringify(row.fields || {}), row.score == null ? "unknown" : row.score + " · " + row.score_meaning,
        [row.timestamp || "unknown", row.version, row.scope, row.licensing, row.attribution, row.confidence].filter(Boolean).join(" · ")
      ].forEach(function (value) {
        var td = document.createElement("td"); td.textContent = value; tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    var ip = rep.data && (rep.data.ip || (rep.data.ipv4));
    if (callerEgress && ip) lastEgress = [ip];
    renderEvidence(rep);
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var ip = document.getElementById("ip").value.trim();
    var url = ip ? "/v1/ip/" + encodeURIComponent(ip) + "/risk?live=0" : "/v1/me";
    requestReport(url, !ip);
  });

  document.getElementById("compare").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var ip = document.getElementById("ip").value.trim();
    if (!ip) { ++requestVersion; clearReport(); out.hidden = false; summary.textContent = "请输入公网 IP；不自动推断并向第三方发送本机地址。"; return; }
    var live = document.getElementById("compare-live").checked ? "1" : "0";
    requestReport("/v1/ip/" + encodeURIComponent(ip) + "/compare?live=" + live, false);
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

  // Separate in-memory state: never included in query or WebRTC uploads.
  var aiSignals = null;
  var aiReport = null;
  function showAI(candidate) {
    var review = window.ipdJudge.buildAIReview(candidate === undefined ? aiReport : candidate, aiSignals);
    document.getElementById("ai-results").hidden = false;
    document.getElementById("ai-signals").textContent = aiSignals ? JSON.stringify(aiSignals, null, 2) : "unknown（尚未点击采集）";
    document.getElementById("ai-groups").textContent = JSON.stringify({
      groups: review.groups, unknown: review.unknown, services: review.services
    }, null, 2);
    var fixes = document.getElementById("ai-fixes");
    fixes.textContent = "";
    review.fixes.forEach(function (fix) {
      var item = document.createElement("li");
      item.textContent = fix.issue + "：" + fix.how;
      fixes.appendChild(item);
    });
  }
  document.getElementById("ai-collect").addEventListener("click", function () {
    aiSignals = window.ipdJudge.collectLocalSignals(window);
    showAI();
    document.getElementById("ai-status").textContent = "已重新采集，仅本地内存；null 表示未知。字体结果为布局近似，false/缺少提示不证明无字体、无自动化。";
  });
  document.getElementById("ai-import").addEventListener("click", function () {
    try {
      var text = document.getElementById("ai-report").value;
      if (text.length > 200000) throw new Error("报告过大");
      var rep = JSON.parse(text);
      if (!rep || !rep.data || rep.data.schema_version !== "ai-diagnosis-v1") throw new Error("需要 ai-diagnosis-v1 报告");
      showAI(rep);
      aiReport = rep;
      document.getElementById("ai-status").textContent = "已本地解析，未上传；原报告中的 cached_at 不冒充逐项测量时间。";
    } catch (_) {
      document.getElementById("ai-status").textContent = "无法解析：请输入有效且不超过 200000 字符的 ai-diagnosis-v1 JSON 报告；仍显示上次成功解析的证据。";
    }
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
