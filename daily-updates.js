(function () {
  var root = document.getElementById("dailyUpdates");
  if (!root) return;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function cveLink(id) {
    var a = el("a", "daily-cve", id);
    a.href = "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(id);
    a.target = "_blank";
    a.rel = "noopener";
    return a;
  }

  function card(item, kind) {
    var c = el("article", "daily-card");
    var top = el("div", "daily-card-top");
    top.appendChild(cveLink(item.cve));
    if (kind === "kev") {
      if (item.ransomware === "Known") top.appendChild(el("span", "daily-badge daily-badge-hot", "Ransomware"));
      top.appendChild(el("span", "daily-badge", "Exploited"));
    } else if (item.score != null) {
      top.appendChild(el("span", "daily-badge daily-badge-hot", "CVSS " + item.score));
    }
    c.appendChild(top);
    if (kind === "kev") {
      c.appendChild(el("h4", null, item.vendor + " " + item.product));
      c.appendChild(el("p", "daily-name", item.name));
    }
    c.appendChild(el("p", null, item.summary));
    var meta = kind === "kev"
      ? "Added " + item.added + (item.due ? " • Fix due " + item.due : "")
      : "Published " + item.published;
    c.appendChild(el("small", null, meta));
    return c;
  }

  function group(title, items, kind) {
    var g = el("div", "daily-group");
    g.appendChild(el("h3", null, title));
    var grid = el("div", "daily-grid");
    if (!items || !items.length) {
      grid.appendChild(el("p", "daily-empty", "No data yet — check back soon."));
    } else {
      items.forEach(function (i) { grid.appendChild(card(i, kind)); });
    }
    g.appendChild(grid);
    return g;
  }

  fetch("data/daily.json", { cache: "no-store" })
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function (d) {
      root.textContent = "";
      var head = el("div", "daily-tip");
      head.appendChild(el("strong", null, "✦ Tip of the day: "));
      head.appendChild(document.createTextNode(d.tip || ""));
      root.appendChild(head);
      root.appendChild(group("Newly exploited in the wild (CISA KEV)", d.kev, "kev"));
      root.appendChild(group("Critical CVEs this week (NVD)", d.critical_cves, "nvd"));
      var foot = el("p", "daily-foot",
        "Updated " + d.updated + " • Sources: CISA KEV & NIST NVD • Refreshed automatically every day.");
      root.appendChild(foot);
    })
    .catch(function () {
      root.textContent = "";
      root.appendChild(el("p", "daily-empty", "Daily updates are unavailable right now. Please try again later."));
    });
})();
