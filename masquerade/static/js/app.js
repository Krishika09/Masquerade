/* Masquerade UI helpers - dependency-free (works fully offline). */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

  function el(tag, attrs, parent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs || {}) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function txt(parent, x, y, s, attrs) {
    const t = el("text", Object.assign({ x, y }, attrs || {}), parent);
    t.textContent = s;
    return t;
  }

  /* ---------------- tooltip ---------------- */
  const tip = document.createElement("div");
  tip.id = "tip";
  document.body.appendChild(tip);
  function showTip(e, title, body) {
    tip.innerHTML = "<b>" + title + "</b>" + body;
    tip.style.display = "block";
    moveTip(e);
  }
  function moveTip(e) {
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let x = e.clientX + 14, y = e.clientY + 14;
    if (x + w > window.innerWidth - 8) x = e.clientX - w - 14;
    if (y + h > window.innerHeight - 8) y = e.clientY - h - 14;
    tip.style.left = x + "px"; tip.style.top = y + "px";
  }
  function hideTip() { tip.style.display = "none"; }
  function bindTip(node, title, body) {
    node.addEventListener("mouseenter", (e) => showTip(e, title, body));
    node.addEventListener("mousemove", moveTip);
    node.addEventListener("mouseleave", hideTip);
  }
  document.querySelectorAll("[data-tip]").forEach((n) => {
    const [t, b] = n.getAttribute("data-tip").split("|");
    bindTip(n, t, b || "");
  });

  /* ---------------- section entropy bar chart ---------------- */
  function entropyChart(host, sections) {
    const W = 640, H = 250, m = { l: 34, r: 44, t: 18, b: 38 };
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Section entropy chart" }, host);
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const y = (v) => m.t + ih - (v / 8) * ih;
    for (let g = 0; g <= 8; g += 2) {
      el("line", { x1: m.l, x2: W - m.r, y1: y(g), y2: y(g), stroke: css("--line"), "stroke-width": 1 }, svg);
      txt(svg, m.l - 8, y(g) + 4, g.toFixed(0), { "text-anchor": "end" });
    }
    const n = sections.length, band = iw / Math.max(n, 1);
    const bw = Math.min(54, band * 0.58);
    sections.forEach((s, i) => {
      const cx = m.l + band * i + band / 2, top = y(s.entropy), base = y(0);
      const hot = s.entropy >= 7.0;
      const r = Math.min(4, (base - top) / 2);
      const x0 = cx - bw / 2, x1 = cx + bw / 2;
      const d = base - top < 1 ? `M${x0},${base}h${bw}v-1h-${bw}z`
        : `M${x0},${base}V${top + r}Q${x0},${top} ${x0 + r},${top}H${x1 - r}Q${x1},${top} ${x1},${top + r}V${base}Z`;
      const p = el("path", { d, fill: hot ? css("--serious") : css("--accent") }, svg);
      txt(svg, cx, top - 6, s.entropy.toFixed(2), { "text-anchor": "middle", class: "lbl-strong" });
      txt(svg, cx, base + 16, s.name.length > 10 ? s.name.slice(0, 9) + "…" : s.name,
        { "text-anchor": "middle", class: "lbl-strong", style: "font-family:var(--mono)" });
      txt(svg, cx, base + 30, s.perms + (s.contains_entry_point ? " · EP" : ""),
        { "text-anchor": "middle", style: "font-family:var(--mono);font-size:10px" });
      const hit = el("rect", { x: m.l + band * i, y: m.t, width: band, height: ih, fill: "transparent" }, svg);
      bindTip(hit, s.name, `Entropy <b style="display:inline;color:inherit;font-size:12px">${s.entropy.toFixed(3)}</b> bits/byte<br>` +
        `Perms ${s.perms} · raw ${s.raw_size.toLocaleString()} B · virtual ${s.virtual_size.toLocaleString()} B` +
        (s.contains_entry_point ? "<br>Contains entry point" : ""));
      hit.addEventListener("mouseenter", () => p.setAttribute("opacity", ".8"));
      hit.addEventListener("mouseleave", () => p.removeAttribute("opacity"));
    });
    el("line", { x1: m.l, x2: W - m.r, y1: y(7), y2: y(7), stroke: css("--text-2"), "stroke-width": 1.2, "stroke-dasharray": "5 4" }, svg);
    txt(svg, W - m.r + 6, y(7) + 4, "7.0", { "text-anchor": "start", class: "lbl-strong" });
    el("line", { x1: m.l, x2: W - m.r, y1: y(0), y2: y(0), stroke: css("--line-2") }, svg);
  }

  /* ---------------- generic x/y line chart on [0,1]^2 ---------------- */
  function unitChart(host, opts) {
    const W = opts.width || 460, H = opts.height || 340, m = { l: 46, r: 16, t: 14, b: 42 };
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.aria || "chart" }, host);
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const X = (v) => m.l + v * iw, Y = (v) => m.t + ih - v * ih;
    for (let g = 0; g <= 1.0001; g += 0.25) {
      el("line", { x1: X(0), x2: X(1), y1: Y(g), y2: Y(g), stroke: css("--line") }, svg);
      el("line", { x1: X(g), x2: X(g), y1: Y(0), y2: Y(1), stroke: css("--line") }, svg);
      txt(svg, X(0) - 8, Y(g) + 4, g.toFixed(2), { "text-anchor": "end" });
      txt(svg, X(g), Y(0) + 16, g.toFixed(2), { "text-anchor": "middle" });
    }
    txt(svg, m.l + iw / 2, H - 4, opts.xLabel, { "text-anchor": "middle", class: "lbl-strong" });
    const yl = txt(svg, 12, m.t + ih / 2, opts.yLabel, { "text-anchor": "middle", class: "lbl-strong" });
    yl.setAttribute("transform", `rotate(-90 12 ${m.t + ih / 2})`);
    if (opts.diagonal !== false)
      el("line", { x1: X(0), y1: Y(0), x2: X(1), y2: Y(1), stroke: css("--muted"), "stroke-dasharray": "5 4", "stroke-width": 1.2 }, svg);

    (opts.series || []).forEach((s) => {
      const d = s.points.map((p, i) => (i ? "L" : "M") + X(p[0]).toFixed(1) + "," + Y(p[1]).toFixed(1)).join("");
      el("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, svg);
      if (s.markers) s.points.forEach((p) => {
        const c = el("circle", { cx: X(p[0]), cy: Y(p[1]), r: 4.5, fill: s.hollow ? css("--panel") : s.color, stroke: s.hollow ? s.color : css("--panel"), "stroke-width": 2 }, svg);
        const hit = el("circle", { cx: X(p[0]), cy: Y(p[1]), r: 11, fill: "transparent" }, svg);
        bindTip(hit, s.name, s.tip ? s.tip(p) : `x ${p[0].toFixed(3)} · y ${p[1].toFixed(3)}`);
        hit.addEventListener("mouseenter", () => c.setAttribute("r", 6));
        hit.addEventListener("mouseleave", () => c.setAttribute("r", 4.5));
      });
    });

    if (opts.highlight) {
      const h = opts.highlight;
      el("line", { x1: X(h.x), x2: X(h.x), y1: Y(0), y2: Y(h.y), stroke: css("--series-2"), "stroke-dasharray": "3 3", "stroke-width": 1.4 }, svg);
      el("line", { x1: X(0), x2: X(h.x), y1: Y(h.y), y2: Y(h.y), stroke: css("--accent"), "stroke-dasharray": "3 3", "stroke-width": 1.4 }, svg);
      el("circle", { cx: X(h.x), cy: Y(0), r: 5, fill: css("--panel"), stroke: css("--series-2"), "stroke-width": 2 }, svg);
      const dot = el("circle", { cx: X(h.x), cy: Y(h.y), r: 7, fill: css("--accent"), stroke: css("--panel"), "stroke-width": 2.5 }, svg);
      // label sits away from the S-shaped curve: lower-right for high scores, upper-left for low ones
      const hi = h.x >= 0.5;
      txt(svg, hi ? X(h.x) - 12 : X(h.x) + 12, hi ? Y(0.1) : Y(0.9), h.label,
        { "text-anchor": hi ? "end" : "start", class: "lbl-strong", style: "fill:var(--text);font-size:12.5px" });
      const hit = el("circle", { cx: X(h.x), cy: Y(h.y), r: 14, fill: "transparent" }, svg);
      bindTip(hit, "This sample", h.tip);
      void dot;
    }
    return svg;
  }

  /* ---------------- wire up charts from embedded JSON ---------------- */
  const dataNode = document.getElementById("chart-data");
  const D = dataNode ? JSON.parse(dataNode.textContent) : null;
  if (D) {
    const ent = document.getElementById("entropy-chart");
    if (ent && D.sections) entropyChart(ent, D.sections);

    const cm = document.getElementById("calmap-chart");
    if (cm && D.calmap) {
      unitChart(cm, {
        aria: "Calibration map", xLabel: "Raw Random Forest score", yLabel: "Calibrated probability",
        series: [{ name: "Platt (sigmoid) calibration map", color: css("--accent"), points: D.calmap.map((p) => [p.raw, p.cal]) }],
        highlight: { x: D.raw, y: D.cal, label: `raw ${D.raw.toFixed(2)} → calibrated ${D.cal.toFixed(2)}`,
          tip: `Raw RF score ${D.raw.toFixed(4)}<br>Calibrated probability ${D.cal.toFixed(4)}` },
      });
    }

    const rel = document.getElementById("reliability-chart");
    if (rel && D.reliability) {
      const t = (p) => `Mean predicted ${p[0].toFixed(3)}<br>Observed malware rate ${p[1].toFixed(3)}<br>${p[2]} test samples`;
      unitChart(rel, {
        aria: "Reliability diagram", xLabel: "Mean predicted probability", yLabel: "Observed fraction malicious",
        series: [
          { name: "Raw Random Forest", color: css("--series-2"), markers: true, hollow: true, tip: t,
            points: D.reliability.raw.map((b) => [b.mean_pred, b.frac_pos, b.count]) },
          { name: "Calibrated (Platt)", color: css("--accent"), markers: true, tip: t,
            points: D.reliability.calibrated.map((b) => [b.mean_pred, b.frac_pos, b.count]) },
        ],
      });
    }

    const roc = document.getElementById("roc-chart");
    if (roc && D.roc) {
      unitChart(roc, {
        width: 420, height: 300, aria: "ROC curve", xLabel: "False positive rate", yLabel: "True positive rate",
        series: [{ name: "ROC", color: css("--accent"), points: D.roc.fpr.map((f, i) => [f, D.roc.tpr[i]]) }],
      });
    }
  }

  /* ---------------- upload dropzone ---------------- */
  const drop = document.getElementById("drop");
  if (drop) {
    const input = drop.querySelector("input[type=file]");
    const picked = drop.querySelector(".picked");
    const show = () => {
      const f = input.files && input.files[0];
      picked.textContent = f ? `${f.name}  ·  ${(f.size / 1024).toFixed(1)} KB` : "";
    };
    input.addEventListener("change", show);
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", (e) => { if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; show(); } });
    const form = document.getElementById("upload-form");
    form.addEventListener("submit", () => {
      const b = form.querySelector("button[type=submit]");
      b.disabled = true; b.textContent = "Analyzing statically…";
    });
  }

  /* ---------------- JSON syntax highlight ---------------- */
  document.querySelectorAll("pre.json").forEach((pre) => {
    const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const src = pre.textContent;
    const hl = (s) => s.replace(
      /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false)\b|\bnull\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
      (mt, _a, colon) => {
        let cls = "n";
        if (/^"/.test(mt)) cls = colon ? "k" : "s";
        else if (/true|false/.test(mt)) cls = "b";
        else if (/null/.test(mt)) cls = "z";
        if (cls === "k") return `<span class="k">${mt.replace(/:$/, "")}</span>:`;
        return `<span class="${cls}">${mt}</span>`;
      });
    // top-level keys (indent of exactly two spaces) become scroll anchors
    pre.innerHTML = esc(src).split("\n").map((line) => {
      const m = /^ {2}"([^"]+)":/.exec(line);
      return (m ? `<span class="anchor" id="json-${m[1]}"></span>` : "") + hl(line);
    }).join("\n");
  });

  /* copy buttons */
  document.querySelectorAll("[data-copy]").forEach((b) => {
    b.addEventListener("click", () => {
      navigator.clipboard && navigator.clipboard.writeText(b.getAttribute("data-copy"));
      const o = b.textContent; b.textContent = "Copied"; setTimeout(() => (b.textContent = o), 1200);
    });
  });
})();
