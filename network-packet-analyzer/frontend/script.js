/* Packet Analyzer dashboard.
 * Polls the Flask API, then draws a live "traffic map": this machine sits in the
 * middle, other hosts orbit it, and every packet flies between them as a comet
 * coloured by protocol. */
(function () {
  "use strict";

  const API = "";            // same origin as the Flask server
  const POLL_MS = 1000;
  const MAX_ROWS = 300;
  const MAX_NODES = 16;      // hosts drawn on the map
  const MAX_PARTICLES = 400;
  const MTU = 1514;
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const PROTO_VARS = {
    TCP: "--c-tcp", UDP: "--c-udp", DNS: "--c-dns", HTTP: "--c-http", HTTPS: "--c-https",
    ICMP: "--c-icmp", ARP: "--c-arp", SSH: "--c-ssh",
  };
  const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fd)/i;

  const $ = (id) => document.getElementById(id);
  const el = {
    status: $("status"), statusText: $("status-text"), error: $("error"),
    form: $("capture-form"), iface: $("iface"), bpf: $("bpf"), demo: $("demo"),
    start: $("start-btn"), stop: $("stop-btn"), clear: $("clear-btn"), tryDemo: $("try-demo"),
    map: $("map"), canvas: $("map-canvas"), hint: $("map-hint"), tip: $("tip"), pps: $("n-pps"),
    strip: $("proto-strip"), chips: $("proto-chips"),
    gPackets: $("g-packets"), gBytes: $("g-bytes"), gBps: $("g-bps"), gHosts: $("g-hosts"),
    spPackets: $("sp-packets"), spBytes: $("sp-bytes"),
    topSrc: $("top-src"), topDst: $("top-dst"),
    search: $("search"), pause: $("pause-btn"), rowCount: $("row-count"),
    body: $("packet-body"), empty: $("empty"),
    detail: $("detail"), rSrc: $("r-src"), rDst: $("r-dst"), rWire: $("r-wire"),
    rProto: $("r-proto"), rLen: $("r-len"), rMeter: $("r-meter"), dList: $("d-list"),
  };

  const ctx = el.canvas.getContext("2d");
  const state = {
    packets: [],          // newest first, straight from the API
    lastId: 0,
    paused: false,
    filter: "all",        // protocol chosen with the chips
    selected: null,       // packet chosen in the log
    local: null,          // address of "this machine"
    localNode: { addr: null, local: true, pulse: 0, pkts: 0, bytes: 0, proto: "TCP" },
    nodes: new Map(),     // address -> node
    slots: 0,
    moreHosts: 0,
    particles: [],
    edges: new Map(),
    hover: null,
    w: 0, h: 0,
    protocols: [],
    timeline: [],
  };

  /* ================= small helpers ================= */
  async function api(path, options) {
    const res = await fetch(API + path, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  const colorCache = {};
  function cssVar(name) {
    if (!colorCache[name]) colorCache[name] = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return colorCache[name];
  }
  const protoColor = (name) => cssVar(PROTO_VARS[name] || "--c-other");

  function formatBytes(n) {
    if (n < 1024) return `${Math.round(n)} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
    return `${n.toFixed(n < 10 ? 2 : 1)} ${units[i]}`;
  }

  function node(tag, className, text) {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function shorten(addr, max) {
    return addr.length <= max ? addr : `${addr.slice(0, max / 2 - 1)}…${addr.slice(-(max / 2 - 2))}`;
  }

  function showError(message) {
    el.error.textContent = message || "";
    el.error.hidden = !message;
  }

  /* ================= capture controls ================= */
  function renderStatus(s) {
    el.status.classList.toggle("live", s.mode === "live");
    el.status.classList.toggle("demo", s.mode === "demo");
    el.statusText.textContent =
      s.mode === "live" ? `Capturing on ${s.interface || "default interface"}` :
      s.mode === "demo" ? "Showing demo traffic" : "Idle";
    el.start.disabled = s.running;
    el.stop.disabled = !s.running;
    [el.iface, el.bpf, el.demo].forEach((c) => (c.disabled = s.running));
    state.running = s.running;
    if (!s.scapy_available && !s.running) {
      showError("Scapy is not available, so live capture is off. Use demo traffic, or install the requirements.");
    }
  }

  async function loadInterfaces() {
    try {
      const { interfaces } = await api("/api/interfaces");
      interfaces.forEach((name) => {
        const opt = node("option", "", name);
        opt.value = name;
        el.iface.appendChild(opt);
      });
    } catch (err) { /* keep the default option */ }
  }

  async function startCapture(forceDemo) {
    showError("");
    try {
      const status = await api("/api/capture/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          interface: el.iface.value, filter: el.bpf.value, demo: forceDemo || el.demo.checked,
        }),
      });
      if (forceDemo) el.demo.checked = true;
      renderStatus(status);
      refresh();
    } catch (err) {
      showError(err.message);
    }
  }

  el.form.addEventListener("submit", (e) => { e.preventDefault(); startCapture(false); });
  el.tryDemo.addEventListener("click", () => startCapture(true));

  el.stop.addEventListener("click", async () => {
    try { renderStatus(await api("/api/capture/stop", { method: "POST" })); }
    catch (err) { showError(err.message); }
  });

  el.clear.addEventListener("click", async () => {
    await api("/api/packets/clear", { method: "POST" });
    Object.assign(state, { packets: [], selected: null, local: null, particles: [], moreHosts: 0 });
    state.nodes.clear();
    state.edges.clear();
    el.detail.hidden = true;
    refresh();
  });

  el.pause.addEventListener("click", () => {
    state.paused = !state.paused;
    el.pause.setAttribute("aria-pressed", String(state.paused));
    el.pause.textContent = state.paused ? "Resume log" : "Pause log";
    if (!state.paused) renderTable();
  });

  el.search.addEventListener("input", renderTable);

  function setFilter(name) {
    state.filter = state.filter === name ? "all" : name;
    renderChips();
    renderTable();
  }

  function filterByHost(addr) {
    el.search.value = el.search.value === addr ? "" : addr;
    renderTable();
    el.search.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "center" });
  }

  /* ================= stats panels ================= */
  function renderStats(s) {
    el.pps.textContent = Math.round(s.packets_per_second).toLocaleString();
    el.gPackets.textContent = s.total_packets.toLocaleString();
    el.gBytes.textContent = formatBytes(s.total_bytes);
    el.gBps.textContent = `${formatBytes(s.bytes_per_second)}/s`;
    state.timeline = s.timeline;
    state.protocols = s.protocols;
    drawSpark(el.spPackets, s.timeline.map((d) => d.packets), cssVar("--c-tcp"));
    drawSpark(el.spBytes, s.timeline.map((d) => d.bytes), cssVar("--c-https"));
    renderCargo();
    renderRank(el.topSrc, s.top_sources);
    renderRank(el.topDst, s.top_destinations);
  }

  function renderCargo() {
    el.strip.replaceChildren();
    state.protocols.forEach((p) => {
      const seg = node("span");
      seg.style.width = `${p.percent}%`;
      seg.style.background = protoColor(p.name);
      seg.style.opacity = state.filter === "all" || state.filter === p.name ? 1 : 0.2;
      seg.title = `${p.name}: ${p.percent}%`;
      el.strip.appendChild(seg);
    });
    renderChips();
  }

  let chipSignature = "";

  function renderChips() {
    // Rebuild the chips only when the set of protocols or the filter changes, so keyboard focus is not lost every second.
    const total = state.protocols.reduce((a, p) => a + p.count, 0);
    const signature = `${state.filter}|${state.protocols.map((p) => p.name).join(",")}`;

    if (signature === chipSignature) {
      el.chips.querySelectorAll("[data-count]").forEach((span) => {
        const name = span.dataset.count;
        const p = state.protocols.find((x) => x.name === name);
        span.textContent = name === "all" ? total.toLocaleString() : p ? `${p.percent}%` : "";
      });
    } else {
      chipSignature = signature;
      el.chips.replaceChildren();
      const make = (name, label, count) => {
        const li = node("li");
        const b = node("button", "chip");
        b.type = "button";
        b.setAttribute("aria-pressed", String(state.filter === name || (name === "all" && state.filter === "all")));
        if (name !== "all") {
          const sw = node("span", "sw");
          sw.style.background = protoColor(name);
          b.appendChild(sw);
        }
        const n = node("span", "n", count);
        n.dataset.count = name;
        b.append(node("span", "", label), n);
        b.addEventListener("click", () => {
          if (name === "all") { state.filter = "all"; renderChips(); renderTable(); } else setFilter(name);
        });
        li.appendChild(b);
        el.chips.appendChild(li);
      };
      make("all", "All", total.toLocaleString());
      state.protocols.forEach((p) => make(p.name, p.name, `${p.percent}%`));
    }

    [...el.strip.children].forEach((seg, i) => {
      const p = state.protocols[i];
      if (p) seg.style.opacity = state.filter === "all" || state.filter === p.name ? 1 : 0.2;
    });
  }

  function renderRank(list, items) {
    list.replaceChildren();
    if (!items.length) { list.appendChild(node("li", "none", "Nothing captured yet")); return; }
    const max = Math.max(...items.map((i) => i.packets));
    items.forEach((it) => {
      const li = node("li");
      li.style.setProperty("--w", `${(it.packets / max) * 100}%`);
      li.title = "Show these packets in the log";
      li.append(node("span", "addr", it.address), node("span", "val", `${it.packets.toLocaleString()} pkts · ${formatBytes(it.bytes)}`));
      li.addEventListener("click", () => filterByHost(it.address));
      list.appendChild(li);
    });
  }

  function drawSpark(canvas, values, color) {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (!w || !h) return;
    canvas.width = w * dpr; canvas.height = h * dpr;
    const c = canvas.getContext("2d");
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    const max = Math.max(1, ...values);
    const step = w / (values.length - 1 || 1);
    c.beginPath();
    values.forEach((v, i) => {
      const x = i * step, y = h - 2 - (v / max) * (h - 6);
      i ? c.lineTo(x, y) : c.moveTo(x, y);
    });
    c.strokeStyle = color; c.lineWidth = 1.8; c.lineJoin = "round"; c.stroke();
    c.lineTo(w, h); c.lineTo(0, h); c.closePath();
    c.globalAlpha = 0.16; c.fillStyle = color; c.fill(); c.globalAlpha = 1;
  }

  /* ================= packet log ================= */
  function visiblePackets() {
    const q = el.search.value.trim().toLowerCase();
    return state.packets.filter((p) => {
      if (state.filter !== "all" && p.protocol !== state.filter) return false;
      if (!q) return true;
      return [p.src, p.dst, p.sport, p.dport, p.protocol, p.info].join(" ").toLowerCase().includes(q);
    });
  }

  function renderTable() {
    if (state.paused) return;
    const all = visiblePackets();
    const rows = all.slice(0, MAX_ROWS);
    el.body.replaceChildren();
    el.empty.hidden = rows.length > 0;
    el.empty.textContent = state.packets.length ? "No packets match the current filter." : "No packets yet.";
    el.rowCount.textContent = state.packets.length ? `Showing ${rows.length} of the latest ${state.packets.length}` : "";

    const frag = document.createDocumentFragment();
    rows.forEach((p) => {
      const tr = document.createElement("tr");
      const pc = protoColor(p.protocol);
      tr.style.setProperty("--pc", pc);
      if (state.selected && p.id === state.selected.id) tr.className = "selected";

      tr.appendChild(node("td", "mono", p.id));
      tr.appendChild(node("td", "mono", p.time));
      tr.appendChild(node("td", "mono", p.sport ? `${p.src}:${p.sport}` : p.src));
      tr.appendChild(node("td", "mono", p.dport ? `${p.dst}:${p.dport}` : p.dst));

      const protoTd = node("td");
      const pill = node("span", "pill");
      pill.append(node("i"), document.createTextNode(p.protocol));
      protoTd.appendChild(pill);
      tr.appendChild(protoTd);

      const lenTd = node("td");
      const len = node("div", "len");
      const bar = node("span", "bar");
      const fill = node("b");
      fill.style.setProperty("--w", `${Math.min(100, (p.length / MTU) * 100)}%`);
      bar.appendChild(fill);
      len.append(node("span", "", p.length), bar);
      lenTd.appendChild(len);
      tr.appendChild(lenTd);

      tr.appendChild(node("td", "info", p.info));
      tr.addEventListener("click", () => selectPacket(p));
      frag.appendChild(tr);
    });
    el.body.appendChild(frag);
  }

  function selectPacket(p) {
    state.selected = p;
    el.detail.hidden = false;
    el.detail.style.setProperty("--pc", protoColor(p.protocol));
    el.rSrc.textContent = p.sport ? `${p.src}:${p.sport}` : p.src;
    el.rDst.textContent = p.dport ? `${p.dst}:${p.dport}` : p.dst;
    el.rProto.textContent = p.protocol;
    el.rLen.textContent = `${p.length} B`;
    el.rMeter.style.width = `${Math.min(100, (p.length / MTU) * 100)}%`;

    el.dList.replaceChildren();
    [["Captured at", p.time], ["Transport", p.transport], ["TCP flags", p.flags],
     ["TTL / hop limit", p.ttl], ["Packet number", `#${p.id}`], ["What it says", p.info]]
      .forEach(([k, v]) => {
        if (v === null || v === undefined || v === "") return;
        const d = node("div");
        d.append(node("dt", "", k), node("dd", "", String(v)));
        el.dList.appendChild(d);
      });
    renderTable();
  }

  /* ================= map: hosts ================= */
  function pickLocal(counts) {
    if (state.local && counts.has(state.local)) return;
    let best = null, bestN = 0;
    counts.forEach((n, addr) => { if (PRIVATE.test(addr) && n > bestN) { best = addr; bestN = n; } });
    if (!best) counts.forEach((n, addr) => { if (n > bestN) { best = addr; bestN = n; } });
    state.local = best;
    state.localNode.addr = best;
  }

  function updateNodes(packets) {
    const counts = new Map(), bytes = new Map(), protos = new Map();
    packets.forEach((p) => {
      [p.src, p.dst].forEach((addr) => {
        if (!addr || addr === "-") return;
        counts.set(addr, (counts.get(addr) || 0) + 1);
        bytes.set(addr, (bytes.get(addr) || 0) + p.length);
        const pm = protos.get(addr) || new Map();
        pm.set(p.protocol, (pm.get(p.protocol) || 0) + 1);
        protos.set(addr, pm);
      });
    });
    if (!counts.size) { state.local = null; state.nodes.clear(); state.moreHosts = 0; return; }
    pickLocal(counts);

    const dominant = (addr) => [...protos.get(addr)].sort((a, b) => b[1] - a[1])[0][0];
    const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1])
      .map((e) => e[0]).filter((a) => a !== state.local).slice(0, MAX_NODES);
    const keep = new Set(ranked);
    [...state.nodes.keys()].forEach((a) => { if (!keep.has(a)) state.nodes.delete(a); });

    ranked.forEach((addr) => {
      let n = state.nodes.get(addr);
      if (!n) { n = { addr, slot: state.slots++, pulse: 0 }; state.nodes.set(addr, n); }
      n.pkts = counts.get(addr); n.bytes = bytes.get(addr); n.proto = dominant(addr);
    });
    Object.assign(state.localNode, { pkts: counts.get(state.local), bytes: bytes.get(state.local), proto: dominant(state.local) });
    state.moreHosts = Math.max(0, counts.size - 1 - ranked.length);
    el.gHosts.textContent = (state.nodes.size + 1 + state.moreHosts).toLocaleString();
  }

  function nodeFor(addr) {
    if (addr === state.local) return state.localNode;
    return state.nodes.get(addr) || null;
  }

  const ringFactor = [0.52, 0.78, 1];
  function pos(n) {
    const cx = state.w / 2, cy = state.h / 2;
    if (n.local) return { x: cx, y: cy };
    const rx = state.w / 2 - 86, ry = state.h / 2 - 46;
    const angle = n.slot * 2.39996 + 0.6;          // golden angle keeps hosts evenly spread
    const ring = ringFactor[n.slot % 3];
    return { x: cx + Math.cos(angle) * rx * ring, y: cy + Math.sin(angle) * ry * ring };
  }

  function radius(n) {
    const max = Math.max(1, state.localNode.bytes || 1);
    return n.local ? 15 : 6 + 9 * Math.sqrt(Math.min(1, (n.bytes || 0) / max));
  }

  /* ================= map: packets in flight ================= */
  function spawn(fresh) {
    let list = fresh;
    if (list.length > 90) { const k = Math.ceil(list.length / 90); list = list.filter((_, i) => i % k === 0); }
    const now = performance.now();
    list.forEach((p) => {
      if (state.filter !== "all" && p.protocol !== state.filter) return;
      const a = nodeFor(p.src), b = nodeFor(p.dst);
      if (!a || !b || a === b) return;
      state.particles.push({
        a, b, color: protoColor(p.protocol), size: 2 + Math.min(2.5, p.length / 600),
        t0: now + Math.random() * POLL_MS * 0.9,
        dur: REDUCED ? 300 : 800 + Math.random() * 600,
      });
    });
    if (state.particles.length > MAX_PARTICLES) state.particles.splice(0, state.particles.length - MAX_PARTICLES);
  }

  function control(pa, pb, a, b) {
    const mx = (pa.x + pb.x) / 2, my = (pa.y + pb.y) / 2;
    const dx = pb.x - pa.x, dy = pb.y - pa.y;
    const side = ((a.slot || 0) + (b.slot || 0)) % 2 ? 1 : -1;
    return { x: mx - dy * 0.16 * side, y: my + dx * 0.16 * side };
  }

  const bez = (p0, c, p1, t) => {
    const u = 1 - t;
    return { x: u * u * p0.x + 2 * u * t * c.x + t * t * p1.x, y: u * u * p0.y + 2 * u * t * c.y + t * t * p1.y };
  };

  const alive = (n) => n.local || state.nodes.get(n.addr) === n;
  let lastTs = 0;

  function draw(ts) {
    const { w, h } = state;
    if (!w || !h) return;
    const dt = Math.min(64, ts - lastTs || 16);
    lastTs = ts;
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2, cy = h / 2;
    const rx = w / 2 - 86, ry = h / 2 - 46;

    // chart rings
    ctx.save();
    ctx.setLineDash([2, 7]);
    ctx.strokeStyle = "rgba(217,238,247,.16)";
    ctx.lineWidth = 1;
    ringFactor.forEach((f) => { ctx.beginPath(); ctx.ellipse(cx, cy, rx * f, ry * f, 0, 0, Math.PI * 2); ctx.stroke(); });
    ctx.restore();

    // sonar + sweep around this machine
    if (!REDUCED && state.local) {
      const reach = Math.max(rx, ry) * 1.05;
      for (let k = 0; k < 3; k++) {
        const phase = ((ts / 4200) + k / 3) % 1;
        ctx.beginPath();
        ctx.arc(cx, cy, phase * reach, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(120,215,255,${(1 - phase) * 0.28})`;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
      if (ctx.createConicGradient) {
        const g = ctx.createConicGradient(ts / 2600, cx, cy);
        g.addColorStop(0, "rgba(120,215,255,.0)");
        g.addColorStop(0.9, "rgba(120,215,255,.0)");
        g.addColorStop(1, "rgba(120,215,255,.22)");
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, reach, 0, Math.PI * 2); ctx.fill();
      }
    }

    // edges that have recently carried traffic
    state.edges.forEach((e, key) => {
      if (!alive(e.a) || !alive(e.b) || e.v < 0.02) { state.edges.delete(key); return; }
      const pa = pos(e.a), pb = pos(e.b), c = control(pa, pb, e.a, e.b);
      ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.quadraticCurveTo(c.x, c.y, pb.x, pb.y);
      ctx.strokeStyle = `rgba(217,238,247,${Math.min(0.5, e.v * 0.5)})`;
      ctx.lineWidth = 1;
      ctx.stroke();
      e.v *= Math.pow(0.9992, dt);
    });

    // packet being inspected in the log
    if (state.selected) {
      const a = nodeFor(state.selected.src), b = nodeFor(state.selected.dst);
      if (a && b && a !== b) {
        const pa = pos(a), pb = pos(b), c = control(pa, pb, a, b);
        ctx.save();
        ctx.setLineDash([6, 6]); ctx.lineDashOffset = -ts / 50;
        ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.quadraticCurveTo(c.x, c.y, pb.x, pb.y);
        ctx.strokeStyle = "rgba(255,255,255,.9)"; ctx.lineWidth = 1.6; ctx.stroke();
        ctx.restore();
      }
    }

    // comets
    ctx.globalCompositeOperation = "lighter";
    let keep = 0;
    for (let i = 0; i < state.particles.length; i++) {
      const p = state.particles[i];
      const t = (ts - p.t0) / p.dur;
      if (t >= 1) {
        if (alive(p.b)) {
          p.b.pulse = 1;
          const key = p.a.addr < p.b.addr ? `${p.a.addr}|${p.b.addr}` : `${p.b.addr}|${p.a.addr}`;
          const e = state.edges.get(key) || { a: p.a, b: p.b, v: 0 };
          e.v = Math.min(1, e.v + 0.22);
          state.edges.set(key, e);
        }
        continue;
      }
      state.particles[keep++] = p;
      if (t < 0 || !alive(p.a) || !alive(p.b)) continue;
      const pa = pos(p.a), pb = pos(p.b), c = control(pa, pb, p.a, p.b);
      ctx.fillStyle = p.color;
      for (let k = 0; k < 7; k++) {
        const tt = t - k * 0.022;
        if (tt < 0) break;
        const q = bez(pa, c, pb, REDUCED ? 1 : tt);
        ctx.globalAlpha = (1 - k / 7) * (REDUCED ? 1 - t : 0.95);
        ctx.beginPath(); ctx.arc(q.x, q.y, p.size * (1 - k * 0.1), 0, Math.PI * 2); ctx.fill();
      }
    }
    state.particles.length = keep;
    ctx.globalAlpha = 1;
    ctx.globalCompositeOperation = "source-over";

    // hosts
    const drawNode = (n) => {
      const { x, y } = pos(n), r = radius(n);
      const col = protoColor(n.proto);
      if (n.pulse > 0) {
        ctx.beginPath(); ctx.arc(x, y, r + (1 - n.pulse) * 16, 0, Math.PI * 2);
        ctx.strokeStyle = col; ctx.globalAlpha = n.pulse * 0.8; ctx.lineWidth = 2; ctx.stroke(); ctx.globalAlpha = 1;
        n.pulse = Math.max(0, n.pulse - dt / 550);
      }
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = n.local ? "#e9f7fd" : "#0f3a52"; ctx.fill();
      ctx.lineWidth = n.local ? 3 : 2.5; ctx.strokeStyle = n.local ? "#78d7ff" : col; ctx.stroke();
      if (n.local) { ctx.beginPath(); ctx.arc(x, y, 5, 0, Math.PI * 2); ctx.fillStyle = "#0b2c40"; ctx.fill(); }
      if (state.hover === n) { ctx.beginPath(); ctx.arc(x, y, r + 5, 0, Math.PI * 2); ctx.strokeStyle = "#fff"; ctx.lineWidth = 1.5; ctx.stroke(); }

      ctx.font = `${n.local ? 600 : 400} ${n.local ? 13 : 11.5}px "IBM Plex Mono", monospace`;
      ctx.textAlign = "center";
      ctx.fillStyle = n.local ? "#ffffff" : "rgba(217,238,247,.85)";
      ctx.fillText(shorten(n.addr, 22), x, y + r + 16);
      if (n.local) { ctx.fillStyle = "rgba(217,238,247,.65)"; ctx.fillText("this machine", x, y + r + 31); }
    };
    state.nodes.forEach(drawNode);
    if (state.local) drawNode(state.localNode);

    if (state.moreHosts > 0) {
      ctx.font = '12px "Bricolage Grotesque", sans-serif';
      ctx.textAlign = "left"; ctx.fillStyle = "rgba(217,238,247,.6)";
      ctx.fillText(`+${state.moreHosts} quieter hosts not drawn`, 18, h - 16);
    }
    localNodePulseGuard();
  }

  function localNodePulseGuard() { if (!state.local) state.localNode.pulse = 0; }

  function loop(ts) { draw(ts); requestAnimationFrame(loop); }

  /* ================= map: size + hover ================= */
  function resize() {
    const dpr = window.devicePixelRatio || 1;
    state.w = el.map.clientWidth;
    state.h = el.map.clientHeight;
    el.canvas.width = state.w * dpr;
    el.canvas.height = state.h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    drawSpark(el.spPackets, state.timeline.map((d) => d.packets), cssVar("--c-tcp"));
    drawSpark(el.spBytes, state.timeline.map((d) => d.bytes), cssVar("--c-https"));
  }
  new ResizeObserver(resize).observe(el.map);

  function hitTest(x, y) {
    const all = [...state.nodes.values()];
    if (state.local) all.push(state.localNode);
    return all.find((n) => { const p = pos(n); return Math.hypot(p.x - x, p.y - y) <= radius(n) + 7; }) || null;
  }

  el.canvas.addEventListener("mousemove", (e) => {
    const r = el.canvas.getBoundingClientRect();
    const x = e.clientX - r.left, y = e.clientY - r.top;
    const n = hitTest(x, y);
    state.hover = n;
    el.canvas.style.cursor = n && !n.local ? "pointer" : "default";
    if (!n) { el.tip.hidden = true; return; }
    el.tip.replaceChildren();
    el.tip.append(
      node("b", "", n.addr),
      node("span", "", `${n.local ? "This machine · " : ""}${n.pkts.toLocaleString()} packets · ${formatBytes(n.bytes)}`),
    );
    el.tip.hidden = false;
    el.tip.style.left = `${Math.min(x + 16, state.w - 270)}px`;
    el.tip.style.top = `${Math.max(8, y - 12)}px`;
  });
  el.canvas.addEventListener("mouseleave", () => { state.hover = null; el.tip.hidden = true; });
  el.canvas.addEventListener("click", (e) => {
    const r = el.canvas.getBoundingClientRect();
    const n = hitTest(e.clientX - r.left, e.clientY - r.top);
    if (n) filterByHost(n.addr);
  });

  /* ================= polling ================= */
  async function refresh() {
    try {
      const [stats, status, data] = await Promise.all([
        api("/api/stats"), api("/api/capture/status"), api(`/api/packets?limit=${MAX_ROWS}`),
      ]);
      renderStats(stats);
      renderStatus(status);

      const packets = data.packets;
      if (packets.length && packets[0].id < state.lastId) state.lastId = 0;   // server restarted
      const fresh = packets.filter((p) => p.id > state.lastId).reverse();
      if (packets.length) state.lastId = packets[0].id;

      state.packets = packets;
      updateNodes(packets);
      spawn(fresh);
      el.hint.hidden = packets.length > 0;
      renderTable();
      if (status.error && status.running) showError(status.error);
    } catch (err) {
      el.statusText.textContent = "Cannot reach the server";
    }
  }

  loadInterfaces();
  resize();
  refresh();
  setInterval(refresh, POLL_MS);
  requestAnimationFrame(loop);
})();
