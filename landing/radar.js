/* Radius radar: a tilted scope with a rotating sweep. Blips are the
 * reported combat events (colored by severity), diamonds are tracked
 * cities, the square is your position. Canvas-only decoration; the
 * analysis list next to it is plain HTML and works without scripting.
 * Pauses off screen and under reduced motion. */
(function () {
  const cv = document.getElementById("radar");
  if (!cv) return;
  const ctx = cv.getContext("2d");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // oklch(L% C H) -> [r,g,b] 0..1, enough for canvas fills
  function oklchToRgb(l, c, h) {
    const hr = (h * Math.PI) / 180, a = c * Math.cos(hr), b = c * Math.sin(hr);
    const L = l + 0.3963377774 * a + 0.2158037573 * b;
    const M = l - 0.1055613458 * a - 0.0638541728 * b;
    const S = l - 0.0894841775 * a - 1.2914855480 * b;
    const l3 = L * L * L, m3 = M * M * M, s3 = S * S * S;
    let r = 4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3;
    let g = -1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3;
    let bl = -0.0041960863 * l3 - 0.7034186147 * m3 + 1.7076147010 * s3;
    const gam = (v) => (v <= 0.0031308 ? 12.92 * v : 1.055 * Math.pow(v, 1 / 2.4) - 0.055);
    return [gam(r), gam(g), gam(bl)].map((v) => Math.max(0, Math.min(1, v)));
  }
  function cssVar(name) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const m = v.match(/oklch\(([^)]+)\)/);
    if (!m) return [0.8, 0.8, 0.8];
    const p = m[1].split(/\s+/);
    return oklchToRgb(parseFloat(p[0]) / 100, parseFloat(p[1]), parseFloat(p[2]));
  }
  const COL = {
    ring: cssVar("--color-rule-2"), muted: cssVar("--color-muted"),
    hi: cssVar("--point-hi"), mid: cssVar("--point-mid"),
    accent: cssVar("--color-accent"),
    c1: cssVar("--lvl-1"), c2: cssVar("--lvl-2"), c3: cssVar("--lvl-3"),
    c4: cssVar("--lvl-4"), c5: cssVar("--lvl-5"),
  };
  const rgb = (c, a) => `rgba(${c[0] * 255 | 0},${c[1] * 255 | 0},${c[2] * 255 | 0},${a})`;

  // Scope data: bearing in degrees clockwise from north, distance in km.
  // Mirrors the analysis list in the markup.
  const RANGE_KM = 520;
  const TILT = 0.42;                    // oblique view of the scope plane
  const EVENTS = [
    { d: 41.8, b: 35,  col: "c2" },
    { d: 92.4, b: 95,  col: "c3" },
    { d: 118,  b: 340, col: "c3" },
    { d: 156,  b: 260, col: "c4" },
    { d: 204,  b: 170, col: "c4" },
    { d: 260,  b: 50,  col: "c5" },
    { d: 310,  b: 300, col: "c5" },
  ];
  const CITIES = [
    { d: 430, b: 332, name: "Lviv" },
    { d: 445, b: 2,   name: "Kyiv" },
    { d: 150, b: 95,  name: "Kherson" },
  ];
  const RINGS = [130, 260, 390, 520];

  // bearing/distance -> screen point on the tilted plane
  function project(dKm, bDeg, cx, cy, R) {
    const br = (bDeg * Math.PI) / 180;
    const x = (dKm / RANGE_KM) * Math.sin(br);
    const y = (dKm / RANGE_KM) * Math.cos(br);
    return [cx + x * R, cy - y * R * TILT];
  }
  // map angle (radians, same convention as bearing) -> edge point
  function edgePoint(a, cx, cy, R) {
    return [cx + Math.cos(a) * R, cy - Math.sin(a) * R * TILT];
  }

  let W = 0, H = 0, dpr = 1;
  function resize() {
    const r = cv.getBoundingClientRect();
    dpr = Math.min(2, window.devicePixelRatio || 1);
    W = Math.max(1, r.width | 0); H = Math.max(1, r.height | 0);
    cv.width = W * dpr; cv.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  new ResizeObserver(resize).observe(cv);

  const sweepPeriod = 4200;             // ms per revolution
  let sweep = 0.6, last = 0, raf = 0, running = true, visible = true;
  const hits = EVENTS.map(() => -1e9);

  function angDiff(a, b) {
    let d = (a - b) % (Math.PI * 2);
    if (d > Math.PI) d -= Math.PI * 2;
    if (d < -Math.PI) d += Math.PI * 2;
    return Math.abs(d);
  }

  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000 || 0.016);
    last = now;
    sweep = (sweep + (dt * Math.PI * 2 * 1000) / sweepPeriod) % (Math.PI * 2);

    ctx.clearRect(0, 0, W, H);
    const cx = W / 2, cy = H * 0.54, R = Math.min(W, H) * 0.44;

    // range rings + km labels
    ctx.font = "10px ui-monospace, Menlo, monospace";
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    for (const km of RINGS) {
      const rr = (km / RANGE_KM) * R;
      ctx.beginPath();
      ctx.ellipse(cx, cy, rr, rr * TILT, 0, 0, Math.PI * 2);
      ctx.strokeStyle = rgb(COL.ring, 0.55);
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.fillStyle = rgb(COL.muted, 0.8);
      ctx.fillText(String(km), cx + rr * 0.86, cy - rr * TILT * 0.86 - 7);
    }
    // axis cross inside the scope
    ctx.strokeStyle = rgb(COL.ring, 0.3);
    ctx.beginPath();
    ctx.ellipse(cx, cy, R, R * TILT, 0, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy);
    ctx.moveTo(cx, cy - R * TILT); ctx.lineTo(cx, cy + R * TILT);
    ctx.stroke();

    // sweep trail: thin sheared pie slices fading behind the beam
    const TRAIL = 1.15, SLICES = 42;
    ctx.globalCompositeOperation = "lighter";
    for (let i = SLICES; i >= 1; i--) {
      const a1 = sweep - (i / SLICES) * TRAIL;
      const a2 = sweep - ((i - 1) / SLICES) * TRAIL;
      const k = 1 - i / SLICES;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      const [x1, y1] = edgePoint(a1, cx, cy, R);
      const [x2, y2] = edgePoint(a2, cx, cy, R);
      ctx.lineTo(x1, y1); ctx.lineTo(x2, y2);
      ctx.closePath();
      ctx.fillStyle = rgb(COL.hi, 0.028 + 0.075 * k * k);
      ctx.fill();
    }
    // leading edge
    const [ex, ey] = edgePoint(sweep, cx, cy, R);
    ctx.strokeStyle = rgb(COL.accent, 0.75);
    ctx.lineWidth = 1.4;
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(ex, ey); ctx.stroke();
    ctx.globalCompositeOperation = "source-over";

    // event blips: flash when the sweep crosses their bearing
    for (let i = 0; i < EVENTS.length; i++) {
      const e = EVENTS[i];
      const bRad = ((90 - e.b) * Math.PI) / 180;   // bearing -> math angle
      if (angDiff(bRad, sweep) < 0.045) hits[i] = now;
      const age = (now - hits[i]) / 1000;
      const flash = Math.max(0, 1 - age / 2.6);
      const [px, py] = project(e.d, e.b, cx, cy, R);
      const col = COL[e.col];
      ctx.fillStyle = rgb(col, 0.32 + 0.6 * flash);
      ctx.beginPath(); ctx.arc(px, py, 1.8 + flash * 1.6, 0, Math.PI * 2); ctx.fill();
      if (flash > 0.35) {
        ctx.strokeStyle = rgb(col, flash * 0.5);
        ctx.beginPath(); ctx.arc(px, py, 4 + flash * 5, 0, Math.PI * 2); ctx.stroke();
      }
    }

    // tracked cities: diamonds
    for (const c of CITIES) {
      const [px, py] = project(c.d, c.b, cx, cy, R);
      ctx.fillStyle = rgb(COL.accent, 0.85);
      ctx.beginPath();
      ctx.moveTo(px, py - 4); ctx.lineTo(px + 4, py);
      ctx.lineTo(px, py + 4); ctx.lineTo(px - 4, py);
      ctx.closePath(); ctx.fill();
      ctx.fillStyle = rgb(COL.muted, 0.75);
      ctx.font = "10px ui-monospace, Menlo, monospace";
      ctx.fillText(c.name, px + 8, py - 6);
    }

    // own position
    ctx.fillStyle = rgb(COL.hi, 0.95);
    ctx.fillRect(cx - 3, cy - 3, 6, 6);
    ctx.strokeStyle = rgb(COL.hi, 0.5);
    ctx.beginPath(); ctx.arc(cx, cy, 8, 0, Math.PI * 2); ctx.stroke();
    ctx.fillStyle = rgb(COL.muted, 0.8);
    ctx.fillText("you", cx + 12, cy + 4);

    if (running && visible && !reduced) raf = requestAnimationFrame(frame);
  }

  if (reduced) {
    for (let i = 0; i < EVENTS.length; i++) hits[i] = performance.now() - 600;
    frame(performance.now());
  } else {
    raf = requestAnimationFrame(frame);
  }

  new IntersectionObserver(([e]) => {
    visible = e.isIntersecting;
    if (visible && running && !reduced && !raf) raf = requestAnimationFrame(frame);
    if (!visible && raf) { cancelAnimationFrame(raf); raf = 0; }
  }).observe(cv);
})();
