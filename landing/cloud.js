/* Vantage point cloud: measured points on a blue-black ground.
 * Slow turn, a sweep that lifts what it crosses, a few lime points
 * for what was found. Canvas pauses off screen and under reduced motion. */
(function () {
  const cv = document.getElementById("cloud");
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
    lo: cssVar("--point-lo"), mid: cssVar("--point-mid"),
    hi: cssVar("--point-hi"), accent: cssVar("--color-accent"),
  };
  const rgb = (c, a) => `rgba(${c[0] * 255 | 0},${c[1] * 255 | 0},${c[2] * 255 | 0},${a})`;

  // heightfield: a low ridge of points, like terrain seen at an angle
  const N = 5200;
  const pts = [];
  const found = new Set();
  for (let i = 0; i < N; i++) {
    const x = Math.random() * 2 - 1;
    const z = Math.random() * 2 - 1;
    const d = Math.hypot(x * 0.82, z * 1.35);
    if (d > 1) continue;
    const h =
      0.16 * Math.sin(x * 3.1 + 0.6) * Math.cos(z * 2.3) +
      0.11 * Math.sin(x * 6.7 - z * 3.9) +
      0.07 * Math.sin((x + z) * 9.0) +
      0.05 * Math.cos(x * 11.0);
    pts.push({ x, z, h, s: 0.6 + Math.random() * 0.9, ph: Math.random() * 6.28 });
  }
  // a handful of points marked "found" — lime, like contacts online
  for (let i = 0; i < 9 && pts.length; i++) {
    found.add(Math.floor(Math.random() * pts.length));
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

  let ang = 0.6, sweep = -1.4, last = 0, raf = 0, running = true, visible = true;
  const sweepSpeed = (Math.PI * 2) / 7000;   // a pass every ~7s
  const turnSpeed = (Math.PI * 2) / 120000;  // one revolution in two minutes

  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000 || 0.016);
    last = now;
    ang = (ang + turnSpeed * dt) % (Math.PI * 2);
    sweep += sweepSpeed * dt;
    if (sweep > 1.6) sweep = -1.6;

    ctx.clearRect(0, 0, W, H);
    const cx = W / 2, cy = H * 0.52, R = Math.min(W, H) * 0.46;
    const ca = Math.cos(ang), sa = Math.sin(ang);
    const t = now / 1000;

    for (let i = 0; i < pts.length; i++) {
      const p = pts[i];
      // rotate around vertical axis, slight tilt toward viewer
      const x1 = p.x * ca - p.z * sa;
      const z1 = p.x * sa + p.z * ca;
      const y1 = p.h - z1 * 0.16;                    // oblique view
      const depth = (z1 + 1) / 2;                    // 0 far .. 1 near
      const px = cx + x1 * R * 1.18;
      const py = cy - y1 * R * 0.72 - depth * R * 0.10;

      // edge falloff so the cloud dissolves into the paper
      const ex = (px - cx) / (R * 1.18), ey = (py - cy) / (R * 0.98);
      const edge = 1 - Math.min(1, Math.hypot(ex, ey) * 0.92);
      if (edge <= 0.02) continue;

      // sweep lifts points near the plane toward white
      const ds = Math.abs(x1 - sweep);
      const lift = Math.max(0, 1 - ds / 0.09);
      const isFound = found.has(i);

      let col;
      const th = Math.max(0, Math.min(1, (p.h + 0.32) / 0.62));
      if (isFound) col = COL.accent;
      else if (th < 0.5) col = lerp3(COL.lo, COL.mid, th * 2);
      else col = lerp3(COL.mid, COL.hi, (th - 0.5) * 2);
      if (lift > 0 && !isFound) col = lerp3(col, COL.hi, lift * 0.85);

      const tw = 0.75 + 0.25 * Math.sin(t * 0.0012 + p.ph);
      const alpha = edge * (0.25 + depth * 0.55) * tw * (isFound ? 0.95 : 1);
      const size = isFound ? 1.9 : 1.1 + depth * 0.9;
      ctx.fillStyle = rgb(col, Math.min(1, alpha));
      ctx.fillRect(px, py, size, size);
    }

    if (running && visible && !reduced) raf = requestAnimationFrame(frame);
  }
  function lerp3(a, b, t) {
    return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
  }

  if (reduced) {
    sweep = 0.25;
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
