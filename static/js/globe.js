/**
 * CyberGuard AI - Hero globe.
 * Loads the heavy map libraries after first paint so the page can show fast.
 */
(function () {
  const container = document.getElementById('globe-container');
  const canvas = document.getElementById('globe-canvas');
  if (!container || !canvas) return;

  let started = false;

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = src;
      script.async = true;

      const timer = setTimeout(() => {
        script.onload = null;
        script.onerror = null;
        reject(new Error(`Timeout while loading ${src}`));
      }, 4500);

      script.onload = () => {
        clearTimeout(timer);
        resolve();
      };
      script.onerror = () => {
        clearTimeout(timer);
        reject(new Error(`Failed to load ${src}`));
      };

      document.head.appendChild(script);
    });
  }

  function scheduleGlobe() {
    // The old blocking issue was NOT caused by loading d3/topojson (a cheap
    // async network fetch) - it was caused by the synchronous nested
    // lat/lon x d3.geoContains loop below that built the dot grid in one
    // long blocking pass. That loop is now time-sliced (see buildDotsAsync),
    // so there is no need to artificially delay the whole globe by 22s
    // anymore. We can start almost immediately after first paint.
    if ('requestIdleCallback' in window) {
      window.requestIdleCallback(startGlobe, { timeout: 1200 });
      return;
    }
    setTimeout(startGlobe, 300);
  }

  function startGlobe() {
    if (started) return;
    started = true;

    Promise.all([
      loadScript('https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js'),
      loadScript('https://unpkg.com/topojson-client@3'),
    ])
      .then(initGlobe)
      .catch(drawStaticFallback);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scheduleGlobe, { once: true });
  } else {
    scheduleGlobe();
  }

  drawStaticFallback();

  function getThemeColors() {
    const light = document.documentElement.getAttribute('data-theme') === 'light';
    return light
      ? {
          dotColor: '#334155',
          glowColor: 'rgba(15, 23, 42, 0.35)',
          graticuleColor: 'rgba(15, 23, 42, 0.14)',
        }
      : {
          dotColor: '#adc6ff',
          glowColor: 'rgba(173, 198, 255, 0.4)',
          graticuleColor: 'rgba(173, 198, 255, 0.12)',
        };
  }

  function drawStaticFallback() {
    const context = canvas.getContext('2d');
    const width = container.offsetWidth || 560;
    const height = container.offsetHeight || 560;
    const radius = Math.min(width, height) * 0.36;
    const centerX = width / 2;
    const centerY = height / 2;
    const colors = getThemeColors();

    canvas.width = width;
    canvas.height = height;
    context.clearRect(0, 0, width, height);
    context.beginPath();
    context.arc(centerX, centerY, radius, 0, Math.PI * 2);
    context.strokeStyle = colors.graticuleColor;
    context.lineWidth = 1;
    context.stroke();

    for (let i = 0; i < 150; i += 1) {
      const angle = i * 2.399963;
      const distance = radius * Math.sqrt(i / 150);
      const x = centerX + Math.cos(angle) * distance;
      const y = centerY + Math.sin(angle) * distance * 0.86;
      context.beginPath();
      context.arc(x, y, 1.25, 0, Math.PI * 2);
      context.fillStyle = colors.dotColor;
      context.globalAlpha = 0.7;
      context.fill();
    }
    context.globalAlpha = 1;
  }

  function initGlobe() {
    if (typeof d3 === 'undefined' || typeof topojson === 'undefined') {
      drawStaticFallback();
      return;
    }

    const context = canvas.getContext('2d');
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const isSmallScreen = window.innerWidth < 768;
    const config = {
      dotDensity: isSmallScreen ? 18 : 28,
      dotRadius: 1.25,
      baseRotationSpeed: reduceMotion ? 0 : 0.1,
      inertiaFactor: 0.94,
      zoomMin: 0.6,
      zoomMax: 2.5,
      zoomTransitionSpeed: 0.15,
      ...getThemeColors(),
    };

    let width = 0;
    let height = 0;
    let baseScale = 0;
    let currentScale = 0;
    let targetScale = 0;
    let velocity = [config.baseRotationSpeed, 0];
    let isDragging = false;
    let autoRotate = true;
    let autoRotateTimer = null;

    const projection = d3.geoOrthographic().precision(0.1).rotate([0, -15, 0]);
    const path = d3.geoPath(projection, context);
    const graticule = d3.geoGraticule().step([10, 10]);

    function resize() {
      width = container.offsetWidth || 560;
      height = container.offsetHeight || 560;
      canvas.width = width;
      canvas.height = height;
      baseScale = Math.min(width, height) / 2.6;
      currentScale = baseScale;
      targetScale = currentScale;
      projection.translate([width / 2, height / 2]).scale(currentScale);
    }

    window.addEventListener('resize', resize);
    window.addEventListener('cg:themechange', () => Object.assign(config, getThemeColors()));
    resize();

    if (!reduceMotion) {
      d3.select(canvas).call(
        d3.zoom()
          .scaleExtent([config.zoomMin, config.zoomMax])
          .on('zoom', (event) => {
            targetScale = baseScale * event.transform.k;
          })
      );
    }

    fetchWorldJson('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
      .then((world) => {
        const land = topojson.feature(world, world.objects.countries);
        const dots = [];
        const step = config.dotDensity / 10;

        // Render loop + interactions are wired up immediately so the globe
        // is draggable/rotating right away, while dots are filled in
        // progressively in the background (see buildDotsAsync below).
        // This is what actually fixes the page-blocking bug: the previous
        // code ran this whole nested loop with ~8000 d3.geoContains checks
        // synchronously in a single pass, which froze the main thread.

        const drag = d3.drag()
          .on('start', () => {
            isDragging = true;
            autoRotate = false;
            if (autoRotateTimer) clearTimeout(autoRotateTimer);
            velocity = [0, 0];
          })
          .on('drag', (event) => {
            const k = 75 / projection.scale();
            velocity = [event.dx * k, event.dy * k];
            const rotate = projection.rotate();
            projection.rotate([rotate[0] + velocity[0], rotate[1] - velocity[1]]);
          })
          .on('end', () => {
            isDragging = false;
            autoRotateTimer = setTimeout(() => { autoRotate = true; }, 3000);
          });

        d3.select(canvas).call(drag);

        // Physics runs every animation-frame tick so the rotation speed and
        // inertia feel are completely unchanged. Only the actual canvas
        // repaint (the expensive part: clearing the canvas and redrawing
        // hundreds of dots with shadowBlur) is throttled to ~30fps instead
        // of ~60fps. At this rotation speed the difference is invisible,
        // but it frees up roughly half of the main-thread time every
        // second for the rest of the page's animations.
        let frameCount = 0;

        function render() {
          frameCount++;

          if (!isDragging) {
            velocity[0] *= config.inertiaFactor;
            velocity[1] *= config.inertiaFactor;
            if (autoRotate) {
              velocity[0] += (config.baseRotationSpeed - velocity[0]) * 0.05;
              velocity[1] *= 0.95;
            }
            const currentRotate = projection.rotate();
            const targetX = currentRotate[0] + velocity[0];
            const targetY = Math.max(-80, Math.min(80, currentRotate[1] - velocity[1]));
            projection.rotate([targetX, targetY]);
          }

          if (Math.abs(currentScale - targetScale) > 0.1) {
            currentScale += (targetScale - currentScale) * config.zoomTransitionSpeed;
            projection.scale(currentScale);
          }

          if (frameCount % 2 === 0) {
            context.clearRect(0, 0, width, height);

            const center = projection.invert([width / 2, height / 2]);
            context.beginPath();
            path(graticule());
            context.strokeStyle = config.graticuleColor;
            context.lineWidth = 0.5;
            context.stroke();

            dots.forEach((dot) => {
              const distance = d3.geoDistance(dot, center);
              if (distance >= Math.PI / 2) return;

              const coords = projection(dot);
              const opacity = Math.pow(Math.cos(distance), 0.6);
              context.beginPath();
              context.arc(coords[0], coords[1], config.dotRadius, 0, 2 * Math.PI);
              context.fillStyle = config.dotColor;
              context.globalAlpha = opacity;
              context.shadowBlur = opacity > 0.8 && !isSmallScreen ? 3 : 0;
              context.shadowColor = config.glowColor;
              context.fill();
              context.shadowBlur = 0;
            });
            context.globalAlpha = 1;
          }

          requestAnimationFrame(render);
        }

        requestAnimationFrame(render);
        buildDotsAsync(land, step, dots);
      })
      .catch(drawStaticFallback);
  }

  // Builds the lat/lon dot grid in small time-sliced batches instead of one
  // long synchronous loop, so d3.geoContains (the expensive part) never
  // blocks the main thread for more than a few milliseconds at a time.
  // This is the actual fix for the "3D figure freezes the whole page" bug.
  function buildDotsAsync(land, step, dots) {
    const lats = [];
    for (let lat = -90; lat <= 90; lat += step) lats.push(lat);
    let latIndex = 0;

    function processChunk(deadline) {
      const hasTimeLeft = () =>
        deadline && typeof deadline.timeRemaining === 'function'
          ? deadline.timeRemaining() > 0
          : true;

      let rowsThisChunk = 0;
      while (latIndex < lats.length && rowsThisChunk < 4 && hasTimeLeft()) {
        const lat = lats[latIndex];
        for (let lon = -180; lon <= 180; lon += step) {
          if (d3.geoContains(land, [lon, lat])) dots.push([lon, lat]);
        }
        latIndex += 1;
        rowsThisChunk += 1;
      }

      if (latIndex < lats.length) {
        scheduleChunk();
      }
    }

    function scheduleChunk() {
      if ('requestIdleCallback' in window) {
        window.requestIdleCallback(processChunk, { timeout: 200 });
      } else {
        setTimeout(() => processChunk(null), 0);
      }
    }

    scheduleChunk();
  }

  function fetchWorldJson(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);

    return fetch(url, {
      cache: 'force-cache',
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error(`World map failed: ${response.status}`);
        return response.json();
      })
      .finally(() => clearTimeout(timer));
  }
})();
