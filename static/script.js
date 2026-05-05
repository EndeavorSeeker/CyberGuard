// ═══════════════════════════════════════
//  TAB SWITCHING
// ═══════════════════════════════════════

function showModule(name) {
  // Cache all modules and tabs
  const modules = document.querySelectorAll('.module');
  const tabs    = document.querySelectorAll('.nav-tab');

  // Hide all modules
  modules.forEach(m => m.classList.remove('active'));

  // Remove active from all tabs
  tabs.forEach(t => t.classList.remove('active'));

  // Show selected module
  document.getElementById('module-' + name).classList.add('active');

  // Highlight selected tab
  const tabIndex = { url: 0, log: 1, trust: 2 };
  tabs[tabIndex[name]].classList.add('active');
}


// ═══════════════════════════════════════
//  SKELETON LOADER (shown while waiting)
// ═══════════════════════════════════════

function showSkeleton(zone) {
  zone.innerHTML = `
    <div class="skeleton">
      <div class="skeleton-line short"></div>
      <div class="skeleton-line full"></div>
      <div class="skeleton-line mid"></div>
      <div class="skeleton-line full"></div>
    </div>
  `;
}


// ═══════════════════════════════════════
//  ERROR CARD
// ═══════════════════════════════════════

function showError(zone, message) {
  zone.innerHTML = `
    <div class="error-card">
      ⚠️ ${message}
    </div>
  `;
}


// ═══════════════════════════════════════
//  RESULT CARD BUILDER
// ═══════════════════════════════════════

function getLevel(score) {
  if (score >= 70) return 'danger';
  if (score >= 40) return 'warn';
  return 'safe';
}

function getLevelLabel(score) {
  if (score >= 70) return '🔴 High Risk';
  if (score >= 40) return '🟠 Medium Risk';
  return '🟢 Safe';
}

function buildResultCard(data) {
  const level      = getLevel(data.score);
  const levelLabel = getLevelLabel(data.score);

  return `
    <div class="result-card ${level}">

      <div class="result-top">
        <span class="result-title">Analysis Result</span>
        <span class="badge badge-${level === 'danger' ? 'red' : level === 'warn' ? 'orange' : 'green'}">
          ${levelLabel}
        </span>
      </div>

      <div class="metrics">

        <div class="metric">
          <div class="metric-label">Threat Score</div>
          <div class="metric-value ${level}">${data.score}%</div>
          <div class="score-bar-wrap">
            <div class="score-bar ${level}" id="bar-anim" style="width:0%"></div>
          </div>
        </div>

        <div class="metric">
          <div class="metric-label">Category</div>
          <div class="metric-value" style="font-size:16px">${data.category}</div>
        </div>

        <div class="metric">
          <div class="metric-label">Confidence</div>
          <div class="metric-value">${data.confidence}%</div>
        </div>

      </div>

      <div class="result-explanation">
        ${data.explanation}
      </div>

    </div>
  `;
}


// ═══════════════════════════════════════
//  ANIMATE SCORE BAR
// ═══════════════════════════════════════

function animateBar(score) {
  // Small delay so the DOM is ready
  setTimeout(() => {
    const bar = document.getElementById('bar-anim');
    if (bar) bar.style.width = score + '%';
  }, 100);
}


// ═══════════════════════════════════════
//  MODULE 1 — URL SHIELD
// ═══════════════════════════════════════

async function analyzeURL() {
  const input  = document.getElementById('url-input');
  const zone   = document.getElementById('url-result');
  const url    = input.value.trim();

  // Validation
  if (!url) {
    showError(zone, 'Please enter a URL before analyzing.');
    return;
  }

  // Show loader
  showSkeleton(zone);

  try {
    // ── Real API call (uncomment when Flask is ready) ──
    // const res  = await fetch('/api/url-shield', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify({ url: url })
    // });
    // const data = await res.json();

    // ── Mock data for testing without Flask ──
    await wait(1200);
    const data = mockURLResult(url);

    // Show result
    zone.innerHTML = buildResultCard(data);
    animateBar(data.score);

  } catch (err) {
    showError(zone, 'Could not connect to the server. Make sure Flask is running.');
  }
}


// ═══════════════════════════════════════
//  MODULE 2 — LOG SENTINEL
// ═══════════════════════════════════════

async function analyzeLog() {
  const input = document.getElementById('log-input');
  const zone  = document.getElementById('log-result');
  const logs  = input.value.trim();

  if (!logs) {
    showError(zone, 'Please paste some log entries before analyzing.');
    return;
  }

  showSkeleton(zone);

  try {
    // ── Real API call ──
    // const res  = await fetch('/api/log-sentinel', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify({ logs: logs })
    // });
    // const data = await res.json();

    // ── Mock data ──
    await wait(1400);
    const data = mockLogResult(logs);

    zone.innerHTML = buildResultCard(data);
    animateBar(data.score);

  } catch (err) {
    showError(zone, 'Could not connect to the server. Make sure Flask is running.');
  }
}


// ═══════════════════════════════════════
//  MODULE 3 — TRUSTCHECK
// ═══════════════════════════════════════

async function analyzeTrust() {
  const input   = document.getElementById('trust-input');
  const zone    = document.getElementById('trust-result');
  const message = input.value.trim();

  if (!message) {
    showError(zone, 'Please paste a message before checking.');
    return;
  }

  showSkeleton(zone);

  try {
    // ── Real API call ──
    // const res  = await fetch('/api/trustcheck', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify({ message: message })
    // });
    // const data = await res.json();

    // ── Mock data ──
    await wait(1300);
    const data = mockTrustResult(message);

    zone.innerHTML = buildResultCard(data);
    animateBar(data.score);

  } catch (err) {
    showError(zone, 'Could not connect to the server. Make sure Flask is running.');
  }
}


// ═══════════════════════════════════════
//  MOCK DATA (remove when Flask is ready)
// ═══════════════════════════════════════

function mockURLResult(url) {
  const suspicious = url.includes('paypal') || url.includes('verify') ||
                     url.includes('login')  || url.includes('secure') ||
                     url.includes('.ru')    || url.includes('bit.ly');

  if (suspicious) {
    return {
      score:       91,
      confidence:  97,
      category:    'Phishing',
      explanation: 'This URL contains suspicious patterns: typosquatting, ' +
                   'misleading domain, no valid HTTPS certificate. ' +
                   'It matches known phishing kits targeting banking users.'
    };
  }
  return {
    score:       12,
    confidence:  94,
    category:    'Legitimate',
    explanation: 'No suspicious patterns detected. Domain is reputable, ' +
                 'certificate is valid, and URL structure appears normal.'
  };
}

function mockLogResult(logs) {
  const failCount = (logs.match(/FAILED/gi) || []).length;

  if (failCount >= 3) {
    return {
      score:       78,
      confidence:  91,
      category:    'Brute Force',
      explanation: `Detected ${failCount} repeated failed login attempts in a short ` +
                   'time window from a single IP. This pattern is consistent with ' +
                   'an automated brute-force attack targeting privileged accounts.'
    };
  }
  if (failCount > 0) {
    return {
      score:       44,
      confidence:  80,
      category:    'Suspicious',
      explanation: 'A small number of failed login events detected. ' +
                   'Could be a user error or early-stage attack. Monitor closely.'
    };
  }
  return {
    score:       8,
    confidence:  96,
    category:    'Normal',
    explanation: 'No anomalies detected in these log entries. ' +
                 'All events appear to be within normal operational patterns.'
  };
}

function mockTrustResult(message) {
  const urgencyWords = ['immediately', 'urgent', 'expire', 'suspend', 'verify',
                        'click here', 'act now', 'compromised', 'deleted'];
  const hits = urgencyWords.filter(w => message.toLowerCase().includes(w)).length;

  if (hits >= 2) {
    return {
      score:       89,
      confidence:  95,
      category:    'Social Engineering',
      explanation: `Detected ${hits} manipulation signals: artificial urgency, ` +
                   'fear-based language, and a suspicious call-to-action link. ' +
                   'This is a classic social engineering pattern.'
    };
  }
  if (hits === 1) {
    return {
      score:       42,
      confidence:  78,
      category:    'Suspicious',
      explanation: 'Some potentially manipulative language detected. ' +
                   'Verify the sender identity before taking any action.'
    };
  }
  return {
    score:       9,
    confidence:  92,
    category:    'Trustworthy',
    explanation: 'No manipulation patterns detected. The message appears ' +
                 'to be legitimate. Always verify sender identity independently.'
  };
}


// ═══════════════════════════════════════
//  UTILITY
// ═══════════════════════════════════════

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}