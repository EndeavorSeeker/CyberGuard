/* ═══════════════════════════════════════════════════════════
   CYBERGUARD AI — app.js
   Author: Ayman
   Stack: Vanilla JS · Flask REST API

   FLASK ENDPOINTS (ready to connect):
     POST /api/url-shield    { data: url }
     POST /api/log-sentinel  { data: logText }
     POST /api/trustcheck    { data: messageText }

   FLASK RESPONSE FORMAT:
     {
       score:       number (0–100),
       level:       "safe" | "suspicious" | "dangerous",
       category:    string,
       explanation: string
     }
═══════════════════════════════════════════════════════════ */

'use strict';

/* ───────────────────────────────────────────────────────────
   STATE
─────────────────────────────────────────────────────────── */
const state = {
  currentModule:      'url',          // 'url' | 'logs' | 'msg'
  isLoading:          false,
  lastResult:         null,           // stores last API result
  explanationMode:    'technical',    // 'technical' | 'human'
};

/* ───────────────────────────────────────────────────────────
   FLASK API ENDPOINTS
   → Uncomment the real fetch() block inside analyzeNow()
     and remove the mock call once Flask is running.
─────────────────────────────────────────────────────────── */
const API_ENDPOINTS = {
  url:  '/api/url-shield',
  logs: '/api/log-sentinel',
  msg:  '/api/trustcheck',
};

/* ───────────────────────────────────────────────────────────
   MOCK DATA (used when Flask is not connected)
─────────────────────────────────────────────────────────── */
const MOCK_RESPONSES = {
  url: {
    phishing: {
      score: 94,
      level: 'dangerous',
      category: 'Phishing / Credential Harvesting',
      explanation: 'This URL exhibits multiple critical indicators of a phishing attack. The domain uses typosquatting to impersonate a trusted brand, the path structure mimics a login portal, and the TLD is associated with high-abuse hosting. The URL was matched against 3 active threat intelligence feeds.',
      humanExplanation: 'This link is a fake website designed to steal your password. It looks like a real site but it\'s not — bad actors built it to trick you into entering your login credentials. Do not click it.',
    },
    safe: {
      score: 4,
      level: 'safe',
      category: 'Legitimate Domain',
      explanation: 'The URL resolves to a well-known, verified domain with a clean reputation across all major threat intelligence databases. SSL certificate is valid, domain registration is long-standing, and no malicious patterns were detected.',
      humanExplanation: 'This link looks completely fine. It belongs to a trustworthy website with a valid security certificate. You can visit it safely.',
    },
    suspicious: {
      score: 58,
      level: 'suspicious',
      category: 'Suspicious Redirect / Unverified Domain',
      explanation: 'The domain is recently registered (< 30 days), uses a free hosting provider associated with abuse, and contains redirect parameters that could mask the true destination. While not definitively malicious, caution is advised.',
      humanExplanation: 'This link looks a bit off. The website is very new and uses a suspicious web host. We can\'t confirm it\'s dangerous, but you should be careful — don\'t enter any personal information.',
    },
  },
  logs: {
    suspicious: {
      score: 82,
      level: 'dangerous',
      category: 'Brute Force Attack',
      explanation: 'Log analysis reveals a classic brute-force pattern: 47 failed authentication attempts for the admin account from IP 185.220.101.34 within 90 seconds, followed by a successful login. The source IP is flagged in multiple threat databases as a Tor exit node and botnet node.',
      humanExplanation: 'Someone tried to guess your password hundreds of times very fast, and they succeeded. This is a break-in. You should change your passwords immediately and block that IP address.',
    },
    normal: {
      score: 7,
      level: 'safe',
      category: 'Normal Activity',
      explanation: 'Log entries show routine system activity within expected parameters. Authentication events originate from known internal IP ranges, session durations are consistent with normal usage, and no privilege escalation or lateral movement patterns were detected.',
      humanExplanation: 'Everything in these logs looks normal. Users are logging in and out as expected, and nothing suspicious is happening. No action needed.',
    },
  },
  msg: {
    fake: {
      score: 89,
      level: 'dangerous',
      category: 'Social Engineering / Phishing',
      explanation: 'The message contains 7 high-confidence social engineering markers: artificial urgency ("act immediately"), authority impersonation (PayPal branding), fear-inducing threat (account suspension), suspicious hyperlink, grammatical inconsistencies, and a generic salutation inconsistent with personalized communication.',
      humanExplanation: 'This message is a scam. Someone is pretending to be a company you trust to scare you into clicking a fake link. Real companies never ask for your password or personal info this way. Delete it.',
    },
    legit: {
      score: 6,
      level: 'safe',
      category: 'Legitimate Communication',
      explanation: 'No social engineering markers detected. The message contains no urgency triggers, no suspicious links, no credential requests, and no impersonation patterns. Language and tone are consistent with legitimate business communication.',
      humanExplanation: 'This message looks like a normal, real message. There\'s nothing suspicious about how it\'s written and it\'s not asking you to do anything dangerous.',
    },
  },
};

/* ───────────────────────────────────────────────────────────
   EXAMPLE INPUTS
─────────────────────────────────────────────────────────── */
const EXAMPLE_INPUTS = {
  url: {
    phishing:   'http://secure-paypa1.account-verify-now.xyz/login?redirect=true&session=8821',
    safe:       'https://www.google.com',
    suspicious: 'http://amazon-free-gift.club/claim?promo=WIN2024',
  },
  logs: {
    suspicious:
      '[2024-01-15 03:41:12] WARN  AUTH Failed login: user=admin src=185.220.101.34\n' +
      '[2024-01-15 03:41:13] WARN  AUTH Failed login: user=admin src=185.220.101.34\n' +
      '[2024-01-15 03:41:14] WARN  AUTH Failed login: user=root  src=185.220.101.34\n' +
      '[2024-01-15 03:41:15] WARN  AUTH Failed login: user=admin src=185.220.101.34\n' +
      '[2024-01-15 03:41:44] INFO  AUTH Login successful: user=admin src=185.220.101.34\n' +
      '[2024-01-15 03:41:45] WARN  SYS  sudo command executed: user=admin cmd=/bin/bash',
    normal:
      '[2024-01-15 09:01:02] INFO  AUTH Login successful: user=alice  src=192.168.1.10\n' +
      '[2024-01-15 09:15:44] INFO  FILE File accessed: /var/www/app/config user=alice\n' +
      '[2024-01-15 10:30:21] INFO  AUTH Login successful: user=bob    src=192.168.1.22\n' +
      '[2024-01-15 11:55:18] INFO  AUTH Logout: user=alice src=192.168.1.10',
  },
  msg: {
    fake:
      'Subject: URGENT — Your account has been suspended!\n\n' +
      'Dear Valued Customer,\n\n' +
      'We have detected suspicious activity on your PayPal account. Your account has been ' +
      'temporarily LIMITED. You must verify your identity IMMEDIATELY to restore access.\n\n' +
      'Click here to verify: http://paypa1-secure.account-verify.xyz/confirm\n\n' +
      'Failure to verify within 24 hours will result in PERMANENT account closure.\n\n' +
      '— PayPal Security Team',
    legit:
      'Hi Sarah,\n\n' +
      "Just following up on our call from Tuesday. I've attached the revised proposal for your " +
      "review. Let me know if you'd like to schedule a quick call before the Friday deadline.\n\n" +
      'Best,\nMarcus',
  },
};

/* ───────────────────────────────────────────────────────────
   DOM ELEMENT CACHE
─────────────────────────────────────────────────────────── */
const DOM = {
  // Inputs
  urlInput:    () => document.getElementById('url-input'),
  logInput:    () => document.getElementById('log-input'),
  msgInput:    () => document.getElementById('msg-input'),

  // Button
  analyzeBtn:  () => document.getElementById('analyzeBtn'),
  btnContent:  () => document.getElementById('btnContent'),
  btnSpinner:  () => document.getElementById('btnSpinner'),

  // Result
  resultCard:  () => document.getElementById('resultCard'),
  resultGlow:  () => document.getElementById('resultGlow'),
  threatBadge: () => document.getElementById('threatBadge'),
  threatLabel: () => document.getElementById('threatLabel'),
  threatDot:   () => document.getElementById('threatDot'),
  resultCategory: () => document.getElementById('resultCategory'),

  // Score
  ringFill:    () => document.getElementById('ringFill'),
  ringNumber:  () => document.getElementById('ringNumber'),
  scoreText:   () => document.getElementById('scoreText'),
  scoreBar:    () => document.getElementById('scoreBar'),

  // Explanation
  explainText:   () => document.getElementById('explainText'),
  explainToggle: () => document.getElementById('explainToggle'),

  // Errors
  errorToast: () => document.getElementById('errorToast'),
  errorMsg:   () => document.getElementById('errorMsg'),

  // Mobile
  mobileMenu:  () => document.getElementById('mobileMenu'),
};

/* ───────────────────────────────────────────────────────────
   TAB SWITCHING — NAVBAR
─────────────────────────────────────────────────────────── */
/**
 * Switch active module from navbar tab click.
 * @param {string} mod - 'url' | 'logs' | 'msg'
 * @param {HTMLElement} btn - the clicked nav tab element
 */
function switchModule(mod, btn) {
  // Update navbar tab styles
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  if (btn && btn.classList.contains('nav-tab')) {
    btn.classList.add('active');
  }
  // Sync card tabs
  switchCardTabById(mod);
}

/* ───────────────────────────────────────────────────────────
   TAB SWITCHING — CARD INNER
─────────────────────────────────────────────────────────── */
/**
 * Switch active pane from card tab click.
 * @param {string} mod - 'url' | 'logs' | 'msg'
 * @param {HTMLElement} btn - the clicked card tab element
 */
function switchCardTab(mod, btn) {
  document.querySelectorAll('.card-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  switchPanes(mod);
}

/**
 * Switch card tab by module ID (called from nav, not direct click).
 * @param {string} mod
 */
function switchCardTabById(mod) {
  const btn = document.getElementById(`ctab-${mod}`);
  if (btn) switchCardTab(mod, btn);
}

/**
 * Show the correct input pane and update state.
 * @param {string} mod
 */
function switchPanes(mod) {
  state.currentModule = mod;

  document.querySelectorAll('.tool-pane').forEach(p => p.classList.remove('active'));
  const pane = document.getElementById(`pane-${mod}`);
  if (pane) pane.classList.add('active');

  // Hide result and error when switching tabs
  hideResult();
  hideError();
}

/* ───────────────────────────────────────────────────────────
   MOBILE MENU
─────────────────────────────────────────────────────────── */
function toggleMobileMenu() {
  const menu = DOM.mobileMenu();
  menu.classList.toggle('open');
}

/* ───────────────────────────────────────────────────────────
   EXAMPLE LOADER
─────────────────────────────────────────────────────────── */
/**
 * Fill the current pane's input with an example value.
 * @param {string} module - 'url' | 'logs' | 'msg'
 * @param {string} type   - key inside EXAMPLE_INPUTS[module]
 */
function loadExample(module, type) {
  const value = EXAMPLE_INPUTS[module]?.[type];
  if (!value) return;

  const inputMap = {
    url:  DOM.urlInput,
    logs: DOM.logInput,
    msg:  DOM.msgInput,
  };

  const el = inputMap[module]?.();
  if (el) {
    el.value = value;
    el.focus();
    // Subtle flash to indicate fill
    el.style.borderColor = 'rgba(59, 130, 246, 0.6)';
    setTimeout(() => { el.style.borderColor = ''; }, 600);
  }
}

/* ───────────────────────────────────────────────────────────
   GET CURRENT INPUT VALUE
─────────────────────────────────────────────────────────── */
/**
 * Returns the trimmed value from the currently active input.
 * @returns {string}
 */
function getCurrentInput() {
  const mod = state.currentModule;
  const el = {
    url:  DOM.urlInput,
    logs: DOM.logInput,
    msg:  DOM.msgInput,
  }[mod]?.();
  return el ? el.value.trim() : '';
}

/* ───────────────────────────────────────────────────────────
   VALIDATE INPUT
─────────────────────────────────────────────────────────── */
/**
 * Light client-side validation before sending to API.
 * @returns {{ valid: boolean, message: string }}
 */
function validateInput() {
  const input = getCurrentInput();

  if (!input) {
    return { valid: false, message: 'Please enter content to analyze.' };
  }

  if (state.currentModule === 'url') {
    // Basic URL check
    try {
      new URL(input);
    } catch {
      if (!input.startsWith('http')) {
        return { valid: false, message: 'Please enter a valid URL starting with http:// or https://' };
      }
    }
  }

  if (input.length < 4) {
    return { valid: false, message: 'Input is too short to analyze.' };
  }

  return { valid: true, message: '' };
}

/* ───────────────────────────────────────────────────────────
   MAIN ANALYZE FUNCTION
─────────────────────────────────────────────────────────── */
/**
 * Called when the Analyze Threat button is clicked.
 * Validates input → shows loading → calls API/mock → renders result.
 */
async function analyzeNow() {
  if (state.isLoading) return;

  // Validate
  const { valid, message } = validateInput();
  if (!valid) {
    showError(message);
    return;
  }

  hideError();
  hideResult();
  setLoading(true);

  try {
    let result;

    /* ──────────────────────────────────────────────
       FLASK INTEGRATION — uncomment this block
       when your Flask backend is running.
       Comment out or remove the mock call below it.
    ─────────────────────────────────────────────── */
    /*
    const endpoint = API_ENDPOINTS[state.currentModule];
    const response = await fetch(endpoint, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ data: getCurrentInput() }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || `Server error: ${response.status}`);
    }

    result = await response.json();
    */

    /* ──────────────────────────────────────────────
       MOCK DATA — remove when Flask is connected
    ─────────────────────────────────────────────── */
    result = await mockAnalyze(getCurrentInput());

    state.lastResult = result;
    renderResult(result);

  } catch (err) {
    // Never show raw error to user
    console.error('[CyberGuard] API error:', err);
    showError('Analysis failed. Please check your connection and try again.');
  } finally {
    setLoading(false);
  }
}

/* ───────────────────────────────────────────────────────────
   MOCK ANALYZER
─────────────────────────────────────────────────────────── */
/**
 * Simulates an API response for demo purposes.
 * Uses input content to pick the most relevant mock response.
 * @param {string} input
 * @returns {Promise<object>}
 */
async function mockAnalyze(input) {
  // Simulate network delay
  await sleep(1200 + Math.random() * 600);

  const mod = state.currentModule;
  const txt = input.toLowerCase();

  if (mod === 'url') {
    const dangerWords = ['verify', 'paypal', 'secure', 'account', 'login', 'xyz', '1337', 'free', 'gift', 'club', 'win'];
    const hits = dangerWords.filter(w => txt.includes(w)).length;
    if (hits >= 3) return MOCK_RESPONSES.url.phishing;
    if (hits >= 1) return MOCK_RESPONSES.url.suspicious;
    return MOCK_RESPONSES.url.safe;
  }

  if (mod === 'logs') {
    const dangerWords = ['failed', 'brute', 'unauthorized', 'sudo', 'crit', 'escalat'];
    const hits = dangerWords.filter(w => txt.includes(w)).length;
    if (hits >= 2) return MOCK_RESPONSES.logs.suspicious;
    return MOCK_RESPONSES.logs.normal;
  }

  if (mod === 'msg') {
    const dangerWords = ['urgent', 'suspended', 'immediately', 'verify', 'click here', 'password', 'limited', 'paypal'];
    const hits = dangerWords.filter(w => txt.includes(w)).length;
    if (hits >= 2) return MOCK_RESPONSES.msg.fake;
    return MOCK_RESPONSES.msg.legit;
  }

  return MOCK_RESPONSES.url.safe;
}

/* ───────────────────────────────────────────────────────────
   RENDER RESULT
─────────────────────────────────────────────────────────── */
/**
 * Renders the result card with score animation, ring, and explanation.
 * @param {{ score: number, level: string, category: string, explanation: string }} result
 */
function renderResult(result) {
  const { score, level, category, explanation, humanExplanation } = result;

  const card    = DOM.resultCard();
  const badge   = DOM.threatBadge();
  const bar     = DOM.scoreBar();

  // Reset classes
  card.className  = 'result-card';
  badge.className = 'threat-badge';
  bar.className   = 'score-bar-fill';

  // Apply level classes
  card.classList.add(`level-${level}`);
  badge.classList.add(`level-${level}`);
  bar.classList.add(`level-${level}`);

  // Threat badge text
  const labelMap = { safe: '✓ Safe', suspicious: '⚠ Suspicious', dangerous: '✕ Dangerous' };
  DOM.threatLabel().textContent = labelMap[level] || level;

  // Category
  DOM.resultCategory().textContent = category;

  // Explanation
  state.explanationMode = 'technical';
  DOM.explainText().textContent   = explanation;
  DOM.explainToggle().textContent = '🧠 Explain like I\'m human';

  // Show card (so dimensions are available for animation)
  card.classList.remove('hidden');

  // Animate score after short delay (allow layout paint)
  requestAnimationFrame(() => {
    setTimeout(() => {
      animateScore(score, level);
    }, 80);
  });

  // Scroll to result
  setTimeout(() => {
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, 200);
}

/* ───────────────────────────────────────────────────────────
   SCORE ANIMATION
─────────────────────────────────────────────────────────── */
/**
 * Animates the score bar, ring, and counter.
 * @param {number} targetScore - 0 to 100
 * @param {string} level
 */
function animateScore(targetScore, level) {
  const CIRCUMFERENCE = 276.46; // 2π × 44

  // Color map for ring stroke
  const strokeMap = {
    safe:       '#22C55E',
    suspicious: '#F59E0B',
    dangerous:  '#EF4444',
  };

  const ring = DOM.ringFill();
  ring.style.stroke = strokeMap[level] || '#3B82F6';

  // Counter animation
  const duration = 1000;
  const start    = performance.now();
  let   lastNum  = -1;

  function tick(now) {
    const elapsed  = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased    = easeOutCubic(progress);
    const current  = Math.round(eased * targetScore);

    // Update counter (only when number changes)
    if (current !== lastNum) {
      lastNum = current;
      DOM.ringNumber().textContent = current;
      DOM.scoreText().textContent  = current + '%';
    }

    // Update ring
    const offset = CIRCUMFERENCE - (eased * targetScore / 100) * CIRCUMFERENCE;
    ring.style.strokeDashoffset = offset;

    // Update bar
    DOM.scoreBar().style.width = (eased * targetScore) + '%';

    if (progress < 1) requestAnimationFrame(tick);
  }

  requestAnimationFrame(tick);
}

/* ───────────────────────────────────────────────────────────
   EXPLANATION TOGGLE
─────────────────────────────────────────────────────────── */
/**
 * Toggles between technical and human-friendly explanation.
 */
function toggleExplanation() {
  if (!state.lastResult) return;

  const { explanation, humanExplanation } = state.lastResult;
  const textEl   = DOM.explainText();
  const toggleEl = DOM.explainToggle();

  // Fade out → swap text → fade in
  textEl.style.opacity = '0';

  setTimeout(() => {
    if (state.explanationMode === 'technical') {
      state.explanationMode = 'human';
      textEl.textContent    = humanExplanation || 'No simplified explanation available.';
      toggleEl.textContent  = '⚙ Show technical details';
    } else {
      state.explanationMode = 'technical';
      textEl.textContent    = explanation;
      toggleEl.textContent  = '🧠 Explain like I\'m human';
    }
    textEl.style.opacity = '1';
  }, 180);
}

/* ───────────────────────────────────────────────────────────
   LOADING STATE
─────────────────────────────────────────────────────────── */
/**
 * Toggle loading state on the analyze button.
 * @param {boolean} loading
 */
function setLoading(loading) {
  state.isLoading = loading;

  const btn     = DOM.analyzeBtn();
  const content = DOM.btnContent();
  const spinner = DOM.btnSpinner();

  btn.disabled = loading;

  if (loading) {
    content.classList.add('hidden');
    spinner.classList.remove('hidden');
  } else {
    content.classList.remove('hidden');
    spinner.classList.add('hidden');
  }
}

/* ───────────────────────────────────────────────────────────
   ERROR HANDLING
─────────────────────────────────────────────────────────── */
/**
 * Show a friendly error message above the result area.
 * @param {string} message
 */
function showError(message) {
  const toast = DOM.errorToast();
  DOM.errorMsg().textContent = message;
  toast.classList.remove('hidden');
}

function hideError() {
  DOM.errorToast().classList.add('hidden');
}

/* ───────────────────────────────────────────────────────────
   RESULT VISIBILITY
─────────────────────────────────────────────────────────── */
function hideResult() {
  DOM.resultCard().classList.add('hidden');
}

/* ───────────────────────────────────────────────────────────
   SCROLL HELPER
─────────────────────────────────────────────────────────── */
function scrollToTool() {
  document.getElementById('tool-section')?.scrollIntoView({ behavior: 'smooth' });
}

/* ───────────────────────────────────────────────────────────
   AUTH FORM HANDLING
─────────────────────────────────────────────────────────── */
/**
 * Handles signup/signin form submission.
 */
async function handleAuthForm(e, endpoint) {
  e.preventDefault();

  const form = e.target;
  const submitBtn = form.querySelector('button[type="submit"]');
  const errorEl = document.getElementById('authError');

  const email = form.email.value.trim().toLowerCase();
  const password = form.password.value;
  const confirmPassword = form.confirmPassword?.value;

  if (confirmPassword !== undefined && password !== confirmPassword) {
    errorEl.textContent = 'Passwords do not match.';
    errorEl.classList.remove('hidden');
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = 'Processing...';
  errorEl.classList.add('hidden');

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    if (data.success) {
      if (endpoint.includes('signin')) {
        window.location.href = '/';
      } else {
        // Signup: show message to check email
        errorEl.textContent = data.message;
        errorEl.classList.remove('hidden');
        errorEl.style.color = 'green';
      }
    } else {
      errorEl.textContent = data.message;
      errorEl.classList.remove('hidden');
    }
  } catch (err) {
    errorEl.textContent = 'Network error. Please try again.';
    errorEl.classList.remove('hidden');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = endpoint.includes('signin') ? 'Sign In' : 'Create account';
  }
}

/**
 * Signs out the user.
 */
async function signOut() {
  try {
    await fetch('/api/auth/signout', { method: 'POST' });
  } catch (err) {
    console.warn('Signout error:', err);
  }
  window.location.href = '/';
}

/* ───────────────────────────────────────────────────────────
   HISTORY LOADING
─────────────────────────────────────────────────────────── */
/**
 * Loads user scan history and populates the table.
 */
async function loadHistory() {
  try {
    const response = await fetch('/api/history');
    if (response.status === 401) {
      // Not logged in, but since @login_required, shouldn't happen
      return;
    }
    if (!response.ok) throw new Error('Failed to load history');

    const data = await response.json();
    const history = data.history || [];
    const table = document.getElementById('historyTable');
    const empty = document.getElementById('historyEmpty');

    if (history.length === 0) {
      table.style.display = 'none';
      empty.style.display = 'block';
      empty.textContent = 'aucune activité';
      return;
    }

    table.style.display = 'table';
    empty.style.display = 'none';

    const tbody = table.querySelector('tbody') || table.appendChild(document.createElement('tbody'));
    tbody.innerHTML = '';

    history.forEach(scan => {
      const row = document.createElement('tr');
      const date = new Date(scan.created_at).toLocaleDateString();
      row.innerHTML = `
        <td><a href="${scan.url}" target="_blank" rel="noopener">${scan.url}</a></td>
        <td>${scan.category}</td>
        <td>${scan.score}%</td>
        <td>${date}</td>
      `;
      tbody.appendChild(row);
    });
  } catch (err) {
    console.error('Failed to load history:', err);
    document.getElementById('historyEmpty').textContent = 'Failed to load history.';
    document.getElementById('historyEmpty').style.display = 'block';
    document.getElementById('historyTable').style.display = 'none';
  }
}
/**
 * Fetches real stats from API and animates counters.
 */
async function loadAndAnimateStats() {
  try {
    const response = await fetch('/api/stats');
    if (response.ok) {
      const data = await response.json();
      document.getElementById('userCount').dataset.target = data.users;
      document.getElementById('scanCount').dataset.target = data.scans;
    }
  } catch (err) {
    console.warn('Failed to load stats:', err);
    // Fallback to 0
    document.getElementById('userCount').dataset.target = 0;
    document.getElementById('scanCount').dataset.target = 0;
  }

  // Now animate
  animateStats();
}

/* ───────────────────────────────────────────────────────────
   STAT COUNTER ANIMATION
─────────────────────────────────────────────────────────── */
function animateStats() {
  document.querySelectorAll('.stat-value[data-target]').forEach(el => {
    const target = parseFloat(el.dataset.target) || 0;
    const suffix = el.dataset.suffix || '';
    const isFloat = !Number.isInteger(target);
    const duration = 1600;
    const start = performance.now();

    function tick(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = easeOutCubic(progress);
      const value = target * eased;
      el.textContent = (isFloat ? value.toFixed(1) : Math.round(value)) + suffix;
      if (progress < 1) requestAnimationFrame(tick);
    }

    requestAnimationFrame(tick);
  });
}

/* ───────────────────────────────────────────────────────────
   UTILITIES
─────────────────────────────────────────────────────────── */

/**
 * Easing function for smooth animations.
 * @param {number} t - progress 0 to 1
 * @returns {number}
 */
function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

/**
 * Promise-based sleep.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ───────────────────────────────────────────────────────────
   KEYBOARD SHORTCUTS
─────────────────────────────────────────────────────────── */
document.addEventListener('keydown', e => {
  // Enter on URL input → analyze
  if (e.key === 'Enter' && document.activeElement === DOM.urlInput()) {
    analyzeNow();
  }
  // Ctrl/Cmd + Enter from any active pane → analyze
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    analyzeNow();
  }
  // Escape → hide result
  if (e.key === 'Escape') {
    hideResult();
    hideError();
  }
});

/* ───────────────────────────────────────────────────────────
   INIT
─────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  // Load and animate hero stats on load
  setTimeout(loadAndAnimateStats, 300);

  // Close mobile menu on outside click
  document.addEventListener('click', e => {
    const menu = DOM.mobileMenu();
    const hamburger = document.getElementById('hamburger');
    if (menu.classList.contains('open') &&
        !menu.contains(e.target) &&
        !hamburger.contains(e.target)) {
      menu.classList.remove('open');
    }
  });

  // Textarea auto-resize (optional UX enhancement)
  document.querySelectorAll('.tool-textarea').forEach(ta => {
    ta.addEventListener('input', function () {
      this.style.height = 'auto';
      this.style.height = Math.min(this.scrollHeight, 300) + 'px';
    });
  });

  // Load history if on history page
  if (document.getElementById('historyTable')) {
    loadHistory();
  }

  // Auth form handlers
  const authForm = document.getElementById('authForm');
  if (authForm) {
    const endpoint = window.location.pathname.includes('signup') ? '/api/auth/signup' : '/api/auth/signin';
    authForm.addEventListener('submit', (e) => handleAuthForm(e, endpoint));
  }

  console.log('%c🛡️ CyberGuard AI loaded', 'color:#3B82F6; font-weight:bold; font-size:14px');
  console.log('%cFlask endpoints ready at /api/url-shield · /api/log-sentinel · /api/trustcheck', 'color:#9CA3AF; font-size:11px');
});