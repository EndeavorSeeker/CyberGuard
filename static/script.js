'use strict';

/* ─────────────────────────────────────
   STATE
───────────────────────────────────── */
const state = {
  currentModule:   null,      // 'url' | 'image' | 'msg'
  isLoading:       false,
  lastResult:      null,
  explanationMode: 'technical',
  imageFile:       null,
  imageBase64:     null,
};

/* ─────────────────────────────────────
   FLASK ENDPOINTS
   → uncomment when Flask is ready
───────────────────────────────────── */
const API = {
  url:   '/api/url-shield',
  image: '/api/image-scan',
  msg:   '/api/trustcheck',
  stats: '/api/stats',
};

/* ─────────────────────────────────────
   MOCK DATA
───────────────────────────────────── */
const MOCK = {
  url: {
    phishing: {
      score:74, level:'dangerous', category:'Phishing / Credential Harvesting',
      explanation:'This URL exhibits typosquatting patterns targeting a well-known brand. The domain was registered recently, uses a suspicious TLD, and the path mimics a login portal. Matched 3 active threat intelligence feeds.',
      humanExplanation:'This is a fake website trying to steal your password. It looks like a real site but it is not. Do not click it.',
    },
    safe: {
      score:5, level:'safe', category:'Legitimate Domain',
      explanation:'The URL resolves to a verified domain with a clean reputation. SSL certificate is valid, domain is long-standing, and no malicious patterns detected.',
      humanExplanation:'This link is completely safe. It belongs to a trusted website with a valid security certificate.',
    },
    suspicious: {
      score:55, level:'suspicious', category:'Unverified / Recently Registered Domain',
      explanation:'Domain registered less than 30 days ago. Hosted on infrastructure associated with abuse. Redirect parameters present that could mask the true destination.',
      humanExplanation:'This link looks a bit suspicious. The website is very new and uses a questionable host. Be careful — do not enter personal information.',
    },
  },
  image: {
    fake: {
      score:82, level:'dangerous', category:'Manipulated Screenshot / Fake UI',
      explanation:'The image contains visual patterns consistent with fabricated screenshots. Metadata anomalies detected, pixel-level inconsistencies suggest compositing, and embedded text matches known phishing templates.',
      humanExplanation:'This image looks fake. It has been edited or generated to look like a real screenshot but is not. Do not trust any information shown in it.',
    },
    safe: {
      score:6, level:'safe', category:'Authentic Image',
      explanation:'No signs of manipulation or synthesis detected. Image metadata is consistent, compression artifacts are natural, and no embedded malicious patterns were found.',
      humanExplanation:'This image looks genuine. No signs of editing or fakery were detected.',
    },
  },
  msg: {
    fake: {
      score:88, level:'dangerous', category:'Social Engineering / Phishing',
      explanation:'Message contains 6 high-confidence social engineering markers: artificial urgency, authority impersonation, fear-inducing threat, suspicious link, grammatical inconsistencies, and a generic salutation.',
      humanExplanation:'This is a scam message. Someone is pretending to be a company to scare you into clicking a fake link. Real companies never ask for passwords this way. Delete it.',
    },
    legit: {
      score:5, level:'safe', category:'Legitimate Communication',
      explanation:'No social engineering markers detected. No urgency triggers, suspicious links, credential requests, or impersonation patterns found.',
      humanExplanation:'This message looks completely normal and legitimate. Nothing suspicious about it.',
    },
  },
};

const EXAMPLES = {
  url: {
    phishing:   'http://secure-paypa1.account-verify-now.xyz/login?session=8821',
    safe:       'https://www.google.com',
    suspicious: 'http://amazon-free-gift.club/claim?promo=WIN2024',
  },
  msg: {
    fake: 'Subject: URGENT — Your account has been suspended!\n\nDear Valued Customer,\n\nWe detected suspicious activity. Your account is LIMITED. Verify IMMEDIATELY:\nhttp://paypa1-secure.account-verify.xyz/confirm\n\nFailure to act within 24 hours will cause PERMANENT closure.\n\n— PayPal Security Team',
    legit: 'Hi Sarah,\n\nJust following up on Tuesday\'s call. I\'ve attached the revised proposal. Let me know if you\'d like to chat before Friday.\n\nBest,\nMarcus',
  },
};

/* ─────────────────────────────────────
   OPEN / CLOSE MODULE PANEL
───────────────────────────────────── */
function openModule(mod) {
  state.currentModule = mod;

  // Set panel title
  const titles = { url:'URL Shield', image:'Image Scan', msg:'TrustCheck' };
  document.getElementById('panelTitle').textContent = titles[mod];

  // Show correct pane
  document.querySelectorAll('.tool-pane').forEach(p => p.classList.remove('active'));
  document.getElementById('pane-' + mod).classList.add('active');

  // Reset state
  hideResult();
  hideError();
  resetImageUpload();

  // Open overlay + panel
  document.getElementById('toolOverlay').classList.add('active');
  document.getElementById('toolPanel').classList.add('open');

  // Scroll panel into view on mobile
  setTimeout(() => {
    document.getElementById('toolPanel').scrollTop = 0;
  }, 100);
}

function closeModule() {
  document.getElementById('toolOverlay').classList.remove('active');
  document.getElementById('toolPanel').classList.remove('open');
  state.currentModule = null;
}

/* ─────────────────────────────────────
   LOAD EXAMPLE INTO INPUT
───────────────────────────────────── */
function loadExample(mod, type) {
  const val = EXAMPLES[mod]?.[type];
  if (!val) return;
  const el = document.getElementById(mod === 'url' ? 'url-input' : 'msg-input');
  if (!el) return;
  el.value = val;
  el.focus();
  el.style.borderColor = 'rgba(59,130,246,0.6)';
  setTimeout(() => { el.style.borderColor = ''; }, 600);
}

/* ─────────────────────────────────────
   IMAGE UPLOAD — DRAG & DROP
───────────────────────────────────── */
function handleDragOver(e) {
  e.preventDefault();
  document.getElementById('dropZone').classList.add('dragging');
}

function handleDragLeave(e) {
  document.getElementById('dropZone').classList.remove('dragging');
}

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('dropZone').classList.remove('dragging');
  const file = e.dataTransfer.files[0];
  if (file && file.type.startsWith('image/')) {
    processImageFile(file);
  } else {
    showError('Please drop a valid image file (PNG, JPG, WEBP).');
  }
}

function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) processImageFile(file);
}

function processImageFile(file) {
  // Validate size (10 MB max)
  if (file.size > 10 * 1024 * 1024) {
    showError('Image is too large. Maximum size is 10 MB.');
    return;
  }

  state.imageFile = file;

  const reader = new FileReader();
  reader.onload = (e) => {
    state.imageBase64 = e.target.result;

    // Show preview
    document.getElementById('imagePreview').src = e.target.result;
    document.getElementById('imageName').textContent = file.name + ' (' + (file.size / 1024).toFixed(0) + ' KB)';
    document.getElementById('dropZone').style.display = 'none';
    document.getElementById('imagePreviewWrap').classList.remove('hidden');

    hideError();
  };
  reader.readAsDataURL(file);
}

function removeImage() {
  resetImageUpload();
  hideResult();
}

function resetImageUpload() {
  state.imageFile   = null;
  state.imageBase64 = null;
  document.getElementById('imageFileInput').value = '';
  document.getElementById('imagePreviewWrap').classList.add('hidden');
  document.getElementById('imagePreview').src = '';
  document.getElementById('dropZone').style.display = '';
}

/* ─────────────────────────────────────
   VALIDATE INPUT
───────────────────────────────────── */
function validateInput() {
  const mod = state.currentModule;

  if (mod === 'url') {
    const val = document.getElementById('url-input').value.trim();
    if (!val) return { ok:false, msg:'Please enter a URL.' };
    return { ok:true };
  }

  if (mod === 'image') {
    if (!state.imageFile) return { ok:false, msg:'Please upload an image first.' };
    return { ok:true };
  }

  if (mod === 'msg') {
    const val = document.getElementById('msg-input').value.trim();
    if (!val) return { ok:false, msg:'Please paste a message to analyze.' };
    if (val.length < 5) return { ok:false, msg:'Message is too short to analyze.' };
    return { ok:true };
  }

  return { ok:false, msg:'No module selected.' };
}

/* ─────────────────────────────────────
   MAIN ANALYZE
───────────────────────────────────── */
async function analyzeNow() {
  if (state.isLoading) return;

  const v = validateInput();
  if (!v.ok) { showError(v.msg); return; }

  hideError();
  hideResult();
  setLoading(true);

  try {
    let result;

    /* ═══ REAL FLASK CALL — uncomment when backend is ready ═══

    let body;
    const mod = state.currentModule;

    if (mod === 'url') {
      body = JSON.stringify({ data: document.getElementById('url-input').value.trim() });
    } else if (mod === 'image') {
      body = JSON.stringify({ image: state.imageBase64, filename: state.imageFile.name });
    } else if (mod === 'msg') {
      body = JSON.stringify({ data: document.getElementById('msg-input').value.trim() });
    }

    const res = await fetch(API[mod], {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || 'Server error ' + res.status);
    }

    result = await res.json();
    ═══════════════════════════════════════════════════════════ */

    // MOCK — remove when Flask is connected
    result = await mockAnalyze();

    state.lastResult = result;
    renderResult(result);

  } catch (err) {
    console.error('[CyberGuard]', err);
    showError('Analysis failed. Please check your connection and try again.');
  } finally {
    setLoading(false);
  }
}

/* ─────────────────────────────────────
   MOCK ANALYZER
───────────────────────────────────── */
async function mockAnalyze() {
  await sleep(1100 + Math.random() * 500);

  const mod = state.currentModule;

  if (mod === 'url') {
    const txt = document.getElementById('url-input').value.toLowerCase();
    const bad = ['verify','paypal','secure','account','login','xyz','free','gift','club','win','1'];
    const hits = bad.filter(w => txt.includes(w)).length;
    if (hits >= 3) return MOCK.url.phishing;
    if (hits >= 1) return MOCK.url.suspicious;
    return MOCK.url.safe;
  }

  if (mod === 'image') {
    // Simple heuristic: small files tend to be screenshots / fake
    const sizeMB = state.imageFile.size / 1024 / 1024;
    if (sizeMB < 0.15) return MOCK.image.fake;
    return MOCK.image.safe;
  }

  if (mod === 'msg') {
    const txt  = document.getElementById('msg-input').value.toLowerCase();
    const bad  = ['urgent','suspended','immediately','verify','click here','password','limited','paypal','expire'];
    const hits = bad.filter(w => txt.includes(w)).length;
    if (hits >= 2) return MOCK.msg.fake;
    return MOCK.msg.legit;
  }

  return MOCK.url.safe;
}

/* ─────────────────────────────────────
   RENDER RESULT
───────────────────────────────────── */
function renderResult(r) {
  const card  = document.getElementById('resultCard');
  const badge = document.getElementById('threatBadge');
  const bar   = document.getElementById('scoreBar');

  // Reset classes
  ['level-safe','level-suspicious','level-dangerous'].forEach(c => {
    card.classList.remove(c);
    badge.classList.remove(c);
    bar.classList.remove(c);
  });

  card.classList.add('level-' + r.level);
  badge.classList.add('level-' + r.level);
  bar.classList.add('level-' + r.level);

  const labels = { safe:'✓ Safe', suspicious:'⚠ Suspicious', dangerous:'✕ Dangerous' };
  document.getElementById('threatLabel').textContent   = labels[r.level] || r.level;
  document.getElementById('resultCategory').textContent = r.category;

  state.explanationMode = 'technical';
  document.getElementById('explainText').textContent   = r.explanation;
  document.getElementById('explainToggle').textContent = '🧠 Explain like I\'m human';

  card.classList.remove('hidden');

  requestAnimationFrame(() => {
    setTimeout(() => animateScore(r.score, r.level), 80);
  });

  setTimeout(() => card.scrollIntoView({ behavior:'smooth', block:'nearest' }), 200);
}

/* ─────────────────────────────────────
   ANIMATE SCORE
───────────────────────────────────── */
function animateScore(target, level) {
  const CIRC = 276.46;
  const strokeColors = { safe:'#22C55E', suspicious:'#F59E0B', dangerous:'#EF4444' };

  const ring = document.getElementById('ringFill');
  ring.style.stroke = strokeColors[level] || '#3B82F6';

  const dur   = 1000;
  const start = performance.now();
  let   last  = -1;

  function tick(now) {
    const p   = Math.min((now - start) / dur, 1);
    const e   = easeOutCubic(p);
    const cur = Math.round(e * target);

    if (cur !== last) {
      last = cur;
      document.getElementById('ringNumber').textContent = cur;
      document.getElementById('scoreText').textContent  = cur + '%';
    }

    ring.style.strokeDashoffset = CIRC - (e * target / 100) * CIRC;
    document.getElementById('scoreBar').style.width = (e * target) + '%';

    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* ─────────────────────────────────────
   EXPLANATION TOGGLE
───────────────────────────────────── */
function toggleExplanation() {
  if (!state.lastResult) return;
  const { explanation, humanExplanation } = state.lastResult;
  const txt = document.getElementById('explainText');
  const btn = document.getElementById('explainToggle');

  txt.style.opacity = '0';
  setTimeout(() => {
    if (state.explanationMode === 'technical') {
      state.explanationMode = 'human';
      txt.textContent = humanExplanation || 'No simplified explanation available.';
      btn.textContent = '⚙ Show technical details';
    } else {
      state.explanationMode = 'technical';
      txt.textContent = explanation;
      btn.textContent = '🧠 Explain like I\'m human';
    }
    txt.style.opacity = '1';
  }, 180);
}

/* ─────────────────────────────────────
   LOADING STATE
───────────────────────────────────── */
function setLoading(on) {
  state.isLoading = on;
  const btn = document.getElementById('analyzeBtn');
  btn.disabled = on;
  document.getElementById('btnContent').classList.toggle('hidden', on);
  document.getElementById('btnSpinner').classList.toggle('hidden', !on);
}

/* ─────────────────────────────────────
   ERROR / RESULT VISIBILITY
───────────────────────────────────── */
function showError(msg) {
  document.getElementById('errorMsg').textContent = msg;
  document.getElementById('errorToast').classList.remove('hidden');
}
function hideError()  { document.getElementById('errorToast').classList.add('hidden'); }
function hideResult() { document.getElementById('resultCard').classList.add('hidden'); }

/* ─────────────────────────────────────
   AUTH FORM
───────────────────────────────────── */
async function handleAuthForm(e, endpoint) {
  e.preventDefault();
  const form    = e.target;
  const submitBtn = form.querySelector('button[type="submit"]');
  const errorEl = document.getElementById('authError');

  const email    = form.email.value.trim().toLowerCase();
  const password = form.password.value;
  const confirm  = form.confirmPassword?.value;

  errorEl.classList.add('hidden');

  if (confirm !== undefined && password !== confirm) {
    errorEl.textContent = 'Passwords do not match.';
    errorEl.classList.remove('hidden');
    return;
  }

  submitBtn.disabled    = true;
  submitBtn.textContent = 'Please wait…';

  try {
    const res  = await fetch(endpoint, {
      method:  'POST',
      headers: { 'Content-Type':'application/json' },
      body:    JSON.stringify({ email, password }),
    });
    const data = await res.json();

    if (data.success) {
      if (endpoint.includes('signin')) {
        window.location.href = '/';
      } else {
        errorEl.textContent = data.message || 'Account created! You can now sign in.';
        errorEl.style.color = 'var(--green)';
        errorEl.classList.remove('hidden');
      }
    } else {
      errorEl.textContent = data.message || 'An error occurred. Please try again.';
      errorEl.classList.remove('hidden');
    }
  } catch {
    errorEl.textContent = 'Network error. Check your connection and try again.';
    errorEl.classList.remove('hidden');
  } finally {
    submitBtn.disabled    = false;
    submitBtn.textContent = endpoint.includes('signin') ? 'Sign In' : 'Create Account';
  }
}

/* ─────────────────────────────────────
   SIGN OUT
───────────────────────────────────── */
async function signOut() {
  try { await fetch('/api/auth/signout', { method:'POST' }); } catch {}
  window.location.href = '/';
}

/* ─────────────────────────────────────
   HISTORY
───────────────────────────────────── */
async function loadHistory() {
  const table = document.getElementById('historyTable');
  const empty = document.getElementById('historyEmpty');
  if (!table) return;

  try {
    const res  = await fetch('/api/history');
    if (!res.ok) throw new Error('Failed');
    const data = await res.json();
    const list = data.history || [];

    if (list.length === 0) {
      table.style.display = 'none';
      empty.style.display = 'block';
      return;
    }

    table.style.display = 'table';
    empty.style.display = 'none';
    const tbody = table.querySelector('tbody') || table.appendChild(document.createElement('tbody'));
    tbody.innerHTML = '';

    list.forEach(scan => {
      const row = document.createElement('tr');
      const date = new Date(scan.created_at).toLocaleDateString();
      row.innerHTML = `
        <td><a href="${scan.url}" target="_blank" rel="noopener noreferrer">${scan.url}</a></td>
        <td>${scan.category}</td>
        <td>${scan.score}%</td>
        <td>${date}</td>
      `;
      tbody.appendChild(row);
    });
  } catch {
    if (empty) { empty.textContent = 'Failed to load history.'; empty.style.display = 'block'; }
    if (table) table.style.display = 'none';
  }
}

/* ─────────────────────────────────────
   STATS ANIMATION
───────────────────────────────────── */
async function loadStats() {
  try {
    const res  = await fetch(API.stats);
    if (res.ok) {
      const data = await res.json();
      const uc = document.getElementById('userCount');
      const sc = document.getElementById('scanCount');
      if (uc) uc.dataset.target = data.users || 0;
      if (sc) sc.dataset.target = data.scans || 0;
    }
  } catch {}
  animateCounters();
}

function animateCounters() {
  document.querySelectorAll('.stat-num[data-target]').forEach(el => {
    const target = parseFloat(el.dataset.target) || 0;
    const dur    = 1600;
    const start  = performance.now();
    function tick(now) {
      const p = Math.min((now - start) / dur, 1);
      el.textContent = Math.round(easeOutCubic(p) * target);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  });
}

/* ─────────────────────────────────────
   KEYBOARD SHORTCUTS
───────────────────────────────────── */
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModule();
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyzeNow();
  if (e.key === 'Enter' && document.activeElement?.id === 'url-input') analyzeNow();
});

/* ─────────────────────────────────────
   UTILITIES
───────────────────────────────────── */
function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ─────────────────────────────────────
   INIT
───────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {

  // Stats counter
  setTimeout(loadStats, 400);

  // History page
  if (document.getElementById('historyTable')) loadHistory();

  // Auth forms
  const authForm = document.getElementById('authForm');
  if (authForm) {
    const ep = window.location.pathname.includes('signup')
      ? '/api/auth/signup'
      : '/api/auth/signin';
    authForm.addEventListener('submit', e => handleAuthForm(e, ep));
  }

  console.log('%c🛡️ CyberGuard AI ready', 'color:#3B82F6;font-weight:bold;font-size:14px');
});