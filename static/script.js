
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
let clerkUser = null;
let clerkLoaded = false;

async function syncBackendClerkUser(user) {
  const email = user?.primaryEmailAddress?.emailAddress || user?.emailAddresses?.[0]?.emailAddress || user?.email;
  if (!user?.id || !email) return;

  await fetch('/api/sync-user', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: user.id, email }),
  });
}

/* ─────────────────────────────────────
   CLERK AUTH
───────────────────────────────────── */
async function initClerk() {
  if (!window.Clerk) {
    updateNavbar();
    return;
  }

  try {
    if (!clerkLoaded) {
      await window.Clerk.load();
      clerkLoaded = true;
    }
    clerkUser = window.Clerk.user;
    if (clerkUser) {
      await syncBackendClerkUser(clerkUser).catch((err) => {
        console.warn('Unable to sync Clerk user to backend:', err);
      });
    }
  } catch (err) {
    console.warn('Clerk failed to initialize:', err);
  } finally {
    updateNavbar();
  }
}

function updateNavbar() {
  const getStartedBtn = document.getElementById('getStartedBtn');
  const signInLink = document.getElementById('signInLink');
  const profileMenu = document.getElementById('profileMenu');
  const profileBtn = document.getElementById('profileBtn');
  const profileEmail = document.getElementById('profileEmail');
  const profileEmailFull = document.getElementById('profileEmailFull');
  const mobileProfile = document.getElementById('mobileProfile');
  const mobileProfileEmail = document.getElementById('mobileProfileEmail');
  const burgerAuth = document.getElementById('burgerAuthSection');
  if (clerkUser) {
    const displayName = clerkUser.fullName || clerkUser.firstName || clerkUser.emailAddresses?.[0]?.emailAddress || 'Account';
    const el = document.getElementById('profileDisplayName');
    if (el) el.textContent = displayName;
  }
  const email = clerkUser?.primaryEmailAddress?.emailAddress || clerkUser?.emailAddresses?.[0]?.emailAddress || '';
  const name = clerkUser?.fullName || clerkUser?.firstName || email.split('@')[0] || 'User';

  if (clerkUser && email) {
    if (getStartedBtn) getStartedBtn.style.display = 'none';
    if (signInLink) signInLink.style.display = 'none';
    if (burgerAuth) burgerAuth.style.display = 'none';
    if (profileMenu) profileMenu.style.display = 'flex';
    if (profileBtn) profileBtn.style.display = 'flex';
    if (profileEmail) profileEmail.textContent = name;
    if (profileEmailFull) profileEmailFull.textContent = email;
    if (mobileProfile) {
      mobileProfile.style.display = 'block';
      if (mobileProfileEmail) mobileProfileEmail.textContent = email;
    }
  } else {
    if (getStartedBtn) getStartedBtn.style.display = 'inline-flex';
    if (signInLink) signInLink.style.display = 'block';
    if (burgerAuth) burgerAuth.style.display = 'block';
    if (profileMenu) profileMenu.style.display = 'none';
    if (mobileProfile) mobileProfile.style.display = 'none';
  }
}

async function signOut() {
  const btn = document.getElementById('signOutBtn') || document.querySelector('[data-signout-button="1"]');

  // Same morph animation as theme toggle (if we can find a button)
  if (btn && btn.querySelector('.material-symbols-outlined')) {
    const icon = btn.querySelector('.material-symbols-outlined');
    if (btn.dataset.signOutMorphing !== '1') {
      btn.dataset.signOutMorphing = '1';
      btn.classList.remove('theme-morph-complete');
      btn.classList.add('theme-morph');
      if (icon) icon.style.willChange = 'transform, filter, opacity';

      // Small delay so the morph CSS feels responsive
      requestAnimationFrame(() => {
        btn.classList.add('theme-morph-complete');
      });

      setTimeout(() => {
        btn.classList.remove('theme-morph');
        btn.classList.remove('theme-morph-complete');
        btn.dataset.signOutMorphing = '0';
        if (icon) icon.style.willChange = '';
      }, 520);
    }
  }

  if (window.Clerk) {
    await window.Clerk.signOut();
  }
  window.location.href = '/';
}

function toggleProfileDropdown() {
  const dropdown = document.getElementById('profileDropdown');
  if (!dropdown) return;
  dropdown.classList.toggle('open');
}

window.addEventListener('load', () => {
  initClerk();
});

document.addEventListener('click', (event) => {
  const menu = document.getElementById('profileMenu');
  const dropdown = document.getElementById('profileDropdown');
  if (dropdown && menu && !menu.contains(event.target)) {
    dropdown.classList.remove('open');
  }
});
/* ─────────────────────────────────────
   FLASK ENDPOINTS
   → uncomment when Flask is ready
───────────────────────────────────── */
const API = {
  scan: '/api/scan',
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
function scrollToModules() {
  const toolSection = document.getElementById('tool-section');
  if (toolSection) {
    toolSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function scrollToAcademy() {
  const academySection = document.getElementById('academy-section');
  if (academySection) {
    academySection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return;
  }
  // Fallback: section not found, go to academy page
  window.location.href = '/academy';
}


function openModule(mod) {
  if (!clerkUser) {
    window.location.href = '/signin';
    return;
  }

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
  document.getElementById('scrollTopBtn')?.classList.remove('stt-visible');

  // Scroll panel into view on mobile
  setTimeout(() => {
    document.getElementById('toolPanel').scrollTop = 0;
  }, 100);
}

function closeModule() {
  document.getElementById('toolOverlay')?.classList.remove('active');
  document.getElementById('toolPanel')?.classList.remove('open');
  state.currentModule = null;
  const y = window.scrollY || window.pageYOffset;
  if (y > 280) {
    document.getElementById('scrollTopBtn')?.classList.add('stt-visible');
  }
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
    showError(cgTranslate('tool_error_invalid_image_drop'));
  }
}

function handleFileSelect(e) {
  const file = e.target.files[0];
  if (file) processImageFile(file);
}

function processImageFile(file) {
  // Validate size (10 MB max)
  if (file.size > 10 * 1024 * 1024) {
    showError(cgTranslate('tool_error_image_too_large'));
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
  if (!clerkUser) {
    window.location.href = '/signin';
    return;
  }

  const v = validateInput();
  if (!v.ok) { showError(v.msg); return; }

  hideError();
  hideResult();
  setLoading(true);

  try {
    let result;

    /* ═══ REAL FLASK CALL ═══ */

    let body;
    const mod = state.currentModule;

    if (mod === 'url') {
      body = JSON.stringify({ type: 'url', url: document.getElementById('url-input').value.trim(), user_id: clerkUser ? clerkUser.id : null });
    } else if (mod === 'image') {
      body = JSON.stringify({
        type: 'image',
        image_name: state.imageFile?.name || 'Uploaded image',
        image_size: state.imageFile?.size || 0,
        user_id: clerkUser.id,
      });
    } else if (mod === 'msg') {
      body = JSON.stringify({ type: 'msg', text: document.getElementById('msg-input').value.trim(), user_id: clerkUser ? clerkUser.id : null });
    }

    const res = await fetch(API.scan, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || 'Server error ' + res.status);
    }

    result = await res.json();
    if (!result.success) throw new Error(result.message || 'Analysis failed');

    result = normalizeResult(result.result);

    state.lastResult = result;
    renderResult(result);

  } catch (err) {
    console.error('[CyberGuard]', err);
    showError(cgTranslate('tool_error_analysis_failed'));
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

function normalizeResult(result) {
  if (!result) return MOCK.url.safe;
  if (result.level) return result;

  const category = (result.category || '').toLowerCase();
  let level = 'safe';
  if (result.score >= 70 || category.includes('phishing') || category.includes('engineering') || category.includes('alert')) {
    level = 'dangerous';
  } else if (result.score >= 40 || category.includes('suspicious')) {
    level = 'suspicious';
  }

  return {
    ...result,
    level,
    humanExplanation: result.humanExplanation || result.explanation,
  };
}

/* ─────────────────────────────────────
   RENDER RESULT
───────────────────────────────────── */
function renderResult(r) {
  r = normalizeResult(r);
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

  const labels = {
    safe: `✓ ${cgTranslate('scale_safe')}`,
    suspicious: `⚠ ${cgTranslate('scale_suspicious')}`,
    dangerous: `✕ ${cgTranslate('scale_dangerous')}`
  };
  document.getElementById('threatLabel').textContent   = labels[r.level] || r.level;
  document.getElementById('resultCategory').textContent = r.category;

  state.explanationMode = 'technical';
  document.getElementById('explainText').textContent   = r.explanation;
  document.getElementById('explainToggle').textContent = cgTranslate('explain_toggle');

  card.classList.remove('hidden');

  requestAnimationFrame(() => {
    setTimeout(() => animateScore(r.score, r.level), 80);
  });

  setTimeout(() => card.scrollIntoView({ behavior:'smooth', block:'nearest' }), 200);
}

/* ─────────────────────────────────────
   SAVE TO HISTORY
───────────────────────────────────── */
function saveToHistory(result) {
  try {
    const mod = state.currentModule;
    let content = '';

    if (mod === 'url') {
      content = document.getElementById('url-input').value.trim();
    } else if (mod === 'image') {
      content = state.imageFile?.name || 'Unnamed image';
    } else if (mod === 'msg') {
      const msg = document.getElementById('msg-input').value.trim();
      content = msg.substring(0, 200);
    }

    const scan = {
      type: mod,
      content: content,
      score: result.score,
      level: result.level,
      category: result.category,
      timestamp: new Date().toISOString()
    };

    const history = JSON.parse(localStorage.getItem('cg_scanHistory') || '[]');
    history.push(scan);
    localStorage.setItem('cg_scanHistory', JSON.stringify(history));
  } catch (err) {
    console.error('Error saving to history:', err);
  }
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
      txt.textContent = humanExplanation || cgTranslate('explain_no_simple');
      btn.textContent = cgTranslate('explain_show_technical');
    } else {
      state.explanationMode = 'technical';
      txt.textContent = explanation;
      btn.textContent = cgTranslate('explain_toggle');
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
    errorEl.textContent = cgTranslate('auth_passwords_no_match');
    errorEl.classList.remove('hidden');
    return;
  }

  submitBtn.disabled    = true;
  submitBtn.textContent = cgTranslate('auth_please_wait');

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
        errorEl.textContent = data.message || cgTranslate('auth_account_created');
        errorEl.style.color = 'var(--green)';
        errorEl.classList.remove('hidden');
      }
    } else {
      errorEl.textContent = data.message || cgTranslate('auth_error_generic');
      errorEl.classList.remove('hidden');
    }
  } catch {
    errorEl.textContent = cgTranslate('auth_network_error');
    errorEl.classList.remove('hidden');
  } finally {
    submitBtn.disabled    = false;
    submitBtn.textContent = endpoint.includes('signin') ? cgTranslate('navbar_signin') : cgTranslate('auth_create_account');
  }
}

/* ─────────────────────────────────────
   SIGN OUT
───────────────────────────────────── */
async function signOut() {
  try {
    localStorage.removeItem('cg_currentUser');
    if (window.Clerk && typeof Clerk.signOut === 'function') {
      await Clerk.signOut();
    }
  } catch (err) {
    console.warn('Sign out error:', err);
  }
  window.location.href = '/';
}

/* ─────────────────────────────────────
   HISTORY
───────────────────────────────────── */
async function loadHistory() {
  const table = document.getElementById('historyTable');
  const empty = document.getElementById('historyEmpty');
  const tbody = document.getElementById('historyTableBody') || table?.querySelector('tbody');
  if (!table) return;

  if (!clerkUser) {
    window.location.href = '/signin';
    return;
  }

  try {
    const res = await fetch('/api/history?user_id=' + encodeURIComponent(clerkUser.id));
    const data = await res.json();
    const list = data.success ? data.history : [];

    if (list.length === 0) {
      table.style.display = 'none';
      if (empty) empty.style.display = 'block';
      return;
    }

    table.style.display = 'table';
    if (empty) empty.style.display = 'none';
    tbody.innerHTML = '';

    const levelColors = {
      Safe: '#22C55E',
      Suspicious: '#F59E0B',
      Phishing: '#EF4444',
      'Social Engineering': '#EF4444',
      Alert: '#F59E0B',
      'Image Phishing': '#EF4444'
    };

    list.forEach((scan) => {
      const row = document.createElement('tr');
      const date = new Date(scan.created_at).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
      const content = scan.content.length > 60 ? scan.content.substring(0, 60) + '...' : scan.content;
      const level = normalizeResult(scan).level;
      const icon = scan.type === 'url' ? 'URL' : scan.type === 'image' ? 'Image' : 'Message';

      row.innerHTML = `
        <td style="padding: 14px; border-bottom: 1px solid rgba(255,255,255,0.05);">
          <span style="word-break: break-all; font-family: monospace; font-size: 0.85rem;">${escapeHtml(content)}</span>
          <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">${icon}</div>
        </td>
        <td style="padding: 14px; border-bottom: 1px solid rgba(255,255,255,0.05); color: var(--text-sub);">${escapeHtml(scan.category)}</td>
        <td style="padding: 14px; border-bottom: 1px solid rgba(255,255,255,0.05); text-align: center;">
          <span style="display: inline-block; padding: 6px 12px; border-radius: 6px; font-weight: 600; font-size: 0.85rem; background: rgba(${level === 'safe' ? '34,197,94' : level === 'suspicious' ? '245,158,11' : '239,68,68'},0.15); color: ${levelColors[scan.category] || '#F59E0B'};">${scan.score}%</span>
        </td>
        <td style="padding: 14px; border-bottom: 1px solid rgba(255,255,255,0.05); text-align: right; font-size: 0.85rem; color: var(--text-muted);">${date}</td>
      `;
      tbody.appendChild(row);
    });
  } catch (err) {
    console.error('Error loading history:', err);
    if (empty) { empty.textContent = cgTranslate('history_load_failed'); empty.style.display = 'block'; }
    table.style.display = 'none';
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
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text ?? '';
  return div.innerHTML;
}

const ACADEMY_MODULES = {
  password: {
    icon: 'lock',
    get title() { return cgTranslate('academy_password_strength_title'); },
    get subtitle() { return cgTranslate('academy_password_strength_subtitle'); },
  },
  phishing: {
    icon: 'phishing',
    get title() { return cgTranslate('academy_phishing_title'); },
    get subtitle() { return cgTranslate('academy_phishing_subtitle'); },
  },
  quiz: {
    icon: 'quiz',
    get title() { return cgTranslate('academy_quiz_title'); },
    get subtitle() { return cgTranslate('academy_quiz_subtitle'); },
  },
  network: {
    icon: 'security',
    get title() { return cgTranslate('academy_network_title'); },
    get subtitle() { return cgTranslate('academy_network_subtitle'); },
  },
};

function cgI18n(key) {
  try {
    if (typeof cgTranslate === 'function') return cgTranslate(key);
  } catch (e) {}
  return key;
}


const academyQuizQuestions = [
  {
    questionText: 'You receive a login link from a sender you do not recognize. What is the safest first action?',
    optionsText: ['Open the link in private mode', 'Verify the sender and domain first', 'Forward it to everyone'],
    answer: 1,
    detailText: 'Verifying the sender and domain prevents credential theft before any click happens.',
  },
  {
    questionText: 'Which password is strongest?',
    optionsText: ['Company2026!', 'blue-car-9', 'Mango!River#72Vault'],
    answer: 2,
    detailText: 'Long, mixed, less predictable passphrases are harder to crack.',
  },
  {
    questionText: 'A public Wi-Fi network asks you to install a certificate. What should you do?',
    optionsText: ['Install it quickly', 'Avoid it unless your organization confirms it', 'Disable your firewall'],
    answer: 1,
    detailText: 'Unexpected certificates can let attackers inspect encrypted traffic.',
  },
  {
    questionText: 'What is a zero-day exploit?',
    optionsText: ['An attack that targets a vulnerability unknown to the vendor', 'A patch released for a known bug', 'A password reused across accounts', 'A type of firewall rule'],
    answer: 0,
    detailText: 'A zero-day exploit takes advantage of a flaw the vendor has not patched yet.',
  },
  {
    questionText: 'What does HTTPS ensure?',
    optionsText: ['Confidentiality and integrity between client and server', 'That the site is always legitimate', 'That the server never gets hacked', 'That passwords are never stored in plaintext'],
    answer: 0,
    detailText: 'HTTPS provides encryption (confidentiality) and protects data integrity in transit.',
  },
  {
    questionText: 'What is social engineering?',
    optionsText: ['Tricking people into revealing credentials or performing unsafe actions', 'Encrypting network traffic with TLS', 'Blocking inbound connections with a firewall', 'Updating antivirus signatures automatically'],
    answer: 0,
    detailText: 'Social engineering manipulates humans—not software—to get sensitive info or access.',
  },
  {
    questionText: 'Which is the safest way to store passwords?',
    optionsText: ['Plaintext in a database', 'Reversible encryption with a shared key', 'Strong salted hashing (e.g., bcrypt/Argon2)', 'Encoding with Base64'],
    answer: 2,
    detailText: 'Passwords should be stored as salted hashes using a strong password hashing function.',
  },
  {
    questionText: 'What is a man-in-the-middle attack?',
    optionsText: ['An attacker secretly relays and/or alters communication between two parties', 'A firewall that blocks malicious IPs', 'A backup system for servers', 'A secure boot process'],
    answer: 0,
    detailText: 'In MITM attacks, the attacker intercepts traffic so victims think they’re connected directly.',
  },
  {
    questionText: 'What does a VPN primarily protect?',
    optionsText: ['Your internet traffic from eavesdropping by creating an encrypted tunnel', 'Your device from malware without any updates', 'Your passwords from phishing links', 'The physical security of your router'],
    answer: 0,
    detailText: 'A VPN creates an encrypted tunnel that helps protect data in transit on untrusted networks.',
  },
  {
    questionText: 'What is two-factor authentication?',
    optionsText: ['Authentication using only one factor (password)', 'Authentication using two separate verification methods', 'Authentication that disables all login attempts', 'A backup for expired passwords'],
    answer: 1,
    detailText: '2FA adds an extra verification step (e.g., code/app + password).',
  },
  {
    questionText: 'What is the purpose of a firewall?',
    optionsText: ['Allow or block network traffic based on security rules', 'Automatically generate strong passwords', 'Encrypt all files on disk', 'Turn a public network into a private one'],
    answer: 0,
    detailText: 'Firewalls enforce inbound/outbound traffic policies to reduce the attack surface.',
  },
];



let academyQuizIndex = 0;
let academyQuizScore = 0;
let academyNetworkScore = 0;

function initAcademy() {
  const body = document.getElementById('academySimBody');
  if (!body) return;

  document.querySelectorAll('[data-academy-module]').forEach((card) => {
    // Prevent double-binding if initAcademy() is ever called again.
    if (card.dataset.academyBound === '1') return;
    card.dataset.academyBound = '1';
    card.addEventListener('click', () => setAcademyModule(card.dataset.academyModule));
  });

  // Only set default module if nothing is active yet.
  const active = document.querySelector('[data-academy-module].active');
  if (!active) setAcademyModule('password');
}






function setAcademyModule(moduleName) {
  const config = ACADEMY_MODULES[moduleName] || ACADEMY_MODULES.password;
  document.querySelectorAll('[data-academy-module]').forEach((card) => {
    card.classList.toggle('active', card.dataset.academyModule === moduleName);
  });

  const icon = document.getElementById('academySimIcon');
  const title = document.getElementById('academySimTitle');
  const subtitle = document.getElementById('academySimSubtitle');
  if (icon) icon.textContent = config.icon;
  if (title) title.textContent = config.title;
  if (subtitle) subtitle.textContent = config.subtitle;

  if (moduleName === 'phishing') renderPhishingTrainer();
  else if (moduleName === 'quiz') renderSecurityQuiz();
  else if (moduleName === 'network') renderNetworkDefense();
  else renderPasswordTrainer();
}

function renderPasswordTrainer() {
  const body = document.getElementById('academySimBody');
  body.innerHTML = `
    <div class="password-field">
      <input id="academyPassword" type="password" value="CyberSec2026!" aria-label="Password payload" />
      <button type="button" id="academyPasswordToggle"><span class="material-symbols-outlined">visibility</span></button>
    </div>
    <div class="strength-row"><span>${cgTranslate('academy_password_strength_label')}</span><strong id="academyStrengthLabel">${cgTranslate('academy_password_strength_strong') || 'Strong'}</strong></div>
    <div class="strength-meter" id="academyStrengthMeter"><span></span><span></span><span></span><span class="empty"></span></div>
    <div class="academy-score-line"><span id="academyPasswordScore">${cgTranslate('academy_password_strength_score_label')}: 0/100</span></div>
    <div class="feedback-chips" id="academyPasswordFeedback"></div>
  `;

  const input = document.getElementById('academyPassword');
  const toggle = document.getElementById('academyPasswordToggle');
  toggle.addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
    toggle.querySelector('.material-symbols-outlined').textContent = input.type === 'password' ? 'visibility' : 'visibility_off';
  });
  input.addEventListener('input', updatePasswordTrainer);
  updatePasswordTrainer();
}

function updatePasswordTrainer() {
  const value = document.getElementById('academyPassword')?.value || '';
  const checks = [
    { ok: value.length >= 12, label: cgTranslate('academy_rule_length') },
    { ok: /[A-Z]/.test(value) && /[a-z]/.test(value), label: cgTranslate('academy_rule_upper_lower') },
    { ok: /\d/.test(value), label: cgTranslate('academy_rule_number') },
    { ok: /[^A-Za-z0-9]/.test(value), label: cgTranslate('academy_rule_special') },
    { ok: !/(password|admin|cyber|qwerty|1234)/i.test(value), label: cgTranslate('academy_rule_no_dict_word') },
  ];
  const score = Math.min(100, checks.filter(check => check.ok).length * 20 + Math.min(10, Math.max(0, value.length - 12)));
  const level = score >= 85
    ? cgTranslate('academy_password_strength_excellent')
    : score >= 65
      ? cgTranslate('academy_password_strength_strong')
      : score >= 40
        ? cgTranslate('academy_password_strength_medium')
        : cgTranslate('academy_password_strength_weak');
  const bars = score >= 85 ? 4 : score >= 65 ? 3 : score >= 40 ? 2 : 1;

  document.getElementById('academyStrengthLabel').textContent = level;
  document.getElementById('academyPasswordScore').textContent = `${cgTranslate('academy_password_strength_score_label')}: ${score}/100`;
  document.getElementById('academyStrengthMeter').innerHTML = [0, 1, 2, 3]
    .map(index => `<span class="${index >= bars ? 'empty' : ''}"></span>`)
    .join('');
  document.getElementById('academyPasswordFeedback').innerHTML = checks.map(check => `
    <span><span class="material-symbols-outlined ${check.ok ? '' : 'warn'}">${check.ok ? 'check_circle' : 'cancel'}</span>${check.label}</span>
  `).join('');
}

function renderPhishingTrainer() {
  const body = document.getElementById('academySimBody');

  const phishingScenarios = [
  {
    prompt: cgTranslate('academy_phishing_s1_prompt'),
    correctAnswer: 'phishing',
    correctDetail: cgTranslate('academy_phishing_s1_correct'),
    wrongDetail: cgTranslate('academy_phishing_s1_wrong')
  },
  {
    prompt: cgTranslate('academy_phishing_s2_prompt'),
    correctAnswer: 'phishing',
    correctDetail: cgTranslate('academy_phishing_s2_correct'),
    wrongDetail: cgTranslate('academy_phishing_s2_wrong')
  },
  {
    prompt: cgTranslate('academy_phishing_s3_prompt'),
    correctAnswer: 'phishing',
    correctDetail: cgTranslate('academy_phishing_s3_correct'),
    wrongDetail: cgTranslate('academy_phishing_s3_wrong')
  },
  {
    prompt: cgTranslate('academy_phishing_s4_prompt'),
    correctAnswer: 'phishing',
    correctDetail: cgTranslate('academy_phishing_s4_correct'),
    wrongDetail: cgTranslate('academy_phishing_s4_wrong')
  },
  {
    prompt: cgTranslate('academy_phishing_s5_prompt'),
    correctAnswer: 'phishing',
    correctDetail: cgTranslate('academy_phishing_s5_correct'),
    wrongDetail: cgTranslate('academy_phishing_s5_wrong')
  },
  {
    prompt: cgTranslate('academy_phishing_s6_prompt'),
    correctAnswer: 'phishing',
    correctDetail: cgTranslate('academy_phishing_s6_correct'),
    wrongDetail: cgTranslate('academy_phishing_s6_wrong')
  },
  {
    prompt: cgTranslate('academy_phishing_s7_prompt'),
    correctAnswer: 'phishing',
    correctDetail: cgTranslate('academy_phishing_s7_correct'),
    wrongDetail: cgTranslate('academy_phishing_s7_wrong')
  }
];

  if (typeof renderPhishingTrainer.currentScenarioIndex !== 'number') {
    renderPhishingTrainer.currentScenarioIndex = Math.floor(Math.random() * phishingScenarios.length);
  }

  const scenario = phishingScenarios[renderPhishingTrainer.currentScenarioIndex];

  function rerenderScenario() {
    const nextIndex = phishingScenarios.length > 1
      ? (() => {
          let idx = renderPhishingTrainer.currentScenarioIndex;
          while (idx === renderPhishingTrainer.currentScenarioIndex) {
            idx = Math.floor(Math.random() * phishingScenarios.length);
          }
          return idx;
        })()
      : renderPhishingTrainer.currentScenarioIndex;

    renderPhishingTrainer.currentScenarioIndex = nextIndex;
    const nextScenario = phishingScenarios[renderPhishingTrainer.currentScenarioIndex];

    document.getElementById('academySimBody').innerHTML = `
      <div class="academy-challenge" style="position:relative;">
        <button type="button" class="premium-primary-btn compact" id="academyNewPhishingScenarioBtn" disabled style="display:flex;align-items:center;gap:6px;margin-top:16px;margin-left:auto;padding:8px 20px;font-size:0.82rem;opacity:0.35;border-radius:10px;cursor:not-allowed;transition:opacity 0.2s ease;">${cgTranslate('common_next')} <span class="material-symbols-outlined" style="font-size:18px;">navigate_next</span></button>
        <div class="message-card">
          <strong>${cgTranslate('academy_phishing_notice_title')}</strong>
          <p>${escapeHtml(nextScenario.prompt)}</p>
        </div>
        <div class="academy-options">
          <button type="button" data-phishing-answer="safe">${cgTranslate('academy_phishing_choice_safe')}</button>
          <button type="button" data-phishing-answer="phishing">${cgTranslate('academy_phishing_choice_phishing')}</button>
        </div>
        <div class="academy-result" id="academyPhishingResult">${cgTranslate('academy_phishing_result_choose')}</div>
      </div>
    `;

    document.querySelectorAll('[data-phishing-answer]').forEach((button) => {
      button.addEventListener('click', () => {
        const correct = button.dataset.phishingAnswer === nextScenario.correctAnswer;
        renderAcademyResult(
          'academyPhishingResult',
          correct,
          correct ? nextScenario.correctDetail : nextScenario.wrongDetail
        );
        const nextBtn = document.getElementById('academyNewPhishingScenarioBtn');
        if (nextBtn) { nextBtn.disabled = false; nextBtn.style.opacity = '0.65'; nextBtn.style.cursor = 'pointer'; }
        document.querySelectorAll('[data-phishing-answer]').forEach(b => b.disabled = true);
      });
    });

    const btn = document.getElementById('academyNewPhishingScenarioBtn');
    if (btn) btn.addEventListener('click', rerenderScenario);
  }

  body.innerHTML = `
    <div class="academy-challenge" style="position:relative;">
      <button type="button" class="premium-primary-btn compact" id="academyNewPhishingScenarioBtn" disabled style="display:flex;align-items:center;gap:6px;margin-top:16px;margin-left:auto;padding:8px 20px;font-size:0.82rem;opacity:0.35;border-radius:10px;cursor:not-allowed;transition:opacity 0.2s ease;">${cgTranslate('common_next')} <span class="material-symbols-outlined" style="font-size:18px;">navigate_next</span></button>
      <div class="message-card">
        <strong>${cgTranslate('academy_phishing_notice_title')}</strong>
        <p>${escapeHtml(scenario.prompt)}</p>
      </div>
      <div class="academy-options">
        <button type="button" data-phishing-answer="safe">${cgTranslate('academy_phishing_choice_safe')}</button>
        <button type="button" data-phishing-answer="phishing">${cgTranslate('academy_phishing_choice_phishing')}</button>
      </div>
      <div class="academy-result" id="academyPhishingResult">${cgTranslate('academy_phishing_result_choose')}</div>
    </div>
  `;

  document.querySelectorAll('[data-phishing-answer]').forEach((button) => {
    button.addEventListener('click', () => {
      const correct = button.dataset.phishingAnswer === scenario.correctAnswer;
      renderAcademyResult('academyPhishingResult', correct, correct
        ? scenario.correctDetail
        : scenario.wrongDetail);
      const nextBtn = document.getElementById('academyNewPhishingScenarioBtn');
      if (nextBtn) { nextBtn.disabled = false; nextBtn.style.opacity = '0.65'; nextBtn.style.cursor = 'pointer'; }
      document.querySelectorAll('[data-phishing-answer]').forEach(b => b.disabled = true);
    });
  });

  const btn = document.getElementById('academyNewPhishingScenarioBtn');
  if (btn) btn.addEventListener('click', rerenderScenario);
}

function renderSecurityQuiz() {
  academyQuizIndex = 0;
  academyQuizScore = 0;
  renderQuizQuestion();
}

function renderQuizQuestion() {
  const body = document.getElementById('academySimBody');
  const item = academyQuizQuestions[academyQuizIndex];

  // Quiz is translated via i18n keys stored in static/js/i18n.js
  const q = cgTranslate(`academy_quiz_q${academyQuizIndex + 1}`) || '';
  const options = [0, 1, 2, 3].map((idx) => {
    const letter = ['a','b','c','d'][idx];
    return cgTranslate(`academy_quiz_q${academyQuizIndex + 1}_${letter}`) || '';
  }).filter(Boolean);
  const detail = cgTranslate(`academy_quiz_q${academyQuizIndex + 1}_explain`) || '';

  // Keep consistent: question/options are translated, but scoring uses item.answer.





  body.innerHTML = `
    <div class="academy-challenge">
      <div class="academy-score-line">${academyQuizIndex + 1}/${academyQuizQuestions.length} · ${cgTranslate('academy_password_strength_score_label')} ${academyQuizScore}</div>
      <h3>${escapeHtml(q)}</h3>
      <div class="academy-options">
        ${options.map((option, index) => `<button type="button" data-quiz-answer="${index}">${escapeHtml(option)}</button>`).join('')}
      </div>
      <div class="academy-result" id="academyQuizResult">${cgTranslate('academy_quiz_result_choose')}</div>
    </div>
  `;


  document.querySelectorAll('[data-quiz-answer]').forEach((button) => {
    button.addEventListener('click', () => {
      const selected = Number(button.dataset.quizAnswer);
      const correct = selected === item.answer;
      if (correct) academyQuizScore += 1;
      renderAcademyResult('academyQuizResult', correct, detail);
      document.querySelectorAll('[data-quiz-answer]').forEach(btn => btn.disabled = true);
      setTimeout(() => {
        academyQuizIndex += 1;
        if (academyQuizIndex >= academyQuizQuestions.length) renderQuizSummary();
        else renderQuizQuestion();
      }, 1100);
    });
  });
}


function renderQuizSummary() {
  document.getElementById('academySimBody').innerHTML = `
    <div class="academy-challenge">
      <h3>${cgTranslate('academy_quiz_complete_title')}</h3>
      <p class="academy-score-line">${cgTranslate('academy_quiz_final_score_label')}: ${academyQuizScore}/${academyQuizQuestions.length}</p>
      <button class="premium-primary-btn compact" type="button" onclick="renderSecurityQuiz()">${cgTranslate('academy_quiz_restart')}</button>
    </div>
  `;
}

function renderNetworkDefense() {
  academyNetworkScore = 0;
  const body = document.getElementById('academySimBody');

  const networkScenarios = [
  { prompt: cgTranslate('academy_network_s1_prompt'), correctAnswer: 'isolate' },
  { prompt: cgTranslate('academy_network_s2_prompt'), correctAnswer: 'isolate' },
  { prompt: cgTranslate('academy_network_s3_prompt'), correctAnswer: 'isolate' },
  { prompt: cgTranslate('academy_network_s4_prompt'), correctAnswer: 'isolate' },
  { prompt: cgTranslate('academy_network_s5_prompt'), correctAnswer: 'isolate' },
  { prompt: cgTranslate('academy_network_s6_prompt'), correctAnswer: 'isolate' },
];

  if (typeof renderNetworkDefense.currentScenarioIndex !== 'number') {
    renderNetworkDefense.currentScenarioIndex = Math.floor(Math.random() * networkScenarios.length);
  }

  const scenario = networkScenarios[renderNetworkDefense.currentScenarioIndex];

  function rerenderScenario() {
    const nextIndex = networkScenarios.length > 1
      ? (() => {
          let idx = renderNetworkDefense.currentScenarioIndex;
          while (idx === renderNetworkDefense.currentScenarioIndex) {
            idx = Math.floor(Math.random() * networkScenarios.length);
          }
          return idx;
        })()
      : renderNetworkDefense.currentScenarioIndex;

    renderNetworkDefense.currentScenarioIndex = nextIndex;
    const nextScenario = networkScenarios[renderNetworkDefense.currentScenarioIndex];

    document.getElementById('academySimBody').innerHTML = `
      <div class="academy-challenge" style="position:relative;">
        <button type="button" class="premium-primary-btn compact" id="academyNewNetworkScenarioBtn" disabled style="display:flex;align-items:center;gap:6px;margin-top:16px;margin-left:auto;padding:8px 20px;font-size:0.82rem;opacity:0.35;border-radius:10px;cursor:not-allowed;transition:opacity 0.2s ease;">${cgTranslate('common_next')} <span class="material-symbols-outlined" style="font-size:18px;">navigate_next</span></button>
        <div class="message-card">
          <strong>${cgTranslate('academy_network_incident_title')}</strong>
          <p>${escapeHtml(nextScenario.prompt)}</p>
        </div>
        <div class="academy-options">
          <button type="button" data-network-answer="ignore">${cgTranslate('academy_network_choice_ignore')}</button>
          <button type="button" data-network-answer="isolate">${cgTranslate('academy_network_choice_isolate')}</button>
          <button type="button" data-network-answer="wipe">${cgTranslate('academy_network_choice_wipe')}</button>
        </div>
        <div class="academy-result" id="academyNetworkResult">${cgTranslate('academy_network_result_choose')}</div>
      </div>
    `;

    document.querySelectorAll('[data-network-answer]').forEach((button) => {
      button.addEventListener('click', () => {
        const correct = button.dataset.networkAnswer === nextScenario.correctAnswer;
        academyNetworkScore = correct ? 100 : 35;
        renderAcademyResult(
          'academyNetworkResult',
          correct,
          correct
            ? `${cgTranslate('academy_network_result_correct_prefix')} ${academyNetworkScore}/100${cgTranslate('academy_network_result_correct_suffix')}`
            : `${cgTranslate('academy_network_result_risky_prefix')} ${academyNetworkScore}/100${cgTranslate('academy_network_result_risky_suffix')}`
        );

        const nextBtn = document.getElementById('academyNewNetworkScenarioBtn');
        if (nextBtn) { nextBtn.disabled = false; nextBtn.style.opacity = '0.65'; nextBtn.style.cursor = 'pointer'; }
        document.querySelectorAll('[data-network-answer]').forEach(b => b.disabled = true);
      });
    });

    const btn = document.getElementById('academyNewNetworkScenarioBtn');
    if (btn) btn.addEventListener('click', rerenderScenario);
  }

  body.innerHTML = `
    <div class="academy-challenge" style="position:relative;">
      <button type="button" class="premium-primary-btn compact" id="academyNewNetworkScenarioBtn" disabled style="display:flex;align-items:center;gap:6px;margin-top:16px;margin-left:auto;padding:8px 20px;font-size:0.82rem;opacity:0.35;border-radius:10px;cursor:not-allowed;transition:opacity 0.2s ease;">${cgTranslate('common_next')} <span class="material-symbols-outlined" style="font-size:18px;">navigate_next</span></button>
      <div class="message-card">
        <strong>${cgTranslate('academy_network_incident_title')}</strong>
        <p>${escapeHtml(scenario.prompt)}</p>
      </div>
      <div class="academy-options">
        <button type="button" data-network-answer="ignore">${cgTranslate('academy_network_choice_ignore')}</button>
        <button type="button" data-network-answer="isolate">${cgTranslate('academy_network_choice_isolate')}</button>
        <button type="button" data-network-answer="wipe">${cgTranslate('academy_network_choice_wipe')}</button>
      </div>
      <div class="academy-result" id="academyNetworkResult">${cgTranslate('academy_network_result_choose')}</div>
    </div>
  `;

  document.querySelectorAll('[data-network-answer]').forEach((button) => {
    button.addEventListener('click', () => {
      const correct = button.dataset.networkAnswer === scenario.correctAnswer;
      academyNetworkScore = correct ? 100 : 35;
      renderAcademyResult(
        'academyNetworkResult',
        correct,
        correct
          ? `${cgTranslate('academy_network_result_correct_prefix')} ${academyNetworkScore}/100${cgTranslate('academy_network_result_correct_suffix')}`
          : `${cgTranslate('academy_network_result_risky_prefix')} ${academyNetworkScore}/100${cgTranslate('academy_network_result_risky_suffix')}`
      );

      const nextBtn = document.getElementById('academyNewNetworkScenarioBtn');
      if (nextBtn) { nextBtn.disabled = false; nextBtn.style.opacity = '0.65'; nextBtn.style.cursor = 'pointer'; }
      document.querySelectorAll('[data-network-answer]').forEach(b => b.disabled = true);
    });
  });

  const btn = document.getElementById('academyNewNetworkScenarioBtn');
  if (btn) btn.addEventListener('click', rerenderScenario);
}

function renderAcademyResult(id, correct, message) {
  const result = document.getElementById(id);
  if (!result) return;
  result.classList.toggle('success', correct);
  result.classList.toggle('danger', !correct);
  result.textContent = message;
}

/* ─────────────────────────────────────
   INIT
───────────────────────────────────── */
async function syncClerkUser() {
  await initClerk();
}

document.addEventListener('DOMContentLoaded', async () => {
  await initClerk();

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

  // Initialize hero animations
  initializeHeroAnimations();

  // Initialize stats scroll animation
  initializeStatsScrollAnimation();
  initializeThemeToggleButton();
  initAcademy();

  console.log('%c🛡️ CyberGuard AI ready', 'color:#3B82F6;font-weight:bold;font-size:14px');
});

window.addEventListener('load', async () => {
  await initClerk();
});

/* ─────────────────────────────────────
   HERO ANIMATIONS
───────────────────────────────────── */
function initializeHeroAnimations() {
  const heroTitle = document.querySelector('.hero-title');
  const heroBadge = document.querySelector('.hero-badge');
  const heroSub = document.querySelector('.hero-sub');
  
  // Fade animation for badge
  if (heroBadge) {
    heroBadge.style.animation = 'fade 2s ease-out both';
  }
  
  if (heroTitle) {
    prepareHeroTitleLines(heroTitle);
  }

  if (heroSub) {
    heroSub.style.animation = 'slideUpFade 1.4s cubic-bezier(0.22,1,0.36,1) 0.4s both';
  }
}

function prepareHeroTitleLines(element) {
  const originalHTML = element.innerHTML.trim();
  const parts = originalHTML.split(/<br\s*\/?>/i);
  element.innerHTML = '';

  parts.forEach((part, index) => {
    const lineWrapper = document.createElement('span');
    lineWrapper.className = 'hero-line';
    lineWrapper.style.setProperty('--delay', `${index * 0.18}s`);

    const inner = document.createElement('span');
    inner.className = 'hero-line-inner';
    inner.innerHTML = part.trim();

    lineWrapper.appendChild(inner);
    element.appendChild(lineWrapper);
  });

  const lineItems = element.querySelectorAll('.hero-line-inner');

  if (window.gsap?.to) {
    window.gsap.set(lineItems, {
      y: 28,
      opacity: 0,
      filter: 'blur(16px)'
    });

    window.gsap.to(lineItems, {
      y: 0,
      opacity: 1,
      filter: 'blur(0px)',
      duration: 1.2,
      ease: 'cubic-bezier(0.22, 1, 0.36, 1)',
      stagger: 0.18
    });
  } else {
    requestAnimationFrame(() => {
      setTimeout(() => element.classList.add('hero-title-animated'), 100);
    });
  }
}

function initializeStatsScrollAnimation() {
  const statsElement = document.querySelector('.hero-stats');
  if (!statsElement) return;

  // Create intersection observer for stats pop-up animation on scroll
  const observerOptions = {
    threshold: 0.3,
    rootMargin: '0px 0px -50px 0px'
  };

  // NOTE UX: animations doivent démarrer quand on arrive proche du bloc,
  // et ne pas “pousser” le rendu en haut de page.
  // On anime au moment où .hero-stats est à 80% visible.
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting && !entry.target.classList.contains('stats-animated')) {
        entry.target.classList.add('stats-animated');
        entry.target.style.animation = 'popScale 1.8s cubic-bezier(0.22,1,0.36,1) forwards';
        entry.target.style.opacity = '1';
        observer.unobserve(entry.target);
      }
    });
  }, { ...observerOptions, threshold: 0.8 });

  observer.observe(statsElement);
}

/* ─────────────────────────────────────
   UPDATE USER PROFILE
───────────────────────────────────── */
function updateUserProfile() {
  updateNavbar();
}

function initializeThemeToggleButton() {
  const button = document.getElementById('themeToggleBtn');
  if (!button) return;

  button.addEventListener('click', () => {
    const btn = document.getElementById('themeToggleBtn');
    const icon = btn?.querySelector('.material-symbols-outlined');
    if (!btn) return;

    // Anti double-click during morph
    if (btn.dataset.themeMorphing === '1') return;
    btn.dataset.themeMorphing = '1';

    // Morph sun ↔ moon illusion
    btn.classList.remove('theme-morph-complete');
    btn.classList.add('theme-morph');
    if (icon) icon.style.willChange = 'transform, filter, opacity';

    // Apply theme change while morph is playing
    if (typeof toggleTheme === 'function') toggleTheme();

    // Next frame: finish morph
    requestAnimationFrame(() => {
      updateThemeToggleIcon();
      btn.classList.add('theme-morph-complete');

      // Cleanup after animation
      setTimeout(() => {
        btn.classList.remove('theme-morph');
        btn.classList.remove('theme-morph-complete');
        btn.dataset.themeMorphing = '0';
        if (icon) icon.style.willChange = '';
      }, 520);
    });

    updateScrollBtnIcon?.();
    updateSettingsHighlights();
  });

  updateThemeToggleIcon();
}

function updateThemeToggleIcon() {
  const button = document.getElementById('themeToggleBtn');
  const icon = button?.querySelector('.material-symbols-outlined');
  if (!button || !icon) return;

  const isLight = document.body.classList.contains('light-mode')
    || document.documentElement.getAttribute('data-theme') === 'light';
  icon.textContent = isLight ? 'dark_mode' : 'light_mode';
  button.setAttribute('aria-label', isLight ? 'Switch to dark mode' : 'Switch to light mode');
  button.setAttribute('title', isLight ? 'Dark mode' : 'Light mode');
}

/* ─────────────────────────────────────
   SETTINGS MENU (Language / Theme)
───────────────────────────────────── */
function initializeSettings() {
  const settingsBtn = document.getElementById('settingsBtn');
  const settingsDropdown = document.getElementById('settingsDropdown');

  if (settingsBtn && settingsDropdown) {
    /* ── Sortir le dropdown du conteneur relatif
          et l'attacher directement au body ── */
    document.body.appendChild(settingsDropdown);

    function positionDropdown() {
    const rect = settingsBtn.getBoundingClientRect();
    settingsDropdown.style.position   = 'fixed';
    /* APRÈS */
    settingsDropdown.style.top        = (rect.bottom + 8) + 'px';
    settingsDropdown.style.right      = (window.innerWidth - rect.right) + 'px';
    settingsDropdown.style.left       = 'auto';
    settingsDropdown.style.width      = 'auto';
    settingsDropdown.style.minWidth   = '238px';
    settingsDropdown.style.zIndex     = '99999';

    /* Sur petit écran → pleine largeur sous la navbar */
    if (window.innerWidth <= 768) {
      settingsDropdown.style.left   = '0';
      settingsDropdown.style.right  = '0';
      settingsDropdown.style.width  = '100%';
      settingsDropdown.style.borderRadius = '0';
    } else {
      settingsDropdown.style.borderRadius = '14px';
    }
  }

  settingsBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    e.preventDefault();
    const isOpen = settingsDropdown.style.display === 'block';
    if (isOpen) {
      settingsDropdown.style.display = 'none';
    } else {
      positionDropdown();
      settingsDropdown.style.display = 'block';
      updateSettingsHighlights();
    }
  });

  document.addEventListener('click', (e) => {
    if (!settingsBtn.contains(e.target) && !settingsDropdown.contains(e.target)) {
      settingsDropdown.style.display = 'none';
    }
  });

  window.addEventListener('resize', () => {
    if (settingsDropdown.style.display === 'block') positionDropdown();
  });
  }

  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const lang = btn.dataset.lang;
      if (!lang) return;
      changeLanguage(lang);
      updateSettingsHighlights();
    });
  });

  document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const theme = btn.dataset.theme;
      if (!theme) return;
      changeTheme(theme);
      updateSettingsHighlights();
      if (settingsDropdown) {
        setTimeout(() => { settingsDropdown.style.display = 'none'; }, 400);
      }
    });
  });

  updateSettingsHighlights();
}

function updateSettingsHighlights() {
  const currentLang = localStorage.getItem('cg_language') || 'en';
  const currentTheme = localStorage.getItem('cg_theme') || 'dark';

  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.lang === currentLang);
  });

  document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.theme === currentTheme);
  });
}

/* ─────────────────────────────────────
   SCROLL REVEAL — HOW SECTION
───────────────────────────────────── */
const revealTargets = document.querySelectorAll(
  '.how-title, .how-sub, .how-note, .step-item'
);

const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('in-view');
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.15 });

revealTargets.forEach(el => revealObserver.observe(el));

/* ── Scroll-to-Top: Radial Progress Engine ── */
(function () {
  'use strict';
  var CIRC = 2 * Math.PI * 24; // ≈ 150.796 (circumference of r=24)
  var _btn, _ring, _arrowD, _arrowL, _rafId, _lastScroll = -1;

  function _getDocHeight() {
    return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight) - window.innerHeight;
  }
  function _updateRing(y) {
    if (!_ring) return;
    var pct = Math.min(y / (_getDocHeight() || 1), 1);
    var filled = Math.round(pct * CIRC * 100) / 100;
    _ring.setAttribute('stroke-dasharray', filled + ' ' + Math.round((CIRC - filled) * 100) / 100);
  }
  function _updateVisibility(y) {
    if (!_btn) return;
    const panelOpen = document.getElementById('toolPanel')?.classList.contains('open');
    if (y > 280 && !panelOpen) {
      _btn.classList.add('stt-visible');
    } else {
      _btn.classList.remove('stt-visible');
    }
  }
  function _onScroll() {
    var y = window.scrollY || window.pageYOffset;
    if (y === _lastScroll) return;
    _lastScroll = y;
    if (_rafId) cancelAnimationFrame(_rafId);
    _rafId = requestAnimationFrame(function () { _updateVisibility(y); _updateRing(y); });
  }
  function _updateArrows() {
    if (!_arrowD || !_arrowL) return;
    var light = document.body.classList.contains('light-mode');
    _arrowD.style.display = light ? 'none' : '';
    _arrowL.style.display = light ? ''     : 'none';
  }
  function _init() {
    _btn    = document.getElementById('scrollTopBtn');
    _ring   = document.getElementById('sttProgressRing');
    _arrowD = document.querySelector('.stt-arrow-dark');
    _arrowL = document.querySelector('.stt-arrow-light');
    if (!_btn) return;
    var tip = _btn.querySelector('.stt-tooltip');
    if (tip && typeof cgTranslate === 'function') tip.textContent = cgTranslate('scroll_top_label') || 'Back to top';
    window.addEventListener('scroll', _onScroll, { passive: true });
    _updateArrows();
  }
  var _orig = window.applyTheme;
  window.applyTheme = function (t) {
    if (typeof _orig === 'function') _orig(t);
    if (typeof updateThemeToggleIcon === 'function') updateThemeToggleIcon();
    _updateArrows();
  };
  document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', _init) : _init();
})();

/* Home page: float the desktop navbar only after it begins leaving its original spot. */
(function () {
  'use strict';
  var _nav, _media, _rafId, _triggerY = 0;

  function _isHomePage() {
    return document.body && document.body.classList.contains('home-page');
  }

  function _sync() {
    if (!_nav) return;
    var isDesktop = !_media || _media.matches;
    var y = window.scrollY || window.pageYOffset;
    _nav.classList.toggle('home-nav-floating', isDesktop && y > _triggerY);
  }

  function _requestSync() {
    if (_rafId) cancelAnimationFrame(_rafId);
    _rafId = requestAnimationFrame(_sync);
  }

  function _measure() {
    if (!_nav) return;
    var wasFloating = _nav.classList.contains('home-nav-floating');
    _nav.classList.remove('home-nav-floating');
    var height = _nav.offsetHeight || 76;
    _triggerY = Math.max(16, _nav.offsetTop + (height * 0.55));
    if (wasFloating) _nav.classList.add('home-nav-floating');
    _sync();
  }

  function _init() {
    if (!_isHomePage()) return;
    _nav = document.querySelector('.navbar.premium-navbar');
    if (!_nav) return;

    _media = window.matchMedia('(min-width: 601px)');
    window.addEventListener('scroll', _requestSync, { passive: true });
    window.addEventListener('resize', _measure, { passive: true });

    if (_media.addEventListener) {
      _media.addEventListener('change', _measure);
    } else if (_media.addListener) {
      _media.addListener(_measure);
    }

    _measure();
  }

  document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', _init) : _init();
})();

/* Hide navbar on scroll down, show it as soon as the user scrolls up. */
(function () {
  'use strict';
  var _nav, _lastY = 0, _rafId;

  function _sync() {
    if (!_nav) return;
    var y = window.scrollY || window.pageYOffset || 0;

    if (y === 0 || y < _lastY) {
      _nav.classList.remove('nav-hidden');
    } else if (y > _lastY) {
      _nav.classList.add('nav-hidden');
    }

    _lastY = y;
  }

  function _requestSync() {
    if (_rafId) cancelAnimationFrame(_rafId);
    _rafId = requestAnimationFrame(_sync);
  }

  function _init() {
    _nav = document.querySelector('.navbar');
    if (!_nav) return;
    _lastY = window.scrollY || window.pageYOffset || 0;
    _sync();
    window.addEventListener('scroll', _requestSync, { passive: true });
  }

  document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', _init) : _init();
})();

function safeInitSettings() {
  if (document.getElementById('settingsBtn')) {
    initializeSettings();
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', safeInitSettings);
} else {
  safeInitSettings();
}

function toggleBurgerMenu() {
  const menu       = document.getElementById('burgerMenu');
  const btn        = document.getElementById('burgerBtn');
  const burgerAuth = document.getElementById('burgerAuth');
  const isOpen     = menu.classList.toggle('open');

  btn.querySelector('.material-symbols-outlined').textContent = isOpen ? 'close' : 'menu';

  // Cache le bouton Sign In si l'utilisateur est connecté
  if (burgerAuth) {
    const isLoggedIn = document.getElementById('profileMenu') &&
                       document.getElementById('profileMenu').style.display !== 'none' &&
                       document.getElementById('getStartedBtn') &&
                       document.getElementById('getStartedBtn').style.display === 'none';
    burgerAuth.style.display = isLoggedIn ? 'none' : 'block';
  }
}

// Ferme le burger si on clique ailleurs
document.addEventListener('click', function(e) {
  const menu = document.getElementById('burgerMenu');
  const btn  = document.getElementById('burgerBtn');
  if (menu && btn && !menu.contains(e.target) && !btn.contains(e.target)) {
    menu.classList.remove('open');
    btn.querySelector('.material-symbols-outlined').textContent = 'menu';
  }
});
