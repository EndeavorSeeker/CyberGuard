/* ─────────────────────────────────────────────
   CyberGuard AI — Theme System (Dark / Light / System)
   No external dependencies. Pure Vanilla JS.
───────────────────────────────────────────── */
'use strict';

function getEffectiveTheme() {
  const saved = localStorage.getItem('cg_theme') || 'dark';
  if (saved === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return saved;
}

function applyTheme(theme) {
  if (!['dark', 'light', 'system'].includes(theme)) theme = 'dark';
  localStorage.setItem('cg_theme', theme);

  const effective = getEffectiveTheme();
  document.documentElement.setAttribute('data-theme', effective);

  if (effective === 'light') {
    document.body.classList.add('light-mode');
    document.body.classList.remove('dark-mode');
  } else {
    document.body.classList.add('dark-mode');
    document.body.classList.remove('light-mode');
  }
}

function changeTheme(theme) { applyTheme(theme); }
function toggleTheme() {
  const cur = localStorage.getItem('cg_theme') || 'dark';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
}
function getCurrentTheme() { return localStorage.getItem('cg_theme') || 'dark'; }

/* Watch system preference changes */
if (window.matchMedia) {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (localStorage.getItem('cg_theme') === 'system') applyTheme('system');
  });
}

/* Init immediately (avoids flash of wrong theme) */
(function() {
  applyTheme(localStorage.getItem('cg_theme') || 'dark');
})();