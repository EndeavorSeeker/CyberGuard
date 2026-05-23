/* ==================== NAVIGATION & SECTIONS ==================== */
function showSection(sectionId) {
  // Hide all sections
  document.querySelectorAll('.section-home, .section-lessons, .section-games, .section-category-detail').forEach(section => {
    section.classList.remove('active-section');
  });

  // Show selected section
  const section = document.getElementById(sectionId);
  if (section) {
    section.classList.add('active-section');
    window.scrollTo(0, 0);
  }
}

function showCategory(categoryId) {
  // Hide all category contents
  document.querySelectorAll('.category-content').forEach(content => {
    content.classList.remove('active-content');
  });

  // Show selected category content
  const categoryContent = document.getElementById(`cat-${categoryId}`);
  if (categoryContent) {
    categoryContent.classList.add('active-content');
  }

  // Show category detail section
  showSection('category-detail');
}

function switchGame(gameId) {
  // Hide all games
  document.querySelectorAll('.game-container').forEach(game => {
    game.classList.remove('active-game');
  });

  // Show selected game
  const game = document.getElementById(gameId);
  if (game) {
    game.classList.add('active-game');
    
    // Initialize game based on type
    if (gameId === 'password-game') {
      initPasswordGame();
    } else if (gameId === 'phishing-game') {
      initPhishingGame();
    } else if (gameId === 'quiz-game') {
      initQuizGame();
    } else if (gameId === 'hacker-game') {
      initDefenseGame();
    }
  }
  
  // Show games section
  showSection('games');
}

function closeGame() {
  document.querySelectorAll('.game-container').forEach(game => {
    game.classList.remove('active-game');
  });
  showSection('games');
}

/* ==================== PASSWORD STRENGTH CHECKER ==================== */
function initPasswordGame() {
  const passwordInput = document.getElementById('passwordInput');
  const toggleBtn = document.getElementById('togglePwdView');
  
  if (passwordInput) {
    passwordInput.addEventListener('input', checkPasswordStrength);
  }
  
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const type = passwordInput.type === 'password' ? 'text' : 'password';
      passwordInput.type = type;
      toggleBtn.textContent = type === 'password' ? '👁️' : '🙈';
    });
  }
}

function checkPasswordStrength() {
  const password = document.getElementById('passwordInput').value;
  const feedbackEl = document.getElementById('passwordFeedback');
  const strengthBar = document.getElementById('passwordStrengthBar');
  
  if (!password) {
    feedbackEl.innerHTML = '';
    strengthBar.innerHTML = '';
    return;
  }

  let strength = 0;
  let feedback = [];

  // Length checks
  if (password.length >= 8) strength++;
  else feedback.push('❌ Use at least 8 characters');

  if (password.length >= 12) strength++;
  if (password.length >= 16) strength++;

  // Character type checks
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  if (hasLower) strength++; else feedback.push('❌ Add lowercase letters');
  if (hasUpper) strength++; else feedback.push('❌ Add uppercase letters');
  if (hasDigit) strength++; else feedback.push('❌ Add numbers');
  if (hasSpecial) strength++; else feedback.push('❌ Add special characters (!@#$%)');

  // Check for common passwords
  const common = ['password', '123456', 'qwerty', 'admin', 'letmein', '111111', 'welcome'];
  if (common.includes(password.toLowerCase())) {
    strength = Math.max(0, strength - 2);
    feedback.unshift('⚠️ Too common - avoid well-known passwords');
  }

  const level = strength < 3 ? 'Weak' : strength < 5 ? 'Fair' : strength < 7 ? 'Good' : 'Strong';
  const color = strength < 3 ? 'error' : strength < 5 ? 'warning' : strength < 7 ? 'accent' : 'success';
  
  feedbackEl.innerHTML = `
    <div style="color: var(--text-secondary); margin-bottom: 0.5rem;">
      <strong style="color: var(--${color});">Strength: ${level}</strong>
    </div>
    <div style="font-size: 0.9rem; color: var(--text-secondary);">
      ${feedback.length > 0 ? feedback.join('<br>') : '✅ Great password!'}
    </div>
  `;

  const fillClass = strength < 3 ? 'strength-weak' : strength < 5 ? 'strength-fair' : strength < 7 ? 'strength-good' : 'strength-strong';
  strengthBar.innerHTML = `<div class="strength-fill ${fillClass}"></div>`;
}

/* ==================== PHISHING EMAIL DETECTOR ==================== */
const phishingEmails = [
  {
    from: 'Amazon Support',
    subject: 'Your account has been suspended',
    body: 'Dear Customer,\nYour account has been suspended. Click here immediately to verify your account.',
    isPhishing: true,
    reason: 'Urgent language and immediate action required'
  },
  {
    from: 'support@paypal-security.com',
    subject: 'Confirm Your PayPal Account',
    body: 'Click here to confirm your password and payment information.',
    isPhishing: true,
    reason: 'Fake email asking for credentials'
  },
  {
    from: 'noreply@github.com',
    subject: 'New login to your account',
    body: 'Your GitHub account was accessed from a new location. Review your security settings.',
    isPhishing: false,
    reason: 'Legitimate security notification'
  },
  {
    from: 'billing@apple.com',
    subject: 'Update your billing information',
    body: 'Your payment method declined. Please update it immediately.',
    isPhishing: true,
    reason: 'Urgent tone and payment request'
  },
  {
    from: 'Microsoft Account Team',
    subject: 'Unusual activity detected',
    body: 'We detected unusual activity. Sign in immediately to verify it was you.',
    isPhishing: true,
    reason: 'Suspicious activity claim with urgent call-to-action'
  }
];

let currentPhishingEmail = 0;
let phishingScore = 0;

function initPhishingGame() {
  currentPhishingEmail = Math.floor(Math.random() * phishingEmails.length);
  phishingScore = 0;
  displayPhishingEmail();
}

function displayPhishingEmail() {
  const email = phishingEmails[currentPhishingEmail];
  document.getElementById('emailFrom').textContent = `From: ${email.from}`;
  document.getElementById('emailBody').textContent = email.body;
  document.getElementById('phishingResult').innerHTML = '';
}

function answerPhishing(isPhishing) {
  const email = phishingEmails[currentPhishingEmail];
  const result = document.getElementById('phishingResult');
  const correct = isPhishing === email.isPhishing;

  if (correct) {
    phishingScore++;
    result.classList.add('success');
    result.classList.remove('error');
    result.innerHTML = `
      <strong>✅ Correct!</strong><br>
      <small>${email.reason}</small>
    `;
  } else {
    result.classList.add('error');
    result.classList.remove('success');
    result.innerHTML = `
      <strong>❌ Incorrect!</strong><br>
      <small>Actually ${email.isPhishing ? 'PHISHING' : 'LEGITIMATE'} - ${email.reason}</small>
    `;
  }

  setTimeout(() => {
    currentPhishingEmail = Math.floor(Math.random() * phishingEmails.length);
    displayPhishingEmail();
  }, 2000);
}

/* ==================== SECURITY QUIZ ==================== */
const quizQuestions = [
  {
    question: 'What should you look for in a secure website?',
    options: ['HTTPS in the URL', 'http:// prefix', 'Colorful design', 'No login field'],
    correct: 0
  },
  {
    question: 'What is a strong password?',
    options: ['Your birth year', '12+ characters with mixed case', 'Your pet\'s name', 'Same for all accounts'],
    correct: 1
  },
  {
    question: 'What should you never do on public WiFi?',
    options: ['Check email', 'Enter banking credentials', 'Browse websites', 'All are safe'],
    correct: 1
  },
  {
    question: 'How often should you update your software?',
    options: ['Never', 'Once a year', 'As soon as updates available', 'Every 5 years'],
    correct: 2
  },
  {
    question: 'What is phishing?',
    options: ['A fishing hobby', 'Attempting to gather info by deception', 'A virus', 'Antivirus software'],
    correct: 1
  }
];

let currentQuestionIndex = 0;
let quizScore = 0;
let quizAnswered = false;

function initQuizGame() {
  currentQuestionIndex = 0;
  quizScore = 0;
  quizAnswered = false;
  displayQuizQuestion();
}

function displayQuizQuestion() {
  if (currentQuestionIndex >= quizQuestions.length) {
    showQuizResult();
    return;
  }

  const q = quizQuestions[currentQuestionIndex];
  const questionEl = document.getElementById('quizQuestion');
  const answersEl = document.getElementById('quizAnswers');
  const progressEl = document.getElementById('quizProgress');

  questionEl.textContent = q.question;
  progressEl.textContent = `Question ${currentQuestionIndex + 1} of ${quizQuestions.length}`;
  
  answersEl.innerHTML = q.options.map((option, index) => `
    <div class="quiz-option" onclick="selectQuizAnswer(${index})">${option}</div>
  `).join('');

  quizAnswered = false;
}

function selectQuizAnswer(index) {
  if (quizAnswered) return;
  quizAnswered = true;

  const q = quizQuestions[currentQuestionIndex];
  const options = document.querySelectorAll('.quiz-option');
  
  options.forEach(opt => opt.classList.remove('selected'));
  
  if (index === q.correct) {
    quizScore++;
    options[index].classList.add('selected');
    options[index].style.background = 'rgba(16, 185, 129, 0.2)';
  } else {
    options[index].style.background = 'rgba(239, 68, 68, 0.2)';
    options[q.correct].style.background = 'rgba(16, 185, 129, 0.2)';
  }

  setTimeout(() => {
    currentQuestionIndex++;
    displayQuizQuestion();
  }, 1500);
}

function showQuizResult() {
  const resultEl = document.getElementById('quizResult');
  const percentage = Math.round((quizScore / quizQuestions.length) * 100);
  
  let message = '';
  if (percentage === 100) message = '🏆 Perfect! You\'re a security expert!';
  else if (percentage >= 80) message = '🎉 Great! You know security well!';
  else if (percentage >= 60) message = '👍 Good knowledge! Keep learning!';
  else message = '📚 Keep studying to improve!';

  resultEl.classList.add('success');
  resultEl.innerHTML = `
    <strong>${message}</strong><br>
    <small>Score: ${quizScore}/${quizQuestions.length} (${percentage}%)</small>
  `;
}

/* ==================== DEFENSE GAME ==================== */
const defenseActions = [
  { name: 'Update Software', emoji: '⬆️', points: 15 },
  { name: 'Enable Firewall', emoji: '🧱', points: 20 },
  { name: 'Use VPN', emoji: '🔐', points: 15 },
  { name: 'Antivirus Scan', emoji: '🛡️', points: 25 },
  { name: 'Strong Password', emoji: '🔑', points: 20 },
  { name: '2FA Enabled', emoji: '📱', points: 30 },
  { name: 'Clear Cache', emoji: '🗑️', points: 10 },
  { name: 'Backup Files', emoji: '💾', points: 15 }
];

let defenseLevel = 0;
let defenseActive = {};

function initDefenseGame() {
  defenseLevel = 0;
  defenseActive = {};
  renderDefenseActions();
  updateDefenseLevelUI();
}

function renderDefenseActions() {
  const grid = document.getElementById('defenseActions');
  grid.innerHTML = defenseActions.map((action, index) => `
    <div class="defense-action" onclick="toggleDefenseAction(${index})" id="action-${index}">
      <div style="font-size: 2rem;">${action.emoji}</div>
      <div style="font-size: 0.8rem; margin-top: 0.5rem;">${action.name}</div>
      <div style="font-size: 0.7rem; color: var(--accent-light);">+${action.points}%</div>
    </div>
  `).join('');
}

function toggleDefenseAction(index) {
  const action = defenseActions[index];
  const actionEl = document.getElementById(`action-${index}`);

  if (!defenseActive[index]) {
    defenseLevel += action.points;
    defenseActive[index] = true;
    actionEl.classList.add('active');
  } else {
    defenseLevel -= action.points;
    delete defenseActive[index];
    actionEl.classList.remove('active');
  }

  defenseLevel = Math.max(0, Math.min(100, defenseLevel));
  updateDefenseLevelUI();
}

function updateDefenseLevelUI() {
  const levelBar = document.getElementById('defenseLevel');
  const percent = document.getElementById('defensePercent');
  
  levelBar.style.width = defenseLevel + '%';
  percent.textContent = defenseLevel + '%';

  const message = document.getElementById('defenseMessage');
  if (defenseLevel >= 80) {
    message.classList.add('success');
    message.classList.remove('warning', 'error');
    message.innerHTML = '✅ Strong Defense! Your system is well protected!';
  } else if (defenseLevel >= 50) {
    message.classList.add('warning');
    message.classList.remove('success', 'error');
    message.innerHTML = '⚠️ Moderate Defense - Add more security measures!';
  } else if (defenseLevel > 0) {
    message.classList.add('warning');
    message.classList.remove('success', 'error');
    message.innerHTML = '❌ Weak Defense - You\'re vulnerable to attacks!';
  } else {
    message.innerHTML = '';
  }
}

function resetDefenseGame() {
  initDefenseGame();
}

/* ==================== INITIALIZE ON PAGE LOAD ==================== */
document.addEventListener('DOMContentLoaded', () => {
  showSection('home');
});
