/**
 * Phishing Awareness Training Platform
 * Interactive Logic & Quiz Engine
 * Author: CodeAlpha Cybersecurity Intern
 */

// --- 1. Simulated Phishing Email Scenarios ---
const EMAIL_SCENARIOS = {
  scenario1: {
    id: "scenario1",
    tabTitle: "Streaming Account Suspension",
    senderName: "Netflix Support Team",
    senderAddress: "support-account-update@netf1ix-verify-billing.com",
    recipient: "user@example.com",
    date: "Today at 09:14 AM",
    subject: "🚨 URGENT: Your Subscription Will Be Terminated in 24 Hours",
    body: `
      <p><span class="red-flag" data-reason="Generic Greeting: Legitimate services address you by your account name, not generic 'Dear Customer'.">Dear Valued Customer</span><span class="red-flag-indicator">🚩 RED FLAG</span>,</p><br>
      <p>We were unable to process your latest monthly subscription fee due to a billing issue with your bank card.</p><br>
      <p><span class="red-flag" data-reason="Artificial Urgency & Fear: Attackers enforce short deadlines (24 hours) to trigger panic and bypass logical thinking.">If you do not update your billing details within 24 hours, your account and viewing history will be permanently deleted.</span><span class="red-flag-indicator">🚩 RED FLAG</span></p><br>
      <p>Please click the button below to verify your card details immediately:</p><br>
      <p style="text-align: center; margin: 18px 0;">
        <a href="#safe-demo" class="btn btn-primary red-flag" style="display:inline-block; pointer-events: none;" data-reason="Deceptive Link Destination: The anchor text looks like Netflix, but the destination domain is 'netf1ix-verify-billing.com' (typosquatting).">UPDATE PAYMENT DETAILS NOW</a><span class="red-flag-indicator">🚩 RED FLAG</span>
      </p><br>
      <p style="font-size: 11px; color: #64748b;">Netflix International B.V. - All rights reserved. Do not reply to this automated message.</p>
    `,
    senderRedFlag: "Spoofed Domain / Typosquatting: Notice the number '1' in place of 'l' in 'netf1ix', and the suspicious third-party domain suffix."
  },
  scenario2: {
    id: "scenario2",
    tabTitle: "Corporate IT Password Reset",
    senderName: "Internal IT Helpdesk",
    senderAddress: "it-service-desk@secure-auth-internal.net",
    recipient: "employee@corporate-corp.com",
    date: "Today at 11:42 AM",
    subject: "ACTION REQUIRED: Mandatory MFA Token Re-synchronization",
    body: `
      <p>Hello Team,</p><br>
      <p><span class="red-flag" data-reason="Authority Impersonation: Posing as your company's IT department to demand immediate compliance.">Our security team has rolled out a new enterprise MFA protocol. All staff are required to immediately re-authenticate.</span><span class="red-flag-indicator">🚩 RED FLAG</span></p><br>
      <p>Failure to authenticate will lock your corporate Single Sign-On (SSO) account at the end of the day.</p><br>
      <p><span class="red-flag" data-reason="Credential Harvesting Trap: Fake login portals mimic corporate Microsoft 365 or Okta pages to capture usernames, passwords, and MFA session tokens.">Click here to sync your Authenticator App: https://sso.corporate-corp.com.auth-gateway-internal.net</span><span class="red-flag-indicator">🚩 RED FLAG</span></p><br>
      <p>Regards,<br>IT Infrastructure & Support Services</p>
    `,
    senderRedFlag: "External Sender Pretending to be Internal: Sent from an external .net domain rather than your company's official corporate email domain."
  },
  scenario3: {
    id: "scenario3",
    tabTitle: "Executive Wire Transfer (Whaling)",
    senderName: "Robert Anderson (CEO)",
    senderAddress: "ceo-office.robert.anderson@exec-mail-private.com",
    recipient: "sarah.finance@corporate-corp.com",
    date: "Today at 02:15 PM",
    subject: "Confidential Project - Immediate Wire Transfer Needed",
    body: `
      <p>Hi Sarah,</p><br>
      <p><span class="red-flag" data-reason="Whaling / Executive Pressure: High-level executive asking a finance subordinate to bypass established invoice approval workflows.">I am currently in an urgent offsite board meeting regarding a confidential acquisition.</span><span class="red-flag-indicator">🚩 RED FLAG</span></p><br>
      <p><span class="red-flag" data-reason="Strict Secrecy Request: Requesting that the employee not discuss or verify the request with colleagues or managers.">Please do not call me as my phone is on silent during negotiations. Everything must remain strictly confidential until the press release.</span><span class="red-flag-indicator">🚩 RED FLAG</span></p><br>
      <p><span class="red-flag" data-reason="Wire Transfer Urgency: Demands immediate disbursement of corporate funds to an unknown external account.">Can you immediately wire $48,500 to our external legal counsel's escrow account? Send me the wire confirmation as soon as it clears.</span><span class="red-flag-indicator">🚩 RED FLAG</span></p><br>
      <p>Thanks,<br>Robert Anderson<br>Chief Executive Officer</p>
    `,
    senderRedFlag: "Display Name Spoofing: The display name reads 'Robert Anderson (CEO)', but the email address is a generic external private mailbox."
  }
};

// --- 2. 10-Question Comprehensive Quiz Data ---
const QUIZ_QUESTIONS = [
  {
    question: "1. You receive an email from 'support@paypa1-security.com' stating your account has been compromised. Which indicator is the strongest sign of a phishing attack?",
    options: [
      "The email contains the PayPal company logo.",
      "The domain 'paypa1-security.com' uses typosquatting (the number '1' instead of the letter 'l').",
      "The email asks you to check your account balance.",
      "The email has a copyright notice in the footer."
    ],
    correct: 1,
    explanation: "Attackers commonly register misspelled or lookalike domains (typosquatting) such as replacing 'l' with '1' or 'o' with '0' to trick victims into believing the message is legitimate."
  },
  {
    question: "2. What is the fundamental difference between standard Email Phishing and Spear Phishing?",
    options: [
      "Standard phishing uses emails, while spear phishing only uses phone calls.",
      "Standard phishing casts a broad net with generic templates, whereas spear phishing targets specific individuals with personalized reconnaissance.",
      "Spear phishing is completely legal for corporate training, whereas standard phishing is not.",
      "Spear phishing never uses malicious URLs or attachments."
    ],
    correct: 1,
    explanation: "Spear phishing is highly targeted and personalized. The attacker researches specific details (job title, projects, coworkers) to craft convincing, custom messages."
  },
  {
    question: "3. If a website URL displays a padlock icon and starts with 'https://', does that guarantee the website is safe and legitimate?",
    options: [
      "Yes, the padlock proves the website has been thoroughly vetted and verified as safe by browser vendors.",
      "Yes, phishing websites cannot obtain SSL/TLS certificates.",
      "No, HTTPS only encrypts the connection; modern attackers routinely obtain free SSL certificates for phishing websites.",
      "No, HTTPS means the website is definitely malicious."
    ],
    correct: 2,
    explanation: "The padlock only indicates the communication between your browser and the server is encrypted. Attackers easily obtain free SSL certificates (e.g., Let's Encrypt), and over 80% of phishing sites now use HTTPS."
  },
  {
    question: "4. An employee in finance receives an urgent email from the 'CEO' requesting an immediate $50,000 wire transfer for an acquisition, with instructions NOT to call or verify. This is an example of:",
    options: [
      "Clone Phishing",
      "Smishing",
      "Whaling (CEO Fraud / Business Email Compromise)",
      "Vishing"
    ],
    correct: 2,
    explanation: "Whaling specifically targets high-profile roles (or impersonates C-level executives) to deceive employees into approving unauthorized wire transfers or releasing proprietary data."
  },
  {
    question: "5. You receive an SMS message claiming: 'Your courier package is on hold due to $2.50 unpaid customs fee. Click http://courier-track7.link/pay to avoid return.' What type of attack is this?",
    options: [
      "Smishing (SMS Phishing)",
      "Vishing",
      "Watering Hole Attack",
      "Zero-Day Exploit"
    ],
    correct: 0,
    explanation: "Smishing involves sending fraudulent SMS text messages containing malicious links or phone numbers to harvest payment credentials."
  },
  {
    question: "6. Which psychological triggers are most frequently exploited by social engineering attackers?",
    options: [
      "Urgency, Fear, Authority, and Scarcity",
      "Patience, Logic, and Empirical Evidence",
      "Technical complexity and mathematical proofs",
      "Corporate compliance and audit requirements"
    ],
    correct: 0,
    explanation: "Social engineers deliberately exploit human emotions—urgency (24-hour deadlines), fear (account termination), authority (impersonating bosses/police), and greed/curiosity."
  },
  {
    question: "7. You receive an unexpected phone call from someone claiming to be 'Microsoft IT Support' saying your workstation has a virus and requesting your one-time password (OTP). What is the correct response?",
    options: [
      "Provide the OTP so they can clean your system quickly.",
      "Ask them to email the request, and reply with your password.",
      "Immediately hang up and report the incident to your official internal security team. Never share OTPs over the phone.",
      "Hold the line and follow their instructions to install remote desktop software."
    ],
    correct: 2,
    explanation: "This is a Vishing (Voice Phishing) attack. Legitimate IT departments will NEVER call asking for your passwords, OTPs, or to install unvetted remote tools."
  },
  {
    question: "8. What is 'Clone Phishing'?",
    options: [
      "Cloning an employee's mobile SIM card.",
      "Intercepting an authentic, previously delivered email, cloning its layout and text, and replacing links or attachments with malicious counterparts.",
      "Creating two identical user accounts on LinkedIn.",
      "Copying an open-source GitHub repository."
    ],
    correct: 1,
    explanation: "In clone phishing, the attacker takes a real email you recently received, duplicates it almost verbatim, and claims to be an 'updated' or 'resubmitted' version with weaponized links."
  },
  {
    question: "9. How can a Password Manager provide defensive protection against phishing sites?",
    options: [
      "Password managers delete phishing emails automatically.",
      "Password managers recognize that a spoofed domain (e.g., paypa1.com) does not match the real domain (paypal.com) and will refuse to autofill your credentials.",
      "Password managers notify the FBI when you open a phishing link.",
      "Password managers block web browsing completely on weekends."
    ],
    correct: 1,
    explanation: "Password managers match credentials strictly to the exact Fully Qualified Domain Name (FQDN). If you are on a lookalike fake site, the password manager will not autofill, instantly signaling danger."
  },
  {
    question: "10. What is the single most effective action an employee can take when suspecting an email is a phishing attempt?",
    options: [
      "Forward the email to all colleagues to warn them.",
      "Reply to the sender demanding they remove you from their list.",
      "Click the link to check whether it's truly fake.",
      "Do not click links or open attachments; immediately report the email via your organization's Phish-Report button or to the Information Security team."
    ],
    correct: 3,
    explanation: "Reporting the suspicious email alerts SOC analysts, who can block the malicious domain across the entire enterprise perimeter and purge it from other employee inboxes."
  }
];

// --- 3. App State ---
let currentScenario = "scenario1";
let flagsActive = true;
let currentQuestionIndex = 0;
let userScore = 0;
let answeredQuestions = new Array(QUIZ_QUESTIONS.length).fill(null);

// --- 4. Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  renderScenario(currentScenario);
  setupEmailTabs();
  setupRedFlagToggle();
  initQuiz();
  setupProgressBar();
});

// --- 5. Email Inspector Functions ---
function renderScenario(scenarioId) {
  const data = EMAIL_SCENARIOS[scenarioId];
  if (!data) return;

  const emailBox = document.getElementById("simulated-email-box");
  emailBox.className = `simulated-email ${flagsActive ? "flags-active" : ""}`;

  emailBox.innerHTML = `
    <div class="email-headers">
      <div class="email-header-line">
        <span class="header-label">From:</span>
        <span class="header-val">
          <strong>${data.senderName}</strong> &lt;${data.senderAddress}&gt;
          <span class="red-flag" data-reason="${data.senderRedFlag}" style="margin-left: 8px;">🚩 SENDER INSPECT</span>
        </span>
      </div>
      <div class="email-header-line">
        <span class="header-label">To:</span>
        <span class="header-val">${data.recipient}</span>
      </div>
      <div class="email-header-line">
        <span class="header-label">Date:</span>
        <span class="header-val">${data.date}</span>
      </div>
      <div class="email-header-line">
        <span class="header-label">Subject:</span>
        <span class="header-val" style="font-weight: 700; color: #f87171;">${data.subject}</span>
      </div>
    </div>
    <div class="email-body">
      ${data.body}
    </div>
  `;

  // Attach click listeners to all red flag hotspots
  const hotspots = emailBox.querySelectorAll(".red-flag");
  hotspots.forEach(el => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      const reason = el.getAttribute("data-reason");
      showFlagDetails(reason);
    });
  });
}

function showFlagDetails(reason) {
  const box = document.getElementById("flag-details-box");
  box.innerHTML = `<strong>⚠️ Threat Analysis:</strong> ${reason}`;
  box.className = "flag-details-box show";
}

function setupEmailTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      currentScenario = tab.getAttribute("data-scenario");
      renderScenario(currentScenario);
      document.getElementById("flag-details-box").className = "flag-details-box";
    });
  });
}

function setupRedFlagToggle() {
  const toggle = document.getElementById("red-flag-toggle");
  if (!toggle) return;
  toggle.addEventListener("change", (e) => {
    flagsActive = e.target.checked;
    const box = document.getElementById("simulated-email-box");
    if (flagsActive) {
      box.classList.add("flags-active");
    } else {
      box.classList.remove("flags-active");
      document.getElementById("flag-details-box").className = "flag-details-box";
    }
  });
}

// --- 6. Quiz Engine ---
function initQuiz() {
  currentQuestionIndex = 0;
  userScore = 0;
  answeredQuestions.fill(null);
  renderQuestion(currentQuestionIndex);
  updateScoreTracker();
}

function renderQuestion(index) {
  const q = QUIZ_QUESTIONS[index];
  document.getElementById("question-counter").innerText = `Question ${index + 1} of ${QUIZ_QUESTIONS.length}`;
  document.getElementById("question-text").innerText = q.question;

  const optionsContainer = document.getElementById("options-list");
  optionsContainer.innerHTML = "";

  const prefixes = ["A", "B", "C", "D"];
  q.options.forEach((opt, optIdx) => {
    const btn = document.createElement("button");
    btn.className = "option-btn";
    btn.innerHTML = `<span class="option-prefix">${prefixes[optIdx]}.</span> <span>${opt}</span>`;
    
    // Check if already answered
    if (answeredQuestions[index] !== null) {
      btn.disabled = true;
      if (optIdx === q.correct) {
        btn.classList.add("correct");
      } else if (optIdx === answeredQuestions[index]) {
        btn.classList.add("incorrect");
      }
    } else {
      btn.addEventListener("click", () => handleSelectOption(index, optIdx));
    }
    optionsContainer.appendChild(btn);
  });

  const explBox = document.getElementById("explanation-box");
  if (answeredQuestions[index] !== null) {
    const isCorrect = answeredQuestions[index] === q.correct;
    explBox.innerHTML = `<strong>${isCorrect ? "✅ Correct!" : "❌ Incorrect."}</strong> ${q.explanation}`;
    explBox.className = "explanation-box show";
    document.getElementById("next-btn").style.display = "inline-flex";
  } else {
    explBox.className = "explanation-box";
    document.getElementById("next-btn").style.display = "none";
  }
}

function handleSelectOption(qIndex, selectedOptionIndex) {
  const q = QUIZ_QUESTIONS[qIndex];
  answeredQuestions[qIndex] = selectedOptionIndex;

  if (selectedOptionIndex === q.correct) {
    userScore += 1;
  }
  updateScoreTracker();
  renderQuestion(qIndex);
}

function updateScoreTracker() {
  const tracker = document.getElementById("score-tracker");
  if (tracker) {
    tracker.innerText = `Score: ${userScore} / ${QUIZ_QUESTIONS.length}`;
  }
}

function nextQuestion() {
  if (currentQuestionIndex < QUIZ_QUESTIONS.length - 1) {
    currentQuestionIndex += 1;
    renderQuestion(currentQuestionIndex);
  } else {
    showCompletionScreen();
  }
}

function showCompletionScreen() {
  document.getElementById("quiz-card").style.display = "none";
  const compCard = document.getElementById("completion-card");
  compCard.className = "completion-card show";

  const pct = Math.round((userScore / QUIZ_QUESTIONS.length) * 100);
  document.getElementById("final-score-pct").innerText = `${pct}%`;
  document.getElementById("final-score-summary").innerText = `You correctly answered ${userScore} out of ${QUIZ_QUESTIONS.length} questions.`;

  const badge = document.getElementById("completion-badge-text");
  if (pct >= 80) {
    badge.innerText = "🏆 Cybersecurity Awareness Defender - Certified!";
    badge.style.color = "#10b981";
  } else if (pct >= 60) {
    badge.innerText = "⚠️ Awareness Competent - Review Key Principles!";
    badge.style.color = "#f59e0b";
  } else {
    badge.innerText = "🚨 High Vulnerability Risk - Retake Training Recommended";
    badge.style.color = "#ef4444";
  }

  updateCertificateDate();
}

function restartQuiz() {
  document.getElementById("quiz-card").style.display = "block";
  document.getElementById("completion-card").className = "completion-card";
  initQuiz();
}

function updateCertificateName() {
  const input = document.getElementById("cert-name-input");
  const name = input.value.trim() || "Intern Candidate";
  document.getElementById("cert-recipient-name").innerText = name;
}

function updateCertificateDate() {
  const dateEl = document.getElementById("cert-date");
  if (dateEl) {
    const today = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
    dateEl.innerText = today;
  }
}

function printCertificate() {
  window.print();
}

// --- 7. Progress Bar Tracker ---
function setupProgressBar() {
  window.addEventListener("scroll", () => {
    const totalHeight = document.documentElement.scrollHeight - window.innerHeight;
    const progress = (window.scrollY / totalHeight) * 100;
    const bar = document.getElementById("progress-bar-fill");
    if (bar) {
      bar.style.width = `${Math.min(100, Math.max(0, progress))}%`;
    }
  });
}
