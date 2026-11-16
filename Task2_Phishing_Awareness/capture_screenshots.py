"""
Screenshot & Visual Evidence Generator for Task 2: Phishing Awareness Training
Author: CodeAlpha Cybersecurity Intern
"""

import os
from PIL import Image, ImageDraw, ImageFont


def render_landing_screenshot(output_path: str):
    width, height = 1100, 780
    img = Image.new("RGB", (width, height), color="#0a0d14")
    draw = ImageDraw.Draw(img)

    # Browser Bar
    draw.rectangle([(0, 0), (width, 40)], fill="#101522")
    draw.ellipse([(14, 15), (24, 25)], fill="#ff5f56")
    draw.ellipse([(32, 15), (42, 25)], fill="#ffbd2e")
    draw.ellipse([(50, 15), (60, 25)], fill="#27c93f")
    draw.rectangle([(80, 8), (width - 100, 32)], fill="#141b2d", outline="#222d47")
    draw.text((95, 13), "https://cyberdefense.local/codealpha-phishing-training", fill="#94a3b8")

    # Navbar
    draw.rectangle([(0, 40), (width, 95)], fill="#101522")
    draw.text((32, 55), "🛡️ CodeAlpha CyberShield - Phishing Awareness Training", fill="#ffffff")
    draw.text((width - 320, 58), "Overview   Attack Vectors   Quiz   Certificate", fill="#00f2fe")

    # Hero
    draw.rectangle([(32, 115), (280, 140)], fill="#141b2d", outline="#00f2fe")
    draw.text((42, 120), "DEFENSIVE CYBERSECURITY TRAINING", fill="#00f2fe")
    draw.text((32, 155), "Interactive Phishing Awareness & Defense Platform", fill="#ffffff")
    draw.text((32, 195), "Learn to spot deceptive emails, dissect lookalike URLs, recognize social engineering", fill="#94a3b8")
    draw.text((32, 215), "psychological traps, and certify your threat awareness skills.", fill="#94a3b8")

    # CTA Buttons
    draw.rectangle([(32, 250), (220, 290)], fill="#00f2fe")
    draw.text((45, 262), "🔍 Launch Email Inspector", fill="#050811")
    draw.rectangle([(235, 250), (410, 290)], outline="#3b82f6")
    draw.text((250, 262), "📝 Take Knowledge Quiz", fill="#ffffff")

    # Threat Stats
    stats = [
        ("91%", "of breaches start with phishing"),
        ("3.4B", "phishing emails sent daily"),
        ("82%", "phishing sites use HTTPS SSL"),
        ("< 60s", "median time to credential theft")
    ]
    card_w = 240
    for i, (val, desc) in enumerate(stats):
        x = 32 + i * (card_w + 20)
        draw.rectangle([(x, 320), (x + card_w, 410)], fill="#141b2d", outline="#222d47")
        draw.text((x + 20, 335), val, fill="#00f2fe")
        draw.text((x + 20, 375), desc, fill="#94a3b8")

    # Attack Vectors Preview Cards
    draw.text((32, 440), "THE 6 MAJOR PHISHING ATTACK VECTORS", fill="#00f2fe")
    vectors = [
        ("📧 Mass Email Phishing", "Generic automated spray targeting retail brands"),
        ("🎯 Spear Phishing", "Reconnaissance-driven attack on specific roles"),
        ("👑 Whaling (CEO Fraud)", "Executive impersonation demanding wire transfers"),
        ("📱 Smishing (SMS Phishing)", "Mobile texts lures regarding courier delivery or 2FA"),
        ("📞 Vishing (Voice)", "Voice fraud demanding OTPs or remote agent installs"),
        ("📋 Clone Phishing", "Duplicated real email with replaced weaponized link"),
    ]
    for i, (title, sub) in enumerate(vectors):
        col = i % 3
        row = i // 3
        cx = 32 + col * (330 + 20)
        cy = 475 + row * 125
        draw.rectangle([(cx, cy), (cx + 330, cy + 110)], fill="#141b2d", outline="#222d47")
        draw.text((cx + 15, cy + 15), title, fill="#ffffff")
        draw.text((cx + 15, cy + 45), sub, fill="#94a3b8")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    img.save(output_path, "PNG")
    print(f"[+] Landing screenshot saved to: {output_path}")


def render_email_inspector_screenshot(output_path: str):
    width, height = 1100, 780
    img = Image.new("RGB", (width, height), color="#0a0d14")
    draw = ImageDraw.Draw(img)

    # Browser Bar
    draw.rectangle([(0, 0), (width, 40)], fill="#101522")
    draw.ellipse([(14, 15), (24, 25)], fill="#ff5f56")
    draw.ellipse([(32, 15), (42, 25)], fill="#ffbd2e")
    draw.ellipse([(50, 15), (60, 25)], fill="#27c93f")
    draw.text((95, 13), "https://cyberdefense.local/email-inspector", fill="#94a3b8")

    # Section Title
    draw.text((32, 55), "MODULE 03: INTERACTIVE EMAIL INSPECTOR (SPOTTING RED FLAGS)", fill="#00f2fe")
    draw.text((32, 80), "Realistic simulation demonstrating domain spoofing, urgency traps, and link redirection.", fill="#94a3b8")

    # Tabs and Red Flag toggle
    draw.rectangle([(32, 115), (190, 150)], fill="#00f2fe")
    draw.text((45, 125), "🎬 Streaming Billing", fill="#050811")
    draw.rectangle([(205, 115), (380, 150)], fill="#101522", outline="#222d47")
    draw.text((220, 125), "🏢 IT Password Reset", fill="#94a3b8")
    draw.rectangle([(395, 115), (590, 150)], fill="#101522", outline="#222d47")
    draw.text((410, 125), "💸 Executive Wire Transfer", fill="#94a3b8")

    draw.text((width - 320, 125), "Highlight Red Flags: [ON 🔴]", fill="#ef4444")

    # Simulated Email Box
    draw.rectangle([(32, 165), (width - 32, 600)], fill="#0d121f", outline="#1f2a40")

    # Email Headers
    draw.text((50, 180), "From: Netflix Support Team <support-account-update@netf1ix-verify-billing.com>", fill="#ffffff")
    draw.rectangle([(710, 175), (870, 200)], fill="#ef4444")
    draw.text((720, 180), "🚩 RED FLAG: Spoofed Domain", fill="#ffffff")

    draw.text((50, 210), "To:   user@example.com", fill="#94a3b8")
    draw.text((50, 235), "Date: Today at 09:14 AM", fill="#94a3b8")
    draw.text((50, 260), "Subj: 🚨 URGENT: Your Subscription Will Be Terminated in 24 Hours", fill="#f87171")
    draw.line([(50, 290), (width - 50, 290)], fill="#1f2a40", width=1)

    # Email Body Content
    draw.text((50, 310), "Dear Valued Customer, [🚩 RED FLAG: Generic greeting]", fill="#fca5a5")
    draw.text((50, 345), "We were unable to process your latest monthly subscription fee due to a billing issue with your bank card.", fill="#cbd5e1")
    draw.text((50, 380), "If you do not update your billing details within 24 hours, your account and viewing history will be", fill="#fca5a5")
    draw.text((50, 405), "permanently deleted. [🚩 RED FLAG: Artificial Urgency & Fear]", fill="#fca5a5")
    draw.text((50, 440), "Please click the button below to verify your card details immediately:", fill="#cbd5e1")

    # Malicious Button Simulation
    draw.rectangle([(width // 2 - 140, 475), (width // 2 + 140, 520)], fill="#ef4444")
    draw.text((width // 2 - 110, 490), "UPDATE PAYMENT DETAILS NOW", fill="#ffffff")
    draw.text((width // 2 - 150, 530), "Hover URL: http://netf1ix-verify-billing.com/login.php [🚩 RED FLAG]", fill="#fca5a5")

    # Threat Analysis Details Callout Box
    draw.rectangle([(32, 620), (width - 32, 740)], fill="#1c1116", outline="#ef4444")
    draw.text((50, 635), "⚠️ CRITICAL THREAT ANALYSIS FINDINGS:", fill="#ef4444")
    draw.text((50, 665), "1. Typosquatting in Domain: The sender address uses 'netf1ix' with the digit '1' replacing letter 'l'.", fill="#f8fafc")
    draw.text((50, 690), "2. Coercive Urgency: Imposing a 24-hour termination window to provoke unthinking compliance.", fill="#f8fafc")
    draw.text((50, 715), "3. Credential Harvesting URL: The CTA directs traffic to an unvetted phishing portal targeting card numbers.", fill="#f8fafc")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    img.save(output_path, "PNG")
    print(f"[+] Email inspector screenshot saved to: {output_path}")


def render_quiz_screenshot(output_path: str):
    width, height = 1100, 780
    img = Image.new("RGB", (width, height), color="#0a0d14")
    draw = ImageDraw.Draw(img)

    # Browser Bar
    draw.rectangle([(0, 0), (width, 40)], fill="#101522")
    draw.ellipse([(14, 15), (24, 25)], fill="#ff5f56")
    draw.ellipse([(32, 15), (42, 25)], fill="#ffbd2e")
    draw.ellipse([(50, 15), (60, 25)], fill="#27c93f")
    draw.text((95, 13), "https://cyberdefense.local/quiz-completion-certificate", fill="#94a3b8")

    # Completion Header
    draw.text((width // 2 - 180, 55), "🏆 CERTIFICATION QUIZ COMPLETED!", fill="#00f2fe")
    draw.text((width // 2 - 70, 85), "SCORE: 10 / 10 (100%)", fill="#10b981")

    # Printable Certificate Box
    draw.rectangle([(80, 120), (width - 80, 720)], fill="#0b1120", outline="#00f2fe", width=3)
    draw.rectangle([(90, 130), (width - 90, 710)], fill="#0b1120", outline="#222d47", width=1)

    draw.text((width // 2 - 190, 160), "CODEALPHA CYBERSECURITY ACADEMY • OFFICIAL ACCREDITATION", fill="#00f2fe")
    draw.text((width // 2 - 160, 200), "CERTIFICATE OF COMPLETION", fill="#ffffff")
    draw.text((width // 2 - 80, 245), "This is proudly awarded to:", fill="#94a3b8")

    # Recipient Name
    draw.text((width // 2 - 110, 290), "Vijay Sathwik Naidu", fill="#00f2fe")
    draw.line([(width // 2 - 140, 325), (width // 2 + 140, 325)], fill="#00f2fe", width=2)

    desc1 = "for successfully completing the rigorous Phishing Awareness & Social Engineering Defense Training,"
    desc2 = "demonstrating verified competence in identifying spear phishing, whaling, URL deception,"
    desc3 = "and enterprise-grade defensive counter-measures."
    draw.text((width // 2 - 290, 350), desc1, fill="#cbd5e1")
    draw.text((width // 2 - 270, 375), desc2, fill="#cbd5e1")
    draw.text((width // 2 - 170, 400), desc3, fill="#cbd5e1")

    # Badges and Signatures
    draw.line([(120, 530), (width - 120, 530)], fill="#222d47", width=1)

    draw.text((150, 560), "Senior Security Auditor", fill="#ffffff")
    draw.text((150, 585), "CodeAlpha Cybersecurity Mentor", fill="#64748b")

    draw.text((width // 2 - 60, 560), "November 2026", fill="#ffffff")
    draw.text((width // 2 - 60, 585), "Verification Date", fill="#64748b")

    draw.text((width - 320, 560), "VERIFIED DEFENDER", fill="#10b981")
    draw.text((width - 320, 585), "Credential ID: CA-SEC-2026-9812", fill="#64748b")

    # Gold Stamp representation
    draw.ellipse([(width // 2 - 40, 440), (width // 2 + 40, 520)], outline="#f59e0b", width=2)
    draw.text((width // 2 - 25, 470), "SEAL OF", fill="#f59e0b")
    draw.text((width // 2 - 28, 485), "SECURITY", fill="#f59e0b")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    img.save(output_path, "PNG")
    print(f"[+] Quiz completion screenshot saved to: {output_path}")


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    shot_dir = os.path.join(base, "screenshots")
    render_landing_screenshot(os.path.join(shot_dir, "phishing_awareness_landing.png"))
    render_email_inspector_screenshot(os.path.join(shot_dir, "interactive_email_inspector.png"))
    render_quiz_screenshot(os.path.join(shot_dir, "phishing_quiz_and_certificate.png"))
