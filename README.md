# 🔍 Source Code DarkLight

**AI-Powered Web Vulnerability Scanner | Find SQL Injection, XSS & Hardcoded Secrets**

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Ollama](https://img.shields.io/badge/ollama-AI-orange.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)
[![GitHub stars](https://img.shields.io/github/stars/Darklight099/source-code-darklight)](https://github.com/Darklight099/source-code-darklight/stargazers)

## What is this?

I built DarkLight because I wanted a tool that doesn't just find security holes but actually explains them. It scans websites for SQL injection, XSS, hardcoded secrets, and other nasty stuff. When it finds something, it tells you:

- Why it's dangerous
- How someone could exploit it
- What tools to use
- How to fix it

You can run it in two ways:

**1. Terminal/Command Line** - Quick scans, good for scripts
**2. Web Interface** - Point and click, shows everything nicely in your browser

## What It Finds

| Vulnerability | Severity | What's the problem? |
|--------------|----------|---------------------|
| Hardcoded Secrets | 🔴 Critical | API keys, passwords sitting in source code |
| SQL Injection | 🔴 Critical | Unsanitized database queries - can dump your whole DB |
| XSS (Cross-Site Scripting) | 🟠 High | Users can inject malicious scripts |
| Command Injection | 🟠 High | Attackers can run system commands |
| eval() / document.write() | 🟡 Medium | Dangerous JavaScript functions |
| Missing CSRF Protection | 🟡 Medium | Forms that can be forged |
| Passwords in Comments | 🟡 Medium | Devs leaving sensitive stuff in HTML comments |
| GET Forms | 🟢 Low | Sensitive data in URLs |

## How to Use It

### Option 1: Terminal (Fast & Scriptable)

```bash
# Clone it
git clone https://github.com/Darklight099/source-code-darklight.git
cd source-code-darklight

# Install stuff
pip install -r requirements.txt

# Scan a single page
python3 main.py https://example.com

# Crawl the whole site (be careful, might take a while)
python3 main.py https://example.com --crawl --max-pages 50

# If you don't want AI explanations (faster)
python3 main.py https://example.com --no-ai

# Limit how many vulnerabilities get AI analysis
python3 main.py https://example.com --ai-limit 5
Option 2: Web Interface (Point & Click)
# Install Flask
pip install flask

# Start the web server
python3 web_gui/app.py

# Open your browser and go to http://localhost:5000
The web interface gives you:

    Clean dashboard with vulnerability counts

    Click to expand any finding

    See exactly where in the code the issue is (line numbers)

    Step-by-step exploitation instructions

    Tool commands you can copy-paste

    Links to learn more
Real-World Example

I tested this on a random shopping site and it found 1,498 vulnerabilities in one go:

    436 Critical SQL injection flaws (including coupon code fields)

    1002 XSS issues

    20 Medium severity problems

    40 Low severity issues

The SQL injection on the coupon code field was especially nasty - someone could dump the whole database, steal customer info, or get admin access just by messing with the coupon input.
What Makes This Different

Most scanners just tell you "SQL injection found" and leave you hanging. DarkLight actually teaches you:

    Where - Shows you the exact line of code

    Why - Explains what makes it vulnerable

    How - Step-by-step exploitation guide

    Tools - Exact commands to test it (sqlmap, burp, etc.)

    Fix - How to patch it properly

You don't need to be a security expert to understand the reports.
The AI Thing

If you have Ollama running, it'll give you detailed explanations. But honestly, the tool works great without AI too - all the exploitation guides are built-in and offline. No API keys, no internet required.
If Something Breaks

Ollama not connecting?
bash

ollama serve

Scan too slow?
bash

python3 main.py https://example.com --no-ai

Web interface won't start? Make sure Flask is installed:
bash

pip install flask

High CPU usage?
bash

python3 main.py https://example.com --delay 1.0

Stuff I Learned Building This

    Web scraping is harder than it looks (async programming, rate limiting, avoiding detection)

    SQL injection patterns are everywhere if you know what to look for

    People still hardcode API keys in JavaScript (yikes)

    A clean UI makes security tools way more approachable

    Rate limiting is crucial - without it, the tool can eat up your CPU

What's Next?

I'm planning to add:

    More vulnerability types (SSRF, XXE, path traversal)

    Better crawling (respect robots.txt, smarter link discovery)

    PDF reports

    Maybe a Chrome extension

Legal Stuff

This is for educational purposes and authorized testing only. Don't scan stuff you don't own or have permission to test. I'm not responsible if you use this for shady stuff.
License

MIT - do whatever you want with it, just don't blame me if it breaks something.

Built because I was tired of security tools that just yell "VULNERABILITY!" without explaining anything. Hope it helps someone else learn as much as I did building it.

Questions? Open an issue or hit me up on GitHub.
