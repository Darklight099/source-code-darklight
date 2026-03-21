# 🔍 DarkLight Source Code Reviewer

**AI-Powered Web Security Analyzer | Detect Vulnerabilities | Learn & Fix**

## 🎯 What is DarkLight?

DarkLight is an advanced web security analysis tool that combines traditional pattern-based vulnerability detection with AI-powered analysis. It doesn't just find vulnerabilities—it **teaches** you why they're dangerous and how to fix them.

## ✨ Features

- 🔍 **Deep Source Code Analysis**: Scrapes and inspects HTML, JavaScript, CSS, and inline handlers
- 🤖 **AI-Powered Insights**: Uses Ollama to explain vulnerabilities with real-world impact
- 📊 **Multi-Format Reports**: Generates HTML, JSON, and Markdown reports
- 🕷️ **Web Crawling**: Can scan entire websites, not just single pages
- 🎨 **Beautiful CLI**: Color-coded output with progress indicators
- 📚 **Educational Focus**: Each vulnerability comes with explanation, impact, and remediation

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.8+ is required
python3 --version

# Install Ollama for AI features
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2 
