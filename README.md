# 🛡️ Project CYRUS — Enterprise C++ LLM Security Firewall & Guardrail Platform

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-17%2F20-blue.svg)](https://isocpp.org/)
[![Security Guardrail](https://img.shields.io/badge/OWASP%20LLM-Top%2010-crimson.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Latency Benchmark](https://img.shields.io/badge/Scan%20Latency-%3C%2050%20%CE%BCs-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**CYRUS** is a high-performance **Enterprise C++ LLM Security Firewall & Guardrail Platform** designed to detect, redact, and neutralize **Prompt Injection Attacks** (Jailbreaks, System Prompt Extraction, Indirect RAG Injections) and **Sensitive Data Leaks** (API Keys, AWS Secrets, SSNs, Credit Cards) in real-time.

---

## 🚀 6 High-Impact Enterprise Features

1. **📄 RAG Document & VectorDB Inspector**:
   - Detects Indirect Prompt Injections hidden inside untrusted third-party documents (PDFs, TXT, CSV, scraped HTML) before vector embeddings are created.
2. **🍯 Active Defense Honeypot & Decoy Engine**:
   - Responds to malicious injection attempts with realistic fake decoy payloads to trap payload execution while secretly logging threat telemetry to SOC logs.
3. **⚙️ Interactive Custom Policy & Rule Builder**:
   - Live configuration manager allowing security engineers to toggle individual detection modules, set custom regex patterns, add custom blacklisted keyphrases, and tune sensitivity thresholds (0–100).
4. **🤖 Multi-LLM Benchmark Simulator (Gemini vs Claude vs GPT-4)**:
   - Comparative evaluation bench showing unprotected LLM outputs vs CYRUS firewall protected outputs across Google Gemini 1.5, Anthropic Claude 3.5, and OpenAI GPT-4.
5. **📜 Exportable Security Audit Reports (JSON & CSV)**:
   - One-click SOC2 / GDPR compliance audit log generator exporting structured JSON and CSV reports.
6. **🌐 C++ REST API Proxy Middleware (`/v1/chat/completions`)**:
   - Native C++ engine supporting OpenAI-compatible chat payload schemas (`messages` array with `user` and `system` roles).

---

## ⚡ Quick Start & Build Instructions

### 1. View Web Dashboard
Double click `index.html` to open the multi-tab cyber dashboard directly in any web browser!

### 2. Compile C++ Backend (Windows / Linux / macOS)
- **Windows**:
  ```cmd
  build.bat
  ```
- **Linux / macOS**:
  ```bash
  chmod +x build.sh
  ./build.sh
  ```

---

## 📜 License
Released under the MIT License. Created for Project CYRUS.
