# 🕷️ CrawlMe Pro v2 - Advanced Web Crawler & OSINT Intelligence Engine

A highly advanced, multi-threaded, and feature-rich **Web Crawler and OSINT Intelligence Engine** designed for security researchers, developers, and educational audit operations. It parses target websites to map their entire framework structure, audit security baselines, and discover critical contact points, endpoints, technology stack footprints, and metadata.
<img width="1332" height="701" alt="Dashboard" src="https://github.com/user-attachments/assets/69f36fc7-e9fe-4c56-83ab-fb39104a597d" />
<img width="1332" height="701" alt="Dashboard" src="https://github.com/user-attachments/assets/3b8c0468-2395-4416-8c9b-dc2fb9b60d87" />
<img width="1327" height="372" alt="Files" src="https://github.com/user-attachments/assets/3b4945ab-6d14-4547-979d-7cba6df86fc9" />
<img width="1327" height="372" alt="Files" src="https://github.com/user-attachments/assets/7c30c507-3b39-4f70-b012-c2a5c7c0a1b8" />
<img width="1308" height="348" alt="Screenshot_capture" src="https://github.com/user-attachments/assets/115eb675-6734-4c09-b4f4-dd94dacc2fd0" />

## 🌟 Visual Modes

### 💻 1. Interactive Command Line Interface (CLI)
CrawlMe Pro features a hacker-themed CLI console complete with custom golden ANSI banners, real-time color-coded scanner logging, configuration prompts, and structured output formatting.

### 📊 2. Premium Real-Time Web Dashboard UI
Powered by a background Flask server, the application hosts a beautiful glassmorphism dark-mode dashboard featuring:
- **Interactive charts** (via Chart.js) tracking crawler status, performance, and discoveries.
- **SSE (Server-Sent Events) live streaming** of crawler worker logs, scanned pages, and real-time statistics.
- **Visual Page Screenshot Gallery** utilizing headless browsers to capture target UI screenshots in real-time.
- **Intelligence Score Gauge Cards** summarizing the target's SEO, Performance, and Security posture.
- **One-click multi-format data exporters** (TXT, JSON, CSV, PDF, HTML, XML).

---

## 🚀 Key Features & OSINT Capabilities

### 🔍 Content & Contact Discovery
- **Deep Email Extraction:** Identifies standard and obscured email patterns on target pages, with false-positive filtering (such as filtering out `.jpg`, `.png`, and `.js` false matches).
- **Phone Number Parsing:** Matches international phone number schemas and formats, ensuring digits are validated and formatted.
- **Social Media Scraper:** Traverses links and anchors to gather targets' social media channels (e.g., Twitter/X, LinkedIn, Facebook, Instagram, GitHub, Reddit, Telegram).

### 🛠️ Technology Fingerprinting
- **Server Detection:** Identifies hosting servers (Nginx, Apache, LiteSpeed, IIS).
- **Web Backend & CDNs:** Detects X-Powered-By architectures (PHP, ASP.NET, Express) and CDN/WAF infrastructures like Cloudflare.
- **CMS & Frontend Frameworks:** Identifies popular Content Management Systems (WordPress, Shopify, Joomla) and UI/JavaScript libraries (jQuery, React, Vue, Angular, Bootstrap, Tailwind CSS).

### 🚨 JavaScript & SPA Auditing
- **SPA Source Scanning:** Resolves external and inline JavaScript scripts on the same domain to trace modern Single Page Application (SPA) templates.
- **API Endpoint Mapping:** Extracts internal API routes and REST endpoints (e.g., `/api/v1/`, `/admin`) from JS strings.
- **Secrets/Token Extraction:** Uses heuristic patterns to find hardcoded configuration keys, API keys, JWT/auth tokens, and credentials in JavaScript code.
- **Developer Comments Scanner:** Audits single-line (`//`) and multi-line (`/* */`) JS comments for flags like `TODO`, `FIXME`, `config`, `password`, `key`, and `db`.

### 🛡️ Security Audit & Metrics
- **HTTP Headers Audit:** Verifies the presence and values of security headers:
  - `Content-Security-Policy` (CSP)
  - `Strict-Transport-Security` (HSTS)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- **Cookies Security Check:** Examines set cookies for critical safety flags: `Secure` and `HttpOnly`.
- **SSL/TLS Certificate Details:** Resolves SSL details: certificate issuer, subject details, validation window, remaining lifetime (in days), and active TLS protocol versions.
- **Network Metadata:** Automatically probes target domain IP address, country code, ASN information, and hosting networks.
- **Scoring System:** Computes real-time dynamic ratings (0-100% scale) for **SEO**, **Security**, and **Performance**.
- **Heuristic AI Insights:** Automatically parses scan statistics, header audits, and content details to produce a target categorization profile (e.g., E-Commerce Storefront, Financial Portal, Educational ERP) and lists custom-tailored recommendations.

---

## 📦 Project Architecture & Components

CrawlMe Pro comprises the following core files and assets:

- [crawler_engine.py](file:///c:/Users/aashi/Desktop/MyRepos/crawlme/crawler_engine.py): The main engine containing the `AdvancedWebCrawler` class. It manages multi-threaded execution, scheduling queues, HTML/JS token parsers, SSL/network resolvers, score calculators, and PDF/HTML/XML raw exporters.
- [crawlme.py](file:///c:/Users/aashi/Desktop/MyRepos/crawlme/crawlme.py): The CLI runner and entry point. It parses command-line args, runs interactive prompting loops, prints logging callbacks, and saves ASCII text reports.
- [app.py](file:///c:/Users/aashi/Desktop/MyRepos/crawlme/app.py): The Flask server middleware that instantiates the crawler, spins up background threads, serves the Web UI, runs Server-Sent Events (SSE) log pipelines, and handles file exports.
- [templates/index.html](file:///c:/Users/aashi/Desktop/MyRepos/crawlme/templates/index.html): The front-end dashboard built with HTML5, vanilla CSS grid layout, glassmorphic styling, chart visualization scripts, and SSE clients.
- `static/`: Contains server assets, CSS, JS, and target page screenshots under `static/screenshots/`.
- [requirements.txt](file:///c:/Users/aashi/Desktop/MyRepos/crawlme/requirements.txt): Environment dependencies including Flask, BS4, requests, fpdf2, and playwright.

---

## 🛠️ Installation Guide

### Prerequisites
- Python 3.6 or newer installed on your environment.
- Access to pip (Python Package Installer).

### Step-by-Step Setup
1. **Clone the repository:**
   ```bash
   git clone https://github.com/AashishCyberH4CKS/CrawlmeV2.git
   cd CrawlmeV2
   ```

2. **Install core python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Playwright Browsers (Required for real-time website screenshotting):**
   ```bash
   playwright install chromium
   ```
   *Note: If Playwright is not installed or initialized, the engine automatically falls back to Unsplash placeholders without interrupting your scan.*

---

## 🚀 Execution & Usage Guide

CrawlMe Pro provides multiple modes of execution depending on your preference.

### 1. Launching the Web Dashboard UI (Recommended)
Spins up the Flask web server locally, which allows visual interaction with all telemetry.
```bash
python crawlme.py --web
```
- Open your browser and navigate to: `http://127.0.0.1:5000`
- Configure crawl parameters (Max depth, worker threads, delay seconds, user-agent profile, and robots.txt toggle) and input the seed URL.
- Monitor logging and results dynamically as they stream into the dashboard.

### 2. Direct CLI Scan
Run an immediate, one-off CLI crawl from your terminal without opening any browser GUI:
```bash
python crawlme.py --url https://example.com --pages 100 --depth 3 --threads 5 --delay 1.0
```

#### Command Arguments Reference:
- `--web` or `-w`: Start the local Flask web dashboard.
- `--url` or `-u`: Specify seed URL to begin crawls immediately.
- `--pages` or `-p`: Max number of pages to crawl before stopping (default: 100).
- `--depth` or `-d`: Max depth of internal navigation links to follow (default: 3).
- `--threads` or `-t`: Number of worker threads running concurrently (default: 5).
- `--delay` or `-s`: Delay (in seconds) between requests on each worker thread (default: 1.0).
- `--ignore-robots`: Bypass guidelines parsed from target's `robots.txt`.

### 3. Interactive CLI Console
Run the main script without any arguments to trigger the CLI wizard:
```bash
python crawlme.py
```
- Enter target seed URLs manually inside the loop.
- Type `web` to transition and launch the Flask dashboard.
- Type `quit` to exit.

---

## 📊 Output & Data Export Formats

Upon completion of a scan, CrawlMe Pro generates reports and allows exporting to various media:

1. **Detailed Text Summary (`.txt`):** Automatically saved to the current directory after terminal scans, or downloaded via the dashboard. Contains organized contact information lists and page routing indexes.
2. **Structural Dump (`.json`):** Perfect for importing results into third-party analysis programs or automation pipelines.
3. **Granular CSV Files (`.csv`):** Specific spreadsheets exported for:
   - Discovered email contacts (`emails_*.csv`)
   - Discovered phone numbers (`phones_*.csv`)
   - Social networks profiles (`socials_*.csv`)
   - Discovered file assets (`files_*.csv`)
   - API endpoints (`apis_*.csv`)
   - Internal/External URL maps (`links_*.csv`)
4. **Structured XML Logs (`.xml`):** Hierarchical layout of target configuration parameters and scan results.
5. **Print-Ready PDF Reports (`.pdf`):** A custom structured Security Intelligence Report with overview fields, threat summaries, metrics, and vulnerabilities.
6. **Self-Contained HTML Summary (`.html`):** Beautifully styled single-file scan summary reports.

---

## ⚠️ Important Cautions & Ethical Policy

> [!IMPORTANT]
> **LEGAL DISCLAIMER**
> CrawlMe Pro is created strictly for authorized security auditing, educational research, and infrastructure SEO auditing. Do not use this tool on any external servers or targets without explicit, written, and legal authorization. The creators and maintainers of this repository assume zero liability for misuse or damage caused by this software.

### 🛡️ Best Practices for Ethical Crawling
- **Obtain Consent First:** Never crawl websites unless you own them, run them in a private sandboxed sandbox, or have direct permission from the host administrator.
- **Respect `robots.txt`:** By default, CrawlMe Pro respects target site robots.txt parameters and policies. Bypass this feature (`--ignore-robots`) ONLY if you are performing a certified penetration test.
- **Pace Requests Carefully:** Keep the delay setting active (`--delay 1.0` or higher). Setting concurrent worker threads high (`--threads`) with zero delays can overload smaller servers, causing unintended Denial of Service (DoS) conditions.
- **Data Protection:** Extracted contacts (emails, phone numbers) could represent Personally Identifiable Information (PII). Treat all scanned data responsibly, store it securely, and delete it in compliance with localized data protection policies (e.g. GDPR, CCPA).
- **Environment Stability:** Playwright screenshots require headless web browsers. Running multiple concurrent screenshot cycles could consume substantial CPU and RAM resources on weaker servers or local host systems.

---

## 🆘 Troubleshooting & Support

If you encounter issues during installation or setup:
1. **Command Line Warnings:** Ensure that your console font supports UTF-8 characters if banner animations appear distorted. Standard modern consoles (Windows Terminal, VS Code Terminal, macOS Terminal) render emojis and colors properly out of the box.
2. **Missing Playwright Screen Capture:** If you see `[Screenshot Warning] Playwright failed...` in your console log, run `playwright install chromium` inside your virtual environment to configure headless browser binaries.
3. **Port Collisions:** The Flask dashboard runs on port `5000` by default. If another service is already using port `5000` on your system, modify the host port within [app.py](file:///c:/Users/aashi/Desktop/MyRepos/crawlme/app.py) or check port availability.
4. **Dependency Conflicts:** It is highly recommended to run this tool inside a virtual environment (`venv`) to avoid libraries version clashes:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   pip install -r requirements.txt
   ```

---

## 👨‍💻 Creator & License
- **Lead Developer:** AashishCyberH4CKS — Security Researcher & Developer
- **License:** Released under the terms of the MIT License.

⚡ *Remember: With great power comes great responsibility. Always scan ethically and legally.* 🛡️
