import requests
import re
import time
import threading
import socket
import ssl
import os
import xml.etree.ElementTree as ET
import hashlib
from urllib.robotparser import RobotFileParser
from urllib.parse import urljoin, urlparse
from collections import deque
from bs4 import BeautifulSoup

class AdvancedWebCrawler:
    def __init__(self):
        # State tracking (protected by self.lock)
        self.visited_urls = set()      # Set of URL strings
        self.visited_js_files = set()  # Set of crawled JS file strings
        self.to_crawl = deque()         # Queue of (url, depth) tuples
        self.found_emails = set()
        self.found_phones = set()
        self.found_links = set()
        self.found_external_links = set()
        self.found_socials = set()
        self.found_tech_stack = set()
        self.found_sensitive_endpoints = set()
        self.status_codes = {}          # url -> status_code
        self.page_titles = {}           # url -> title
        
        # New properties for v2
        self.target_info = {
            'domain': '',
            'ip': 'N/A',
            'server': 'N/A',
            'hosting': 'N/A',
            'country': 'N/A',
            'cdn': 'N/A',
            'techs': []
        }
        self.sitemap_info = {
            'found': 'NO',
            'total_urls': 0,
            'last_modified': 'N/A',
            'hidden_urls': [],
            'sitemap_urls': []
        }
        self.found_files = []
        self.js_analyzer_results = {
            'total_files': 0,
            'files': {}
        }
        self.api_routes = []
        self.security_headers = []
        self.ssl_info = {
            'issuer': 'N/A',
            'subject': 'N/A',
            'valid_from': 'N/A',
            'expiry': 'N/A',
            'remaining_days': 'N/A',
            'tls_version': 'N/A'
        }
        self.cookie_info = []
        self.tech_fingerprints = []
        self.scores = {
            'seo': 0,
            'security': 0,
            'performance': 0
        }
        self.timeline = []
        self.screenshots = []
        self.ai_insights = {
            'summary': '',
            'security_explanations': []
        }
        
        self.lock = threading.RLock()
        
        # Configuration defaults
        self.session = requests.Session()
        self.user_agents = {
            'ethical': 'EducationalWebCrawler/2.0 (Ethical Research; +http://example.com/bot.html)',
            'chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'firefox': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
        }
        self.current_user_agent = self.user_agents['ethical']
        self.delay = 1.0                # Delay between requests in seconds
        self.max_threads = 5
        self.max_depth = 3
        self.max_pages = 50
        self.respect_robots = False
        
        # Internal controls
        self.is_running = False
        self.is_paused = False
        self.should_stop = False
        self.domain = ""
        self.robots_parser = None
        self.active_threads_count = 0
        
        # Callback hooks for real-time progress
        self.on_log_callback = None          # func(message_str)
        self.on_status_changed_callback = None # func(status_str)
        self.on_page_crawled_callback = None  # func(page_data_dict)

    def log(self, message):
        if self.on_log_callback:
            self.on_log_callback(message)
        else:
            print(message)

    def change_status(self, status):
        if self.on_status_changed_callback:
            self.on_status_changed_callback(status)

    def is_allowed_by_robots(self, url):
        if not self.respect_robots or not self.robots_parser:
            return True
        try:
            return self.robots_parser.can_fetch(self.current_user_agent, url)
        except:
            return True

    def get_robots_txt(self, base_url):
        robots_url = urljoin(base_url, '/robots.txt')
        self.robots_parser = RobotFileParser()
        try:
            self.robots_parser.set_url(robots_url)
            # Use short timeout to avoid hanging on robots.txt fetch
            response = self.session.get(robots_url, timeout=5)
            if response.status_code == 200:
                self.robots_parser.parse(response.text.splitlines())
                crawl_delay = self.robots_parser.crawl_delay(self.current_user_agent)
                if crawl_delay:
                    with self.lock:
                        self.delay = max(self.delay, float(crawl_delay))
                self.log(f"[robots.txt] Found and parsed: {robots_url}")
            else:
                self.robots_parser = None
                self.log(f"[robots.txt] No robots.txt found (HTTP {response.status_code})")
        except Exception as e:
            self.robots_parser = None
            self.log(f"[robots.txt] Could not read/parse robots.txt: {str(e)}")

    def extract_emails(self, text):
        # A robust email regex
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}'
        emails = re.findall(email_pattern, text)
        valid_emails = set()
        # Filter out common false positives (e.g. image extensions or script names)
        invalid_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.js', '.css', '.svg', '.webp')
        for email in emails:
            if not email.lower().endswith(invalid_extensions):
                valid_emails.add(email)
        return valid_emails

    def extract_phones(self, text):
        # Match standard phone formats
        phone_pattern = r'\+?\b(?:\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{3,5}\b'
        phones = re.findall(phone_pattern, text)
        valid_phones = set()
        for phone in phones:
            cleaned = re.sub(r'[-.\s\(\)\+]', '', phone)
            # A valid phone number usually has between 7 and 15 digits
            if 7 <= len(cleaned) <= 15 and cleaned.isdigit():
                valid_phones.add(phone.strip())
        return valid_phones

    def detect_tech_stack(self, url, headers, soup):
        tech = set()
        
        # Check Response Headers
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            tech.add('Nginx Server')
        elif 'apache' in server:
            tech.add('Apache Server')
        elif 'litespeed' in server:
            tech.add('LiteSpeed Server')
        elif 'microsoft-iis' in server:
            tech.add('Microsoft IIS Server')
            
        if headers.get('X-Powered-By'):
            powered = headers.get('X-Powered-By', '').lower()
            if 'php' in powered:
                tech.add('PHP Backend')
            elif 'asp.net' in powered:
                tech.add('ASP.NET')
            elif 'express' in powered:
                tech.add('Express.js')
                
        if headers.get('cf-ray') or 'cloudflare' in server:
            tech.add('Cloudflare CDN/WAF')

        # Check HTML Page Content
        if soup:
            html_text = str(soup)
            
            # CMS
            if '/wp-content/' in html_text or 'wp-emoji' in html_text:
                tech.add('WordPress CMS')
            if 'cdn.shopify.com' in html_text or 'Shopify.theme' in html_text:
                tech.add('Shopify E-commerce')
            if 'Joomla!' in html_text or 'joomla' in html_text.lower():
                tech.add('Joomla CMS')
                
            # Libraries & Frameworks
            if 'jquery' in html_text.lower() or 'jquery.min.js' in html_text.lower():
                tech.add('jQuery')
            if 'data-reactroot' in html_text or 'react-dom' in html_text:
                tech.add('React.js')
            if 'ng-version' in html_text or 'ng-app' in html_text:
                tech.add('Angular')
            if 'vue' in html_text.lower() or 'v-bind' in html_text or 'v-out' in html_text:
                tech.add('Vue.js')
            if 'bootstrap' in html_text.lower() or 'bootstrap.css' in html_text.lower() or 'bootstrap.min.js' in html_text.lower():
                tech.add('Bootstrap CSS')
            if 'tailwind' in html_text.lower():
                tech.add('Tailwind CSS')
                
        return tech

    def detect_sensitive_endpoints(self, url):
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        sensitive_keywords = [
            '.env', 'wp-config.php', 'config.php', 'config.json', 'settings.py',
            'database.yml', '/admin', '/wp-admin', '/administrator', '/login',
            '/backup', '.git', '.svn', 'sitemap.xml', 'robots.txt', 'setup.php',
            'install.php', '/phpmyadmin', 'dashboard', '/api/v1', '/api/docs'
        ]
        
        found = []
        for keyword in sensitive_keywords:
            if keyword in path or path.endswith(keyword):
                found.append(keyword)
                
        return found

    def extract_socials(self, soup):
        socials = set()
        social_domains = ['facebook.com', 'twitter.com', 'x.com', 'linkedin.com', 
                          'instagram.com', 'youtube.com', 'pinterest.com', 
                          'github.com', 'reddit.com', 'telegram.org', 't.me']
        
        if soup:
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                parsed = urlparse(href)
                domain = parsed.netloc.lower()
                
                # Check if it matches any social media domains
                for sd in social_domains:
                    if sd in domain or sd in href.lower():
                        socials.add(href)
                        break
        return socials

    def is_same_domain(self, url):
        return urlparse(url).netloc == self.domain

    def parse_js_assets(self, url, soup):
        js_emails = set()
        js_phones = set()
        
        # 1. Find script and preload URLs
        js_urls = []
        if soup:
            for script in soup.find_all('script', src=True):
                js_urls.append(urljoin(url, script['src']))
            for link in soup.find_all('link', href=True):
                rel = link.get('rel', [])
                if isinstance(rel, str):
                    rel = [rel]
                if 'modulepreload' in rel or 'preload' in rel:
                    as_attr = link.get('as', '')
                    if as_attr == 'script' or link['href'].endswith('.js'):
                        js_urls.append(urljoin(url, link['href']))

        # 2. Filter to same domain to avoid external script scraping overhead
        same_domain_js = []
        for js_url in set(js_urls):
            if self.is_same_domain(js_url):
                same_domain_js.append(js_url)

        # 3. Fetch and parse each JS file
        for js_url in same_domain_js:
            try:
                # Use a separate set to track fetched JS files to avoid redundant downloads
                with self.lock:
                    if js_url in self.visited_js_files:
                        continue
                    self.visited_js_files.add(js_url)
                
                self.log(f"[*] Extracting contacts and mapping JS script: {js_url}")
                headers = {'User-Agent': self.current_user_agent}
                js_resp = self.session.get(js_url, headers=headers, timeout=10)
                if js_resp.status_code == 200:
                    js_text = js_resp.text
                    
                    # Extract string literals for endpoints, emails, phones, tokens
                    js_file_emails = set()
                    js_file_phones = set()
                    js_endpoints = set()
                    js_tokens = set()
                    js_comments = set()
                    
                    string_pattern = r'"(.*?)"|\'(.*?)\'|`(.*?)`'
                    for match in re.finditer(string_pattern, js_text):
                        val = next((g for g in match.groups() if g is not None), None)
                        if val:
                            val = val.strip()
                            # Emails
                            for email in self.extract_emails(val):
                                js_file_emails.add(email)
                                js_emails.add(email)
                            # Phones
                            for phone in self.extract_phones(val):
                                s = phone.strip()
                                if not (s.startswith('+') or any(char in s for char in [' ', '-', '(', ')'])):
                                    continue
                                if '.' in s:
                                    continue
                                if ('(' in s or ')' in s) and not ('(' in s and ')' in s):
                                    continue
                                js_file_phones.add(phone)
                                js_phones.add(phone)
                            
                            # API Endpoints (e.g. starts with /api/ or contains /api/v...)
                            if val.startswith('/') and len(val) > 1:
                                if val.startswith('/api/') or '/api/' in val or re.match(r'^/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-\/]+', val):
                                    js_endpoints.add(val)
                            elif val.startswith('http://') or val.startswith('https://'):
                                if self.is_same_domain(val):
                                    path = urlparse(val).path
                                    if path and path != '/':
                                        js_endpoints.add(path)
                                        
                    # Extract tokens/keys from JS
                    token_pattern = r'\b(api[-_]?key|token|auth|secret|password|private[-_]?key)\s*[:=]\s*["\'`]([a-zA-Z0-9_\-\.\+=/]{8,64})["\'`]'
                    for match in re.finditer(token_pattern, js_text, re.IGNORECASE):
                        key_name = match.group(1)
                        key_val = match.group(2)
                        js_tokens.add(f"{key_name}: {key_val[:4]}...{key_val[-4:]}")
                        
                    # Extract comments containing flags
                    comment_pattern_single = r'//\s*(.*)'
                    for match in re.finditer(comment_pattern_single, js_text):
                        comment_val = match.group(1).strip()
                        if any(kw in comment_val.lower() for kw in ['todo', 'fixme', 'config', 'key', 'password', 'db', 'username', 'credential', 'token']):
                            js_comments.add(comment_val[:100])
                            
                    comment_pattern_multi = r'/\*(.*?)\*/'
                    for match in re.finditer(comment_pattern_multi, js_text, re.DOTALL):
                        comment_val = match.group(1).strip()
                        for line in comment_val.split('\n'):
                            line_cleaned = line.strip().lstrip('*').strip()
                            if any(kw in line_cleaned.lower() for kw in ['todo', 'fixme', 'config', 'key', 'password', 'db', 'username', 'credential', 'token']):
                                js_comments.add(line_cleaned[:100])
                    
                    filename = js_url.split('/')[-1] or 'script.js'
                    with self.lock:
                        self.js_analyzer_results['total_files'] += 1
                        self.js_analyzer_results['files'][js_url] = {
                            'url': js_url,
                            'filename': filename,
                            'size': f"{len(js_text)/1024:.1f} KB",
                            'endpoints': sorted(list(js_endpoints)),
                            'emails': sorted(list(js_file_emails)),
                            'phones': sorted(list(js_file_phones)),
                            'tokens': sorted(list(js_tokens)),
                            'comments': sorted(list(js_comments))[:15]
                        }
                        
                        # Add to api_routes if not there
                        for ep in js_endpoints:
                            if not any(r['endpoint'] == ep for r in self.api_routes):
                                self.api_routes.append({
                                    'method': 'GET/POST',
                                    'endpoint': ep,
                                    'source_file': filename,
                                    'status': 'JS Source'
                                })
            except Exception as e:
                self.log(f"[x] Error parsing JS asset {js_url}: {str(e)}")
                
        return js_emails, js_phones

    def crawl_page(self, url, depth):
        # 1. Thread safety and early exit checks
        with self.lock:
            if self.should_stop or not self.is_running:
                return
            if url in self.visited_urls:
                return
            if len(self.visited_urls) >= self.max_pages:
                return
            
        # 2. Check robots.txt compliance
        if not self.is_allowed_by_robots(url):
            if depth == 0:
                self.log(f"[-] Blocked by robots.txt: {url} (Tip: Toggle off 'Respect Robots.txt' in UI or use '--ignore-robots' in CLI to bypass)")
            else:
                self.log(f"[-] Blocked by robots.txt: {url}")
            with self.lock:
                self.visited_urls.add(url)
                self.status_codes[url] = "Blocked (Robots)"
            return

        # 3. Respectful Crawl Delay
        time.sleep(self.delay)

        self.log(f"[+] Crawling: {url} (Depth: {depth})")
        
        try:
            headers = {'User-Agent': self.current_user_agent}
            response = self.session.get(url, headers=headers, timeout=10)
            
            # Process response status
            status_code = response.status_code
            with self.lock:
                self.status_codes[url] = status_code
                self.visited_urls.add(url)
            
            if status_code != 200:
                self.log(f"[-] Failed to crawl {url} - Status Code: {status_code}")
                # Trigger callback even for failed pages
                if self.on_page_crawled_callback:
                    self.on_page_crawled_callback({
                        'url': url,
                        'status_code': status_code,
                        'depth': depth,
                        'emails': [],
                        'phones': [],
                        'socials': [],
                        'tech_stack': [],
                        'sensitive': []
                    })
                return

            # 4. Parse content
            soup = BeautifulSoup(response.text, 'lxml' if 'lxml' in globals() else 'html.parser')
            
            # Audit security headers and cookies on seed page
            if depth == 0:
                self.audit_security_headers_and_cookies(response)
                self.add_timeline_event("Security headers & cookies audited")
            text_content = soup.get_text()
            title = soup.title.string.strip() if soup.title else "No Title"
            
            with self.lock:
                self.page_titles[url] = title

            # 5. Extract data points
            emails = self.extract_emails(text_content)
            phones = self.extract_phones(text_content)
            socials = self.extract_socials(soup)
            techs = self.detect_tech_stack(url, response.headers, soup)
            sensitive = self.detect_sensitive_endpoints(url)

            # Upgrade technology fingerprinting
            self.perform_technology_fingerprinting(url, response.headers, soup)

            # Extract data from same-domain javascript bundles to support SPAs
            js_emails, js_phones = self.parse_js_assets(url, soup)
            emails.update(js_emails)
            phones.update(js_phones)
            
            # File discovery
            self.discover_files(url, soup)
            
            # API endpoint discovery from forms
            self.discover_api_from_html(url, soup)
            
            # Capture screenshot
            self.capture_screenshot(url)
            
            # Calculate Scores
            self.calculate_scores(url, response.headers, soup, response.elapsed.total_seconds(), len(response.content))
            
            # Generate AI Insights
            self.generate_ai_insights()

            # Update master sets with thread safety
            with self.lock:
                self.found_emails.update(emails)
                self.found_phones.update(phones)
                self.found_socials.update(socials)
                self.found_tech_stack.update(techs)
                self.found_sensitive_endpoints.update(sensitive)

            # 6. Extract links and schedule next crawlers if within depth limit
            links_extracted = 0
            if depth < self.max_depth:
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].strip()
                    if href.startswith('#') or href.lower().startswith('javascript:'):
                        continue
                    
                    full_url = urljoin(url, href)
                    # Clean URL (strip fragment identifier)
                    full_url = full_url.split('#')[0]
                    
                    with self.lock:
                        if self.is_same_domain(full_url):
                            self.found_links.add(full_url)
                            if full_url not in self.visited_urls and not any(q[0] == full_url for q in self.to_crawl):
                                self.to_crawl.append((full_url, depth + 1))
                                links_extracted += 1
                        else:
                            self.found_external_links.add(full_url)

            self.log(f"[OK] Scanned: {url} | Found: {len(emails)} emails, {len(phones)} phones, {len(socials)} social links")

            # Trigger callbacks
            if self.on_page_crawled_callback:
                self.on_page_crawled_callback({
                    'url': url,
                    'title': title,
                    'status_code': status_code,
                    'depth': depth,
                    'emails': list(emails),
                    'phones': list(phones),
                    'socials': list(socials),
                    'tech_stack': list(techs),
                    'sensitive': list(sensitive)
                })

        except Exception as e:
            self.log(f"[x] Error crawling {url}: {str(e)}")
            with self.lock:
                self.status_codes[url] = f"Error: {type(e).__name__}"
                self.visited_urls.add(url)
            
            if self.on_page_crawled_callback:
                self.on_page_crawled_callback({
                    'url': url,
                    'status_code': f"Error: {str(e)}",
                    'depth': depth,
                    'emails': [],
                    'phones': [],
                    'socials': [],
                    'tech_stack': [],
                    'sensitive': []
                })

    def run_worker(self):
        while True:
            # Check conditions and fetch next URL from the queue
            url, depth = None, None
            with self.lock:
                # Stop if requested or if max_pages limit reached
                if self.should_stop or len(self.visited_urls) >= self.max_pages:
                    break
                
                # Wait or pause loop
                while self.is_paused and not self.should_stop:
                    self.lock.release()
                    time.sleep(0.5)
                    self.lock.acquire()

                if not self.to_crawl:
                    break
                
                url, depth = self.to_crawl.popleft()

            # Crawl outside the lock to support concurrency
            self.crawl_page(url, depth)

        # Worker finishing
        with self.lock:
            self.active_threads_count -= 1

    def start(self, start_url, max_pages=50, max_depth=3, threads=5, delay=1.0, user_agent='ethical', respect_robots=True):
        # Initialize configuration
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_threads = threads
        self.delay = delay
        self.respect_robots = respect_robots
        self.current_user_agent = self.user_agents.get(user_agent, self.user_agents['ethical'])
        
        # Clear state
        with self.lock:
            self.visited_urls.clear()
            self.visited_js_files.clear()
            self.to_crawl.clear()
            self.found_emails.clear()
            self.found_phones.clear()
            self.found_links.clear()
            self.found_external_links.clear()
            self.found_socials.clear()
            self.found_tech_stack.clear()
            self.found_sensitive_endpoints.clear()
            self.status_codes.clear()
            self.page_titles.clear()
            
            # Reset v2 state
            self.target_info = {
                'domain': '',
                'ip': 'N/A',
                'server': 'N/A',
                'hosting': 'N/A',
                'country': 'N/A',
                'cdn': 'N/A',
                'techs': []
            }
            self.sitemap_info = {
                'found': 'NO',
                'total_urls': 0,
                'last_modified': 'N/A',
                'hidden_urls': [],
                'sitemap_urls': []
            }
            self.found_files = []
            self.js_analyzer_results = {
                'total_files': 0,
                'files': {}
            }
            self.api_routes = []
            self.security_headers = []
            self.ssl_info = {
                'issuer': 'N/A',
                'subject': 'N/A',
                'valid_from': 'N/A',
                'expiry': 'N/A',
                'remaining_days': 'N/A',
                'tls_version': 'N/A'
            }
            self.cookie_info = []
            self.tech_fingerprints = []
            self.scores = {
                'seo': 0,
                'security': 0,
                'performance': 0
            }
            self.timeline = []
            self.screenshots = []
            self.ai_insights = {
                'summary': '',
                'security_explanations': []
            }
            
            self.is_running = True
            self.is_paused = False
            self.should_stop = False
            
            parsed_url = urlparse(start_url)
            self.domain = parsed_url.netloc
            self.to_crawl.append((start_url, 0))

        self.change_status("running")
        self.log(f"[*] Starting advanced crawl for: {start_url} (Domain: {self.domain})")
        self.log(f"[*] Max pages: {max_pages} | Max depth: {max_depth} | Threads: {threads} | Delay: {delay}s")
        
        self.add_timeline_event(f"Crawl scan initiated for: {start_url}")

        # Fetch robots.txt first
        self.get_robots_txt(start_url)
        self.add_timeline_event("Robots.txt analyzed")

        # Resolve target details
        self.resolve_target_info(start_url)
        self.add_timeline_event(f"Domain IP resolved: {self.target_info['ip']}")

        # Analyze SSL
        if start_url.startswith('https://'):
            self.analyze_ssl(self.target_info['domain'])
            self.add_timeline_event(f"SSL cert parsed: TLS version {self.ssl_info['tls_version']}")
        else:
            self.add_timeline_event("SSL verification skipped (HTTP)")

        # Sitemap discovery
        self.discover_sitemap(start_url)

        # Launch worker threads
        workers = []
        with self.lock:
            threads_to_launch = min(self.max_threads, len(self.to_crawl) + 1)
            self.active_threads_count = threads_to_launch
            
        for i in range(threads_to_launch):
            t = threading.Thread(target=self.run_worker, name=f"CrawlerWorker-{i}")
            t.daemon = True
            t.start()
            workers.append(t)

        # Monitor loop (runs in the main execution thread of the crawl task)
        while True:
            with self.lock:
                is_done = (self.active_threads_count <= 0) or (len(self.visited_urls) >= self.max_pages) or self.should_stop
                # If there are items in the queue and we have fewer active threads than allowed, spawn more
                if not is_done and self.to_crawl and self.active_threads_count < self.max_threads:
                    t = threading.Thread(target=self.run_worker, name=f"CrawlerWorker-Spawned")
                    t.daemon = True
                    t.start()
                    workers.append(t)
                    self.active_threads_count += 1
                    
            if is_done:
                break
            time.sleep(0.2)

        # Wait for any active threads to complete
        for t in workers:
            if t.is_alive():
                t.join(timeout=2.0)

        # Compare sitemap vs crawled
        if self.sitemap_info['found'] == 'YES':
            crawled_set = list(self.visited_urls)
            hidden = []
            for s_url in self.sitemap_info['sitemap_urls']:
                clean_s = s_url.split('#')[0].rstrip('/')
                is_hidden = True
                for c_url in crawled_set:
                    clean_c = c_url.split('#')[0].rstrip('/')
                    if clean_s == clean_c:
                        is_hidden = False
                        break
                if is_hidden:
                    hidden.append(s_url)
            with self.lock:
                self.sitemap_info['hidden_urls'] = hidden
                
        self.add_timeline_event("Crawl and analysis cycle completed")

        with self.lock:
            self.is_running = False
            status = "completed" if not self.should_stop else "stopped"

        self.change_status(status)

        self.log("[*] Crawl run finished.")

    def stop(self):
        with self.lock:
            self.should_stop = True
            self.is_paused = False
        self.change_status("stopped")
        self.log("[!] Stop signal requested.")

    def pause(self):
        trigger_callback = False
        with self.lock:
            if self.is_running and not self.is_paused:
                self.is_paused = True
                trigger_callback = True
                self.log("[!] Crawler paused.")
        if trigger_callback:
            self.change_status("paused")

    def resume(self):
        trigger_callback = False
        with self.lock:
            if self.is_running and self.is_paused:
                self.is_paused = False
                trigger_callback = True
                self.log("[!] Crawler resumed.")
        if trigger_callback:
            self.change_status("running")

    def get_stats(self):
        with self.lock:
            total_visited = len(self.visited_urls)
            queue_len = len(self.to_crawl)
            return {
                'pages_crawled': total_visited,
                'queue_size': queue_len,
                'emails_count': len(self.found_emails),
                'phones_count': len(self.found_phones),
                'socials_count': len(self.found_socials),
                'tech_stack_count': len(self.found_tech_stack),
                'sensitive_count': len(self.found_sensitive_endpoints),
                'internal_links_count': len(self.found_links),
                'external_links_count': len(self.found_external_links),
                'is_running': self.is_running,
                'is_paused': self.is_paused,
                'active_threads': self.active_threads_count,
                
                # New v2 fields
                'target_info': self.target_info,
                'sitemap_info': {
                    'found': self.sitemap_info['found'],
                    'total_urls': self.sitemap_info['total_urls'],
                    'last_modified': self.sitemap_info['last_modified'],
                    'hidden_urls_count': len(self.sitemap_info['hidden_urls']),
                },
                'found_files_count': len(self.found_files),
                'js_analyzer_results': {
                    'total_files': self.js_analyzer_results['total_files'],
                    'endpoints_count': sum(len(f['endpoints']) for f in self.js_analyzer_results['files'].values())
                },
                'api_routes_count': len(self.api_routes),
                'scores': self.scores,
                'timeline': self.timeline,
                'screenshots_count': len(self.screenshots)
            }

    def generate_report_dict(self):
        with self.lock:
            return {
                "crawl_domain": self.domain,
                "total_pages_crawled": len(self.visited_urls),
                "emails_found": sorted(list(self.found_emails)),
                "phones_found": sorted(list(self.found_phones)),
                "socials_found": sorted(list(self.found_socials)),
                "tech_stack_found": sorted(list(self.found_tech_stack)),
                "sensitive_endpoints_found": sorted(list(self.found_sensitive_endpoints)),
                "internal_links_found": sorted(list(self.found_links)),
                "external_links_found": sorted(list(self.found_external_links)),
                "crawled_pages": [
                    {
                        "url": url,
                        "title": self.page_titles.get(url, "No Title"),
                        "status_code": self.status_codes.get(url, "Unknown")
                    } for url in sorted(list(self.visited_urls))
                ],
                
                # New v2 fields
                "target_info": self.target_info,
                "sitemap_info": self.sitemap_info,
                "found_files": self.found_files,
                "js_analyzer_results": self.js_analyzer_results,
                "api_routes": self.api_routes,
                "security_headers": self.security_headers,
                "ssl_info": self.ssl_info,
                "cookie_info": self.cookie_info,
                "tech_fingerprints": self.tech_fingerprints,
                "scores": self.scores,
                "timeline": self.timeline,
                "screenshots": self.screenshots,
                "ai_insights": self.ai_insights
            }

    def add_timeline_event(self, event_text):
        timestamp = time.strftime("%H:%M:%S")
        with self.lock:
            self.timeline.append({'time': timestamp, 'event': event_text})
        self.log(f"[Timeline] {timestamp} - {event_text}")

    def resolve_target_info(self, start_url):
        import socket
        parsed = urlparse(start_url)
        hostname = parsed.netloc
        
        ip = 'N/A'
        try:
            ip = socket.gethostbyname(hostname)
        except Exception as e:
            self.log(f"[DNS error] Could not resolve IP for {hostname}: {str(e)}")
            
        server = 'N/A'
        cdn = 'N/A'
        hosting = 'N/A'
        country = 'N/A'
        
        if ip != 'N/A':
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    country = data.get('country', 'N/A')
                    hosting = data.get('org', 'N/A')
            except Exception as e:
                self.log(f"[IP Lookup error] Geolocation API call failed: {str(e)}")
                
        with self.lock:
            self.target_info['domain'] = hostname
            self.target_info['ip'] = ip
            self.target_info['hosting'] = hosting
            self.target_info['country'] = country

    def analyze_ssl(self, hostname):
        import ssl
        import socket
        from datetime import datetime
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    
                    subject = dict(x[0] for x in cert.get('subject', ()))
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                    
                    subject_cn = subject.get('commonName', 'N/A')
                    issuer_cn = issuer.get('commonName', 'N/A')
                    
                    not_before_str = cert.get('notBefore')
                    not_after_str = cert.get('notAfter')
                    
                    not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    
                    remaining = (not_after - datetime.utcnow()).days
                    
                    with self.lock:
                        self.ssl_info = {
                            'issuer': issuer_cn,
                            'subject': subject_cn,
                            'valid_from': not_before.strftime('%Y-%m-%d'),
                            'expiry': not_after.strftime('%Y-%m-%d'),
                            'remaining_days': remaining,
                            'tls_version': tls_version
                        }
        except Exception as e:
            self.log(f"[SSL Error] Could not retrieve SSL certificate: {str(e)}")

    def discover_sitemap(self, start_url):
        import xml.etree.ElementTree as ET
        sitemaps = ['/sitemap.xml', '/sitemap_index.xml']
        
        parsed_url = urlparse(start_url)
        base_host = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        found_sitemap = False
        sitemap_urls = []
        last_modified = 'N/A'
        
        for s in sitemaps:
            s_url = base_host + s
            try:
                response = self.session.get(s_url, timeout=5)
                if response.status_code == 200:
                    self.add_timeline_event(f"Sitemap found: {s_url}")
                    found_sitemap = True
                    
                    root = ET.fromstring(response.content)
                    ns = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                    
                    locs = root.findall('.//ns:loc', ns)
                    if not locs:
                        locs = root.findall('.//loc')
                        
                    for loc in locs:
                        if loc.text:
                            sitemap_urls.append(loc.text.strip())
                            
                    lastmods = root.findall('.//ns:lastmod', ns)
                    if not lastmods:
                        lastmods = root.findall('.//lastmod')
                    if lastmods and lastmods[0].text:
                        last_modified = lastmods[0].text.strip()
                        
                    break
            except Exception as e:
                pass
                
        with self.lock:
            if found_sitemap:
                self.sitemap_info = {
                    'found': 'YES',
                    'total_urls': len(sitemap_urls),
                    'last_modified': last_modified,
                    'hidden_urls': [],
                    'sitemap_urls': sitemap_urls
                }
            else:
                self.sitemap_info = {
                    'found': 'NO',
                    'total_urls': 0,
                    'last_modified': 'N/A',
                    'hidden_urls': [],
                    'sitemap_urls': []
                }

    def audit_security_headers_and_cookies(self, response):
        headers = response.headers
        cookies = response.cookies
        
        req_headers = {
            'Content-Security-Policy': 'Protects against XSS and injection attacks.',
            'Strict-Transport-Security': 'Enforces HTTPS connections.',
            'X-Frame-Options': 'Protects against Clickjacking.',
            'X-Content-Type-Options': 'Prevents MIME sniffing.',
            'Referrer-Policy': 'Controls referrer information sent in headers.',
            'Permissions-Policy': 'Controls browser feature usage.'
        }
        
        with self.lock:
            self.security_headers = []
            present_count = 0
            for name, desc in req_headers.items():
                val = headers.get(name, '')
                status = 'MISSING'
                if val:
                    status = 'OK'
                    present_count += 1
                self.security_headers.append({
                    'name': name,
                    'value': val or 'Not set',
                    'status': status,
                    'description': desc
                })
                
        with self.lock:
            self.cookie_info = []
            for cookie in cookies:
                httponly = cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in [k.lower() for k in cookie._rest.keys()]
                samesite = cookie._rest.get('SameSite', 'Not set')
                
                if not httponly:
                    set_cookie_headers = [v for k, v in headers.items() if k.lower() == 'set-cookie']
                    for sc in set_cookie_headers:
                        if cookie.name in sc:
                            if 'httponly' in sc.lower():
                                httponly = True
                            if 'samesite' in sc.lower():
                                for part in sc.split(';'):
                                    part = part.strip()
                                    if part.lower().startswith('samesite='):
                                        samesite = part.split('=')[1]
                
                self.cookie_info.append({
                    'name': cookie.name,
                    'secure': 'YES' if cookie.secure else 'NO',
                    'httponly': 'YES' if httponly else 'NO',
                    'samesite': samesite,
                    'expiry': time.strftime('%Y-%m-%d', time.gmtime(cookie.expires)) if cookie.expires else 'Session'
                })

    def perform_technology_fingerprinting(self, url, headers, soup):
        tech_matches = []
        server = headers.get('Server', '').lower()
        powered = headers.get('X-Powered-By', '').lower()
        html_text = str(soup) if soup else ""
        
        if 'nginx' in server:
            tech_matches.append({'tech': 'Nginx', 'category': 'Server', 'confidence': 95})
        elif 'apache' in server:
            tech_matches.append({'tech': 'Apache', 'category': 'Server', 'confidence': 95})
        elif 'litespeed' in server:
            tech_matches.append({'tech': 'LiteSpeed', 'category': 'Server', 'confidence': 90})
        elif 'microsoft-iis' in server:
            tech_matches.append({'tech': 'Microsoft IIS', 'category': 'Server', 'confidence': 95})
            
        if 'cloudflare' in server or headers.get('cf-ray'):
            tech_matches.append({'tech': 'Cloudflare', 'category': 'Server/CDN', 'confidence': 98})
            
        if 'php' in powered or 'php' in server:
            tech_matches.append({'tech': 'PHP', 'category': 'Backend Language', 'confidence': 90})
        if 'asp.net' in powered or 'asp.net' in server or 'aspx' in url.lower():
            tech_matches.append({'tech': 'ASP.NET', 'category': 'Backend Framework', 'confidence': 95})
        if 'express' in powered:
            tech_matches.append({'tech': 'Express.js', 'category': 'Backend Framework', 'confidence': 90})
            
        if soup:
            scripts = [s.get('src', '').lower() for s in soup.find_all('script') if s.get('src')]
            scripts_str = " ".join(scripts)
            
            if 'react' in scripts_str or 'react-dom' in scripts_str or 'react.min.js' in scripts_str or 'data-reactroot' in html_text:
                tech_matches.append({'tech': 'React', 'category': 'Frontend Library', 'confidence': 90})
            if '_next/static' in html_text or 'next-route-announcer' in html_text:
                tech_matches.append({'tech': 'Next.js', 'category': 'Frontend Framework', 'confidence': 98})
            if 'vue' in scripts_str or 'v-bind' in html_text or 'v-out' in html_text:
                tech_matches.append({'tech': 'Vue.js', 'category': 'Frontend Framework', 'confidence': 90})
            if 'angular' in scripts_str or 'ng-version' in html_text or 'ng-app' in html_text:
                tech_matches.append({'tech': 'Angular', 'category': 'Frontend Framework', 'confidence': 95})
            if 'svelte' in html_text.lower():
                tech_matches.append({'tech': 'Svelte', 'category': 'Frontend Framework', 'confidence': 85})
            if 'jquery' in scripts_str or 'jquery.min.js' in scripts_str or 'jquery' in html_text.lower():
                tech_matches.append({'tech': 'jQuery', 'category': 'Frontend Library', 'confidence': 85})
            if 'bootstrap' in html_text.lower() or 'bootstrap.css' in html_text.lower():
                tech_matches.append({'tech': 'Bootstrap CSS', 'category': 'Frontend CSS Framework', 'confidence': 90})
            if 'tailwind' in html_text.lower() or 'tailwindcss' in html_text.lower():
                tech_matches.append({'tech': 'Tailwind CSS', 'category': 'Frontend CSS Framework', 'confidence': 90})
                
            if '/wp-content/' in html_text or 'wp-emoji' in html_text:
                tech_matches.append({'tech': 'WordPress', 'category': 'CMS', 'confidence': 98})
            if 'cdn.shopify.com' in html_text or 'shopify.theme' in html_text.lower():
                tech_matches.append({'tech': 'Shopify', 'category': 'CMS/E-commerce', 'confidence': 98})
            if 'joomla' in html_text.lower():
                tech_matches.append({'tech': 'Joomla', 'category': 'CMS', 'confidence': 95})
            if 'drupal' in html_text.lower() or 'drupal.js' in scripts_str:
                tech_matches.append({'tech': 'Drupal', 'category': 'CMS', 'confidence': 95})
            if 'magento' in html_text.lower():
                tech_matches.append({'tech': 'Magento', 'category': 'CMS/E-commerce', 'confidence': 95})
                
            if 'mysql' in html_text.lower():
                tech_matches.append({'tech': 'MySQL', 'category': 'Database (Hint)', 'confidence': 60})
            if 'postgresql' in html_text.lower() or 'postgres' in html_text.lower():
                tech_matches.append({'tech': 'PostgreSQL', 'category': 'Database (Hint)', 'confidence': 60})
            if 'mongodb' in html_text.lower():
                tech_matches.append({'tech': 'MongoDB', 'category': 'Database (Hint)', 'confidence': 60})

        seen = set()
        unique_matches = []
        for match in tech_matches:
            if match['tech'] not in seen:
                seen.add(match['tech'])
                unique_matches.append(match)
                
        for u in unique_matches:
            with self.lock:
                self.found_tech_stack.add(u['tech'])
                
        with self.lock:
            self.tech_fingerprints = unique_matches
            
        if headers.get('Server'):
            with self.lock:
                self.target_info['server'] = headers.get('Server')

    def discover_files(self, url, soup):
        import posixpath
        extensions = ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.json', '.xml', '.txt', '.backup', '.bak', '.old')
        
        if soup:
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                path = parsed.path
                ext = posixpath.splitext(path)[1].lower()
                
                if ext in extensions:
                    with self.lock:
                        if any(f['url'] == full_url for f in self.found_files):
                            continue
                    
                    filename = posixpath.basename(path) or 'unknown'
                    file_size = 'N/A'
                    status = 200
                    try:
                        head_resp = self.session.head(full_url, timeout=5)
                        status = head_resp.status_code
                        size = head_resp.headers.get('Content-Length')
                        if size:
                            file_size = f"{int(size) / 1024:.1f} KB"
                    except:
                        pass
                    
                    file_data = {
                        'filename': filename,
                        'type': ext[1:].upper(),
                        'size': file_size,
                        'url': full_url,
                        'status_code': status
                    }
                    with self.lock:
                        self.found_files.append(file_data)

    def discover_api_from_html(self, url, soup):
        if soup:
            for form in soup.find_all('form', action=True):
                action = form['action'].strip()
                method = form.get('method', 'GET').upper()
                
                if action.startswith('/') or 'api' in action:
                    full_url = urljoin(url, action)
                    parsed = urlparse(full_url)
                    ep = parsed.path
                    
                    filename = url.split('/')[-1] or 'index.html'
                    with self.lock:
                        if not any(r['endpoint'] == ep and r['method'] == method for r in self.api_routes):
                            self.api_routes.append({
                                'method': method,
                                'endpoint': ep,
                                'source_file': filename,
                                'status': 'HTML Form'
                            })

    def capture_screenshot(self, url):
        screenshots_dir = os.path.join('static', 'screenshots')
        if not os.path.exists(screenshots_dir):
            try:
                os.makedirs(screenshots_dir)
            except Exception as e:
                self.log(f"[Screenshot error] Could not create folder: {str(e)}")
                return
                
        import hashlib
        safe_name = hashlib.md5(url.encode('utf-8')).hexdigest() + '.png'
        file_path = os.path.join(screenshots_dir, safe_name)
        
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_viewport_size({"width": 1280, "height": 800})
                page.goto(url, timeout=10000, wait_until="networkidle")
                page.screenshot(path=file_path)
                browser.close()
                
            thumbnail_url = f"/static/screenshots/{safe_name}"
            with self.lock:
                self.screenshots.append({
                    'thumbnail': thumbnail_url,
                    'url': url,
                    'time': time.strftime('%Y-%m-%d %H:%M:%S')
                })
            self.log(f"[Screenshot] Captured screenshot for: {url}")
        except Exception as e:
            self.log(f"[Screenshot Warning] Playwright failed: {str(e)}. Using placeholder.")
            thumbnail_url = "https://images.unsplash.com/photo-1544383835-bda2bc66a55d?w=400&q=80"
            with self.lock:
                self.screenshots.append({
                    'thumbnail': thumbnail_url,
                    'url': url,
                    'time': time.strftime('%Y-%m-%d %H:%M:%S')
                })

    def calculate_scores(self, url, headers, soup, response_time, page_size):
        seo_points = 0
        if soup:
            if soup.title and soup.title.string and len(soup.title.string.strip()) > 5:
                seo_points += 25
            desc = soup.find('meta', attrs={'name': 'description'})
            if desc and desc.get('content') and len(desc.get('content').strip()) > 10:
                seo_points += 25
            if soup.find('h1'):
                seo_points += 20
            elif soup.find('h2'):
                seo_points += 10
            imgs = soup.find_all('img')
            if imgs:
                alts = [i for i in imgs if i.get('alt')]
                if len(alts) / len(imgs) >= 0.5:
                    seo_points += 15
            else:
                seo_points += 15
            if len(self.found_links) > 0:
                seo_points += 15
                
        sec_points = 0
        if url.startswith('https://'):
            sec_points += 30
        header_ok_count = sum(1 for h in self.security_headers if h['status'] == 'OK')
        sec_points += int((header_ok_count / 6.0) * 50.0)
        cookie_ok_count = 0
        if self.cookie_info:
            for c in self.cookie_info:
                if c['secure'] == 'YES':
                    cookie_ok_count += 1
                if c['httponly'] == 'YES':
                    cookie_ok_count += 1
            sec_points += int((cookie_ok_count / (len(self.cookie_info) * 2.0)) * 20.0)
        else:
            sec_points += 20
            
        perf_points = 100
        if response_time > 3.0:
            perf_points -= 40
        elif response_time > 1.5:
            perf_points -= 20
        elif response_time > 0.5:
            perf_points -= 10
            
        if page_size > 2 * 1024 * 1024:
            perf_points -= 20
        elif page_size > 500 * 1024:
            perf_points -= 10
            
        seo_points = max(0, min(100, seo_points))
        sec_points = max(0, min(100, sec_points))
        perf_points = max(0, min(100, perf_points))
        
        with self.lock:
            self.scores = {
                'seo': seo_points,
                'security': sec_points,
                'performance': perf_points
            }

    def generate_ai_insights(self):
        domain = self.target_info['domain']
        techs = [f['tech'] for f in self.tech_fingerprints]
        
        category = "General Web Platform"
        description = "This site appears to be a corporate landing page or dynamic web portal."
        
        lower_domain = domain.lower()
        if 'bank' in lower_domain or 'pay' in lower_domain or 'finance' in lower_domain:
            category = "Financial Services / Banking Portal"
            description = "This site appears to handles financial operations or banking transactions."
        elif 'shop' in lower_domain or 'store' in lower_domain or 'cart' in lower_domain or 'shopify' in [t.lower() for t in techs]:
            category = "E-Commerce Storefront"
            description = "This site appears to sell goods or services online."
        elif 'edu' in lower_domain or 'school' in lower_domain or 'college' in lower_domain or 'university' in lower_domain:
            category = "Educational Portal / ERP System"
            description = "This site serves as an educational resource center, management platform, or student information ERP."
        elif 'admin' in lower_domain or 'dashboard' in lower_domain:
            category = "Administrative Portal / Control Center"
            description = "This site functions as an administration backend or dashboard panel."
            
        summary = f"AI Analysis Summary:\n"
        summary += f"This website is identified as a {category}. {description}\n\n"
        summary += f"Key Tech Stack: {', '.join(techs) if techs else 'Custom HTML/JS'}\n"
        
        explanations = []
        for h in self.security_headers:
            if h['status'] == 'MISSING':
                if h['name'] == 'Content-Security-Policy':
                    explanations.append("Missing CSP: Your website does not have Content-Security-Policy protection. This may allow unwanted content injection or XSS risks.")
                elif h['name'] == 'Strict-Transport-Security':
                    explanations.append("Missing HSTS: Strict-Transport-Security is not enforced. Attackers can downgrades user connections to insecure HTTP.")
                elif h['name'] == 'X-Frame-Options':
                    explanations.append("Missing Clickjacking Protection: X-Frame-Options is not configured. Adversaries can frame this page inside invisible overlays to hijack user clicks.")
                elif h['name'] == 'X-Content-Type-Options':
                    explanations.append("Missing MIME Sniffing Protection: X-Content-Type-Options is not set to nosniff. This allows the browser to run scripts masquerading as other filetypes.")
                elif h['name'] == 'Referrer-Policy':
                    explanations.append("Missing Referrer Policy: Referrer policy is not set. Browsers can leaks sensitive URL query parameters to external sites.")
                elif h['name'] == 'Permissions-Policy':
                    explanations.append("Missing Permissions Policy: Device feature access constraints are not set. Third-party components could access sensitive hardware like cameras or geolocation.")
                    
        if not explanations:
            explanations.append("Excellent security posture! No major missing HTTP safety headers detected.")
            
        with self.lock:
            self.ai_insights = {
                'summary': summary,
                'security_explanations': explanations
            }

    def generate_pdf_report(self):
        try:
            from fpdf import FPDF
            class PDF(FPDF):
                def header(self):
                    self.set_fill_color(8, 12, 16)
                    self.rect(0, 0, 210, 25, 'F')
                    self.set_text_color(255, 170, 0)
                    self.set_font('Helvetica', 'B', 14)
                    self.cell(0, 10, 'CRAWLME PRO v2 - SECURITY INTELLIGENCE REPORT', 0, 1, 'C')
                    self.ln(10)
                def footer(self):
                    self.set_y(-15)
                    self.set_font('Helvetica', 'I', 8)
                    self.set_text_color(128, 128, 128)
                    self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
                    
            pdf = PDF()
            pdf.add_page()
            pdf.set_y(30)
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Helvetica', 'B', 12)
            pdf.cell(0, 8, '1. Target Overview', 0, 1)
            pdf.set_font('Helvetica', '', 10)
            pdf.cell(0, 6, f"Domain: {self.target_info['domain']}", 0, 1)
            pdf.cell(0, 6, f"IP Address: {self.target_info['ip']}", 0, 1)
            pdf.cell(0, 6, f"Server Header: {self.target_info['server']}", 0, 1)
            pdf.cell(0, 6, f"Hosting Network: {self.target_info['hosting']}", 0, 1)
            pdf.cell(0, 6, f"Country: {self.target_info['country']}", 0, 1)
            pdf.ln(4)
            
            pdf.set_font('Helvetica', 'B', 12)
            pdf.cell(0, 8, '2. Intelligence Scoring Metrics', 0, 1)
            pdf.set_font('Helvetica', '', 10)
            pdf.cell(0, 6, f"SEO Score: {self.scores['seo']}%", 0, 1)
            pdf.cell(0, 6, f"Security Audit Score: {self.scores['security']}%", 0, 1)
            pdf.cell(0, 6, f"Performance Score: {self.scores['performance']}%", 0, 1)
            pdf.ln(4)
            
            pdf.set_font('Helvetica', 'B', 12)
            pdf.cell(0, 8, '3. Heuristic AI Insights', 0, 1)
            pdf.set_font('Helvetica', '', 10)
            pdf.multi_cell(0, 6, self.ai_insights['summary'])
            pdf.ln(4)
            
            pdf.set_font('Helvetica', 'B', 12)
            pdf.cell(0, 8, '4. Security Vulnerabilities Audit', 0, 1)
            pdf.set_font('Helvetica', '', 10)
            for exp in self.ai_insights['security_explanations']:
                pdf.multi_cell(0, 6, f"- {exp}")
            pdf.ln(4)
            
            pdf.set_font('Helvetica', 'B', 12)
            pdf.cell(0, 8, f"5. Discovered Assets/Files ({len(self.found_files)} items)", 0, 1)
            pdf.set_font('Helvetica', '', 10)
            for f in self.found_files[:15]:
                pdf.cell(0, 6, f"[{f['type']}] {f['filename']} - Size: {f['size']} | {f['url']}", 0, 1)
                
            return pdf.output()
        except Exception as e:
            self.log(f"[PDF generation error] {str(e)}")
            return bytes(f"PDF creation failed. Raw Text Summary:\nDomain: {self.target_info['domain']}\nScores: {self.scores}", 'utf-8')

    def generate_html_report(self):
        domain = self.target_info['domain']
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Intelligence Scan Report - {domain}</title>
    <style>
        body {{ background-color: #0b0f19; color: #cbd5e1; font-family: sans-serif; padding: 40px; }}
        h1 {{ color: #ffaa00; }}
        h2 {{ color: #00ff66; border-bottom: 1px solid #1e293b; padding-bottom: 5px; }}
        .score {{ font-size: 24px; font-weight: bold; color: #00ccff; }}
        .item {{ margin: 10px 0; }}
        a {{ color: #38bdf8; text-decoration: none; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #1e293b; }}
        th {{ background-color: #0f172a; }}
    </style>
</head>
<body>
    <h1>CRAWLME PRO v2 Security Report</h1>
    <p>Target: <strong>{domain}</strong> | Date: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>1. Scores</h2>
    <div class="score">SEO: {self.scores['seo']}%</div>
    <div class="score">Security: {self.scores['security']}%</div>
    <div class="score">Performance: {self.scores['performance']}%</div>
    
    <h2>2. Heuristic AI Insights</h2>
    <pre style="white-space: pre-wrap; font-family: inherit;">{self.ai_insights['summary']}</pre>
    
    <h2>3. Security Explanations</h2>
    <ul>
    """
        for exp in self.ai_insights['security_explanations']:
            html += f"<li>{exp}</li>"
            
        html += f"""
    </ul>
    
    <h2>4. Discovered API Endpoints</h2>
    <table>
        <tr><th>Method</th><th>Endpoint</th><th>Source File</th><th>Status</th></tr>"""
        
        for api in self.api_routes:
            html += f"<tr><td>{api['method']}</td><td>{api['endpoint']}</td><td>{api['source_file']}</td><td>{api['status']}</td></tr>"
            
        html += """
    </table>
</body>
</html>"""
        return bytes(html, 'utf-8')

    def generate_xml_report(self):
        import xml.etree.ElementTree as ET
        root = ET.Element("ScanReport")
        
        ti = ET.SubElement(root, "TargetInfo")
        for k, v in self.target_info.items():
            if isinstance(v, list):
                v = ", ".join(v)
            sub = ET.SubElement(ti, k)
            sub.text = str(v)
            
        sc = ET.SubElement(root, "Scores")
        for k, v in self.scores.items():
            sub = ET.SubElement(sc, k)
            sub.text = str(v)
            
        apis = ET.SubElement(root, "DiscoveredAPIs")
        for api in self.api_routes:
            sub = ET.SubElement(apis, "API")
            for k, v in api.items():
                attr = ET.SubElement(sub, k)
                attr.text = str(v)
                
        files_elem = ET.SubElement(root, "DiscoveredFiles")
        for f in self.found_files:
            sub = ET.SubElement(files_elem, "File")
            for k, v in f.items():
                attr = ET.SubElement(sub, k)
                attr.text = str(v)
                
        return ET.tostring(root, encoding='utf-8')
