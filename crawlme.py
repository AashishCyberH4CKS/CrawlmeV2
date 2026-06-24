import argparse
import sys
import os
import time
from datetime import datetime
from crawler_engine import AdvancedWebCrawler

# Initialize color codes for terminal
class Colors:
    GOLD = '\033[38;5;214m'
    ORANGE = '\033[38;5;208m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

def animate_text(text, delay=0.03):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner = f"""{Colors.GOLD}
    ░█████╗░██████╗░░█████╗░░██╗░░░░░░░██╗██╗░░░░░██╗  ███╗░░░███╗███████╗
    ██╔══██╗██╔══██╗██╔══██╗░██║░░██╗░░██║██║░░░░░╚█║  ████╗░████║██╔════╝
    ██║░░╚═╝██████╔╝███████║░╚██╗████╗██╔╝██║░░░░░░╚╝  ██╔████╔██║█████╗░░
    ██║░░██╗██╔══██╗██╔══██║░░████╔═████║░██║░░░░░░░░  ██║╚██╔╝██║██╔══╝░░
    ╚█████╔╝██║░░██║██║░░██║░░╚██╔╝░╚██╔╝░███████╗░░░  ██║░╚═╝░██║███████╗
    ░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚══════╝░░░  ╚═╝░░░░░╚═╝╚══════╝
    {Colors.END}"""
    
    print(banner)
    
    creator_text = f"{Colors.GOLD}{Colors.BOLD}           Created By AashishCyberH4CKS | Version 2.0 {Colors.END}🔥👨‍💻🔒"
    animate_text(creator_text, 0.03)
    
    print(f"\n{Colors.ORANGE}{'='*70}{Colors.END}")
    print(f"{Colors.RED}🚀 WELCOME TO THE ULTIMATE WEB CRAWLER TOOL {Colors.GREEN}⚡{Colors.END}")
    print(f"{Colors.RED}🔐 For Educational & Ethical Use Only {Colors.GREEN}✅{Colors.END}")
    print(f"{Colors.ORANGE}{'='*70}{Colors.END}\n")

# Global counter for reports in this process session
crawl_count = 0

def save_txt_report(report):
    global crawl_count
    crawl_count += 1
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_safe = report['crawl_domain'].replace('.', '_') or 'site'
    filename = f"crawl_report_{crawl_count}_{timestamp}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("           WEB CRAWLER REPORT - ADVANCED WEB ENGINE\n")
        f.write("="*70 + "\n")
        f.write(f"Target Domain: {report['crawl_domain']}\n")
        f.write(f"Crawl Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Pages Crawled: {report['total_pages_crawled']}\n")
        f.write(f"Emails Found: {len(report['emails_found'])}\n")
        f.write(f"Phone Numbers Found: {len(report['phones_found'])}\n")
        f.write(f"Social Links Found: {len(report['socials_found'])}\n")
        f.write(f"Tech Stacks Found: {len(report['tech_stack_found'])}\n")
        f.write(f"Sensitive Paths Tagged: {len(report['sensitive_endpoints_found'])}\n")
        f.write(f"Internal Links Found: {len(report['internal_links_found'])}\n")
        f.write(f"External Links Found: {len(report['external_links_found'])}\n")
        f.write("="*70 + "\n\n")
        
        f.write("📧 DISCOVERED EMAILS:\n")
        f.write("-" * 50 + "\n")
        for item in report['emails_found']:
            f.write(f"{item}\n")
        f.write("\n")
        
        f.write("📞 DISCOVERED PHONE NUMBERS:\n")
        f.write("-" * 50 + "\n")
        for item in report['phones_found']:
            f.write(f"{item}\n")
        f.write("\n")
        
        f.write("🔗 SOCIAL MEDIA PROFILES:\n")
        f.write("-" * 50 + "\n")
        for item in report['socials_found']:
            f.write(f"{item}\n")
        f.write("\n")
            
        f.write("🛠️ DETECTED TECH STACK:\n")
        f.write("-" * 50 + "\n")
        for item in report['tech_stack_found']:
            f.write(f"{item}\n")
        f.write("\n")
        
        f.write("🚨 POTENTIALLY SENSITIVE ENDPOINTS:\n")
        f.write("-" * 50 + "\n")
        for item in report['sensitive_endpoints_found']:
            f.write(f"{item}\n")
        f.write("\n")
        
        f.write("🌐 CRAWLED URLs:\n")
        f.write("-" * 50 + "\n")
        for item in report['crawled_pages']:
            f.write(f"[{item['status_code']}] {item['url']} - {item['title']}\n")
            
    return filename

def log_callback(message):
    # Print with nice colors based on log indicators
    if message.startswith('[+]'):
        print(f"{Colors.GREEN}{message}{Colors.END}")
    elif message.startswith('[-]'):
        print(f"{Colors.YELLOW}{message}{Colors.END}")
    elif message.startswith('[x]'):
        print(f"{Colors.RED}{message}{Colors.END}")
    elif message.startswith('[*]'):
        print(f"{Colors.PURPLE}{message}{Colors.END}")
    elif message.startswith('[OK]'):
        print(f"{Colors.CYAN}{Colors.BOLD}{message}{Colors.END}")
    else:
        print(message)

def perform_cli_crawl(url, max_pages, max_depth, threads, delay, respect_robots):
    crawler = AdvancedWebCrawler()
    crawler.on_log_callback = log_callback
    
    start_time = time.time()
    
    try:
        crawler.start(
            start_url=url,
            max_pages=max_pages,
            max_depth=max_depth,
            threads=threads,
            delay=delay,
            respect_robots=respect_robots
        )
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Crawl interrupted by user. Stopping workers...{Colors.END}")
        crawler.stop()
        
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    stats = crawler.get_stats()
    report = crawler.generate_report_dict()
    
    print(f"\n{Colors.GREEN}✅ Crawling completed in {elapsed_time:.2f} seconds!{Colors.END}")
    
    report_file = save_txt_report(report)
    print(f"{Colors.GREEN}📄 Detailed report saved to: {report_file}{Colors.END}")
    
    # Display summary
    print(f"\n{Colors.PURPLE}{Colors.BOLD}📊 CRAWL SUMMARY:{Colors.END}")
    print(f"{Colors.CYAN}📝 Pages crawled: {stats['pages_crawled']}{Colors.END}")
    print(f"{Colors.CYAN}📧 Emails found: {stats['emails_count']}{Colors.END}")
    print(f"{Colors.CYAN}📞 Phone numbers found: {stats['phones_count']}{Colors.END}")
    print(f"{Colors.CYAN}🔗 Social links found: {stats['socials_count']}{Colors.END}")
    print(f"{Colors.CYAN}⚙️ Tech stack matched: {stats['tech_stack_count']}{Colors.END}")
    print(f"{Colors.CYAN}🚨 Sensitive endpoints: {stats['sensitive_count']}{Colors.END}")
    print(f"{Colors.CYAN}🌐 Links processed: {stats['internal_links_count']} internal, {stats['external_links_count']} external{Colors.END}")

def start_web_server():
    # Import app inside here to prevent circular imports if any
    try:
        from app import app
        print(f"\n{Colors.GREEN}🚀 Starting Web Dashboard Server...{Colors.END}")
        print(f"{Colors.CYAN}🔗 Open your browser at: {Colors.BOLD}http://127.0.0.1:5000{Colors.END}\n")
        app.run(host='127.0.0.1', port=5000, debug=False)
    except ImportError as e:
        print(f"{Colors.RED}❌ Error importing Flask app: {str(e)}{Colors.END}")
        print(f"{Colors.YELLOW}Please ensure Flask and all requirements are installed: pip install -r requirements.txt{Colors.END}")

def main():
    # Force UTF-8 encoding for standard output and error to prevent Windows console failures
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
        
    parser = argparse.ArgumentParser(description="CrawlMe Pro - Advanced Web Crawler and Intelligence Engine")
    parser.add_argument('--web', '-w', action='store_true', help="Launch the Flask web dashboard UI")
    parser.add_argument('--url', '-u', type=str, help="Seed URL to crawl immediately via CLI")
    parser.add_argument('--pages', '-p', type=int, default=100, help="Max pages to crawl (default: 100)")
    parser.add_argument('--depth', '-d', type=int, default=3, help="Max crawl depth (default: 3)")
    parser.add_argument('--threads', '-t', type=int, default=5, help="Worker thread count (default: 5)")
    parser.add_argument('--delay', '-s', type=float, default=1.0, help="Crawl delay in seconds (default: 1.0)")
    parser.add_argument('--ignore-robots', action='store_true', help="Ignore target robots.txt guidelines")
    
    args = parser.parse_args()
    
    if args.web:
        display_banner()
        start_web_server()
        return

    display_banner()
    
    # Direct CLI crawl via command parameters
    if args.url:
        url = args.url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        respect_robots = not args.ignore_robots
        perform_cli_crawl(url, args.pages, args.depth, args.threads, args.delay, respect_robots)
        return

    # Interactive CLI mode loop
    while True:
        url = input(f"{Colors.BLUE}{Colors.BOLD}💻 Enter target URL to crawl (or 'web' for UI, 'quit' to exit): {Colors.END}").strip()
        
        if url.lower() == 'quit':
            print(f"\n{Colors.GREEN}👋 Thanks for using CrawlMe Pro! Happy ethical hacking! {Colors.END}🚀\n")
            break
            
        if url.lower() == 'web':
            start_web_server()
            break
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        print(f"\n{Colors.YELLOW}⚡ Initiating Crawl sequence for {url}...{Colors.END}\n")
        perform_cli_crawl(url, max_pages=100, max_depth=3, threads=5, delay=1.0, respect_robots=False)
        print(f"\n{Colors.ORANGE}{'='*70}{Colors.END}\n")

if __name__ == "__main__":
    # Ensure ANSI colors are initialized for Windows consoles
    if os.name == 'nt':
        import colorama
        colorama.init()
    main()