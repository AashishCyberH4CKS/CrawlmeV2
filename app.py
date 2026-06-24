import os
import json
import queue
import threading
import io
import csv
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, send_file
from crawler_engine import AdvancedWebCrawler

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Global Crawler instance
crawler = AdvancedWebCrawler()
crawler_thread = None

# SSE broadcasting system
listeners = []
listeners_lock = threading.Lock()

def broadcast_event(event_type, event_data):
    with listeners_lock:
        for q in list(listeners):
            try:
                q.put_nowait((event_type, event_data))
            except Exception:
                pass

# Wire crawler callbacks to broadcast SSE events
def on_crawler_log(message):
    broadcast_event('log', message)

def on_crawler_status(status):
    broadcast_event('status_update', {
        'status': status,
        'stats': crawler.get_stats()
    })

def on_page_crawled(page_data):
    broadcast_event('page_crawled', page_data)
    # Also broadcast updated stats
    broadcast_event('stats_update', crawler.get_stats())

crawler.on_log_callback = on_crawler_log
crawler.on_status_changed_callback = on_crawler_status
crawler.on_page_crawled_callback = on_page_crawled

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'stats': crawler.get_stats(),
        'domain': crawler.domain
    })

@app.route('/api/start', methods=['POST'])
def start_crawl():
    global crawler_thread
    
    if crawler.get_stats()['is_running']:
        return jsonify({'error': 'Crawler is already running'}), 400
        
    data = request.json or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    max_pages = int(data.get('max_pages', 50))
    max_depth = int(data.get('max_depth', 3))
    threads = int(data.get('threads', 5))
    delay = float(data.get('delay', 1.0))
    user_agent = data.get('user_agent', 'ethical')
    respect_robots = bool(data.get('respect_robots', True))
    
    # Run the crawl in a background thread so Flask isn't blocked
    def run_crawl_task():
        try:
            crawler.start(
                start_url=url,
                max_pages=max_pages,
                max_depth=max_depth,
                threads=threads,
                delay=delay,
                user_agent=user_agent,
                respect_robots=respect_robots
            )
        except Exception as e:
            broadcast_event('log', f"[CRITICAL ERROR] Thread crashed: {str(e)}")
            
    crawler_thread = threading.Thread(target=run_crawl_task, daemon=True)
    crawler_thread.start()
    
    return jsonify({'message': 'Crawl started successfully', 'stats': crawler.get_stats()})

@app.route('/api/stop', methods=['POST'])
def stop_crawl():
    if not crawler.get_stats()['is_running']:
        return jsonify({'error': 'Crawler is not running'}), 400
    crawler.stop()
    return jsonify({'message': 'Stop requested'})

@app.route('/api/pause', methods=['POST'])
def pause_crawl():
    stats = crawler.get_stats()
    if not stats['is_running']:
        return jsonify({'error': 'Crawler is not running'}), 400
    if stats['is_paused']:
        return jsonify({'error': 'Crawler is already paused'}), 400
    crawler.pause()
    return jsonify({'message': 'Crawl paused'})

@app.route('/api/resume', methods=['POST'])
def resume_crawl():
    stats = crawler.get_stats()
    if not stats['is_running']:
        return jsonify({'error': 'Crawler is not running'}), 400
    if not stats['is_paused']:
        return jsonify({'error': 'Crawler is not paused'}), 400
    crawler.resume()
    return jsonify({'message': 'Crawl resumed'})

@app.route('/api/stream')
def sse_stream():
    q = queue.Queue()
    with listeners_lock:
        listeners.append(q)
        
    def generate():
        # Yield the current status as initial message
        yield f"event: init\ndata: {json.dumps({'stats': crawler.get_stats(), 'domain': crawler.domain})}\n\n"
        while True:
            try:
                event_type, event_data = q.get(timeout=10.0)
                yield f"event: {event_type}\ndata: {json.dumps(event_data)}\n\n"
            except queue.Empty:
                # Keepalive ping
                yield "event: ping\ndata: {}\n\n"
            except GeneratorExit:
                break
            except Exception:
                break
                
        # Clean up queue when client disconnects
        with listeners_lock:
            if q in listeners:
                listeners.remove(q)
                
    return Response(generate(), mimetype="text/event-stream")

@app.route('/api/results', methods=['GET'])
def get_results():
    return jsonify(crawler.generate_report_dict())

@app.route('/api/export/<export_type>', methods=['GET'])
def export_data(export_type):
    report = crawler.generate_report_dict()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_safe = crawler.domain.replace('.', '_') or 'site'
    
    if export_type == 'json':
        json_data = json.dumps(report, indent=4)
        return send_file(
            io.BytesIO(json_data.encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name=f"crawl_report_{domain_safe}_{timestamp}.json"
        )
        
    elif export_type == 'txt':
        # Recreate the beautiful text report format
        out = io.StringIO()
        out.write("="*70 + "\n")
        out.write("           WEB CRAWLER REPORT - ADVANCED WEB ENGINE\n")
        out.write("="*70 + "\n")
        out.write(f"Target Domain: {report['crawl_domain']}\n")
        out.write(f"Crawl Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"Total Pages Crawled: {report['total_pages_crawled']}\n")
        out.write(f"Emails Found: {len(report['emails_found'])}\n")
        out.write(f"Phone Numbers Found: {len(report['phones_found'])}\n")
        out.write(f"Social Links Found: {len(report['socials_found'])}\n")
        out.write(f"Tech Stacks Found: {len(report['tech_stack_found'])}\n")
        out.write(f"Sensitive Paths Tagged: {len(report['sensitive_endpoints_found'])}\n")
        out.write(f"Internal Links Found: {len(report['internal_links_found'])}\n")
        out.write(f"External Links Found: {len(report['external_links_found'])}\n")
        out.write("="*70 + "\n\n")
        
        out.write("📧 DISCOVERED EMAILS:\n")
        out.write("-" * 50 + "\n")
        for item in report['emails_found']:
            out.write(f"{item}\n")
        out.write("\n")
        
        out.write("📞 DISCOVERED PHONE NUMBERS:\n")
        out.write("-" * 50 + "\n")
        for item in report['phones_found']:
            out.write(f"{item}\n")
        out.write("\n")
        
        out.write("🔗 SOCIAL MEDIA PROFILES:\n")
        out.write("-" * 50 + "\n")
        for item in report['socials_found']:
            out.write(f"{item}\n")
        out.write("\n")
            
        out.write("🛠️ DETECTED TECH STACK:\n")
        out.write("-" * 50 + "\n")
        for item in report['tech_stack_found']:
            out.write(f"{item}\n")
        out.write("\n")
        
        out.write("🚨 POTENTIALLY SENSITIVE ENDPOINTS:\n")
        out.write("-" * 50 + "\n")
        for item in report['sensitive_endpoints_found']:
            out.write(f"{item}\n")
        out.write("\n")
        
        out.write("🌐 CRAWLED URLs:\n")
        out.write("-" * 50 + "\n")
        for item in report['crawled_pages']:
            out.write(f"[{item['status_code']}] {item['url']} - {item['title']}\n")
            
        mem = io.BytesIO(out.getvalue().encode('utf-8'))
        return send_file(
            mem,
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"crawl_report_{domain_safe}_{timestamp}.txt"
        )
        
    elif export_type in ['emails', 'phones', 'socials', 'sensitive', 'links', 'files', 'apis']:
        out = io.StringIO()
        writer = csv.writer(out)
        
        if export_type == 'emails':
            writer.writerow(['Email Address'])
            for item in report['emails_found']:
                writer.writerow([item])
        elif export_type == 'phones':
            writer.writerow(['Phone Number'])
            for item in report['phones_found']:
                writer.writerow([item])
        elif export_type == 'socials':
            writer.writerow(['Social Link'])
            for item in report['socials_found']:
                writer.writerow([item])
        elif export_type == 'sensitive':
            writer.writerow(['Endpoint'])
            for item in report['sensitive_endpoints_found']:
                writer.writerow([item])
        elif export_type == 'links':
            writer.writerow(['URL', 'Type'])
            for item in report['internal_links_found']:
                writer.writerow([item, 'Internal'])
            for item in report['external_links_found']:
                writer.writerow([item, 'External'])
        elif export_type == 'files':
            writer.writerow(['Filename', 'Type', 'Size', 'URL', 'Status'])
            for item in report.get('found_files', []):
                writer.writerow([item['filename'], item['type'], item['size'], item['url'], item['status_code']])
        elif export_type == 'apis':
            writer.writerow(['Method', 'Endpoint', 'Source File', 'Status'])
            for item in report.get('api_routes', []):
                writer.writerow([item['method'], item['endpoint'], item['source_file'], item['status']])
                
        mem = io.BytesIO(out.getvalue().encode('utf-8'))
        return send_file(
            mem,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"crawl_{export_type}_{domain_safe}_{timestamp}.csv"
        )
        
    elif export_type == 'pdf':
        pdf_data = crawler.generate_pdf_report()
        return send_file(
            io.BytesIO(pdf_data),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"crawl_report_{domain_safe}_{timestamp}.pdf"
        )
        
    elif export_type == 'html':
        html_data = crawler.generate_html_report()
        return send_file(
            io.BytesIO(html_data),
            mimetype='text/html',
            as_attachment=True,
            download_name=f"crawl_report_{domain_safe}_{timestamp}.html"
        )
        
    elif export_type == 'xml':
        xml_data = crawler.generate_xml_report()
        return send_file(
            io.BytesIO(xml_data),
            mimetype='application/xml',
            as_attachment=True,
            download_name=f"crawl_report_{domain_safe}_{timestamp}.xml"
        )
        
    else:
        return jsonify({'error': 'Invalid export format'}), 400

if __name__ == '__main__':
    # Default local port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
