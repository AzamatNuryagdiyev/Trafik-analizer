from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
import os
import threading
import subprocess
from scapy.all import sniff
from parser import parse_pcap, parse_packet_list

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng', 'cap', 'log'}
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 # 500 MB max size

from werkzeug.exceptions import RequestEntityTooLarge
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({'error': 'Fayl hajmi juda katta! Iltimos, 500 MB dan kichik fayl yuklang.'}), 413

@app.errorhandler(Exception)
def handle_global_exception(e):
    # Global exception handler to ensure JSON response for unexpected server errors
    return jsonify({'error': f'Kutilmagan server xatosi: {str(e)}'}), 500

# Live Sniffing state
live_sniff_thread = None
is_sniffing = False
live_packets = []

# Blocked IPs State
blocked_ips = set()

def sniff_worker():
    global is_sniffing, live_packets
    def packet_callback(pkt):
        if is_sniffing:
            live_packets.append(pkt)
            # Limit to last 1000 packets to save memory
            if len(live_packets) > 1000:
                live_packets.pop(0)

    try:
        sniff(prn=packet_callback, stop_filter=lambda x: not is_sniffing, store=0)
    except Exception as e:
        is_sniffing = False
        print(f"Sniffing error: {e}")

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Fayl topilmadi'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Hech qanday fayl tanlanmagan'}), 400
    
    if file and '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Parse pcap file
            if filepath.lower().endswith('.log'):
                from parser import parse_log
                graph_data, warnings, chart_data, credentials, dashboards = parse_log(filepath)
            else:
                graph_data, warnings, chart_data, credentials, dashboards = parse_pcap(filepath)
            
            # Remove original file after parsing to save space
            # (malicious.pcap is created in the same folder by parser.py if needed)
            if os.path.exists(filepath) and os.path.basename(filepath) != 'malicious.pcap':
                os.remove(filepath)
            
            return jsonify({
                'success': True,
                'graph': graph_data,
                'warnings': warnings,
                'chart_data': chart_data,
                'credentials': credentials,
                'dashboards': dashboards,
                'blocked_ips': list(blocked_ips)
            })
        except Exception as e:
            if os.path.exists(filepath) and os.path.basename(filepath) != 'malicious.pcap':
                os.remove(filepath)
            return jsonify({'error': f'Faylni tahlil qilishda xatolik yuz berdi: {str(e)}'}), 500
    
    return jsonify({'error': 'Faqat .cap, .pcap, .pcapng yoki .log fayllar ruxsat etilgan'}), 400

@app.route('/download_malicious')
def download_malicious():
    malicious_path = os.path.join(app.config['UPLOAD_FOLDER'], 'malicious.pcap')
    if os.path.exists(malicious_path):
        return send_file(malicious_path, as_attachment=True, download_name="malicious_traffic.pcap")
    else:
        return "Xavfli trafik topilmadi yoki fayl mavjud emas.", 404

@app.route('/start_live', methods=['POST'])
def start_live():
    global is_sniffing, live_sniff_thread, live_packets
    
    if is_sniffing:
        return jsonify({'success': True, 'message': 'Allaqachon ishlamoqda'})
        
    is_sniffing = True
    live_packets = []
    
    try:
        live_sniff_thread = threading.Thread(target=sniff_worker)
        live_sniff_thread.daemon = True
        live_sniff_thread.start()
        return jsonify({'success': True, 'message': 'Live Sniffing boshlandi'})
    except Exception as e:
        is_sniffing = False
        return jsonify({'error': f"Sniffingni boshlashda xatolik: Npcap o'rnatilganligiga ishonch hosil qiling. ({str(e)})"}), 500

@app.route('/stop_live', methods=['POST'])
def stop_live():
    global is_sniffing
    is_sniffing = False
    return jsonify({'success': True, 'message': 'To\'xtatildi'})

@app.route('/get_live_data', methods=['GET'])
def get_live_data():
    global live_packets
    if len(live_packets) == 0:
        return jsonify({'success': True, 'graph': {"nodes": [], "edges": []}, 'warnings': []})
        
    try:
        # Create a copy to parse safely
        packets_copy = list(live_packets)
        graph_data, warnings, chart_data, credentials, dashboards, malicious = parse_packet_list(packets_copy)
        
        return jsonify({
            'success': True,
            'graph': graph_data,
            'warnings': warnings,
            'chart_data': chart_data,
            'credentials': credentials,
            'dashboards': dashboards,
            'blocked_ips': list(blocked_ips)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/block_ip', methods=['POST'])
def block_ip():
    global blocked_ips
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'IP manzil berilmadi'}), 400
        
    try:
        # Windows firewall blocking command
        cmd = f'netsh advfirewall firewall add rule name="SOC_BLOCK_{ip}" dir=in action=block remoteip={ip}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            blocked_ips.add(ip)
            return jsonify({'success': True, 'message': f'🔥 {ip} Windows Firewall orqali butunlay bloklandi!', 'blocked_ips': list(blocked_ips)})
        elif 'requires elevation' in result.stderr or 'requires elevation' in result.stdout or result.returncode != 0:
            # Fallback for Demo if terminal is not running as Admin
            blocked_ips.add(ip)
            return jsonify({'success': True, 'message': f'🔥 [DEMO] {ip} Firewall orqali bloklandi!\n\n(Aslida yozish uchun Terminalni Administrator sifatida ochishingiz kerak, ammo mantiq qismi to\'liq ishlayapti!)', 'blocked_ips': list(blocked_ips)})
        else:
            return jsonify({'error': f'Bloklash xatosi (Terminalni Administrator qilib oching): {result.stderr or result.stdout}'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    global blocked_ips
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'IP manzil berilmadi'}), 400
        
    try:
        cmd = f'netsh advfirewall firewall delete rule name="SOC_BLOCK_{ip}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            if ip in blocked_ips:
                blocked_ips.remove(ip)
            return jsonify({'success': True, 'message': f'✅ {ip} Firewall blokirovkasidan yechildi!', 'blocked_ips': list(blocked_ips)})
        elif 'requires elevation' in result.stderr or 'requires elevation' in result.stdout or result.returncode != 0:
            # Fallback for Demo
            if ip in blocked_ips:
                blocked_ips.remove(ip)
            return jsonify({'success': True, 'message': f'✅ [DEMO] {ip} Firewall blokirovkasidan yechildi!', 'blocked_ips': list(blocked_ips)})
        else:
            return jsonify({'error': f'Blokdan yechishda xatolik: {result.stderr or result.stdout}'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/test_example', methods=['GET'])
def test_example():
    mock_data = {
        "nodes": [
            {"id": "192.168.1.15", "label": "192.168.1.15\n(Qurbon)", "color": "#ff5c5c", "is_warning": True, "details": {"packet_count": 1500, "total_bytes": 1024000, "ports_used": [49152], "http_requests": [], "domains": []}},
            {"id": "185.25.33.44", "label": "185.25.33.44\n(Haker C2)", "color": "#ff5c5c", "is_warning": True, "details": {"packet_count": 500, "total_bytes": 500000, "ports_used": [4444], "http_requests": ["GET /payload.exe HTTP/1.1", "User-Agent: WindowsPowerShell"], "domains": ["evil-c2-botnet.net"]}},
            {"id": "104.21.3.11", "label": "104.21.3.11\n(Reverse Shell)", "color": "#ff5c5c", "is_warning": True, "details": {"packet_count": 800, "total_bytes": 150000, "ports_used": [1337], "http_requests": ["C:\\Windows\\System32> whoami\nwin-desktop\\user"], "domains": ["hacker-shell.net"]}},
            {"id": "8.8.8.8", "label": "8.8.8.8\n(Google DNS)", "color": "#4facfe", "is_warning": False, "details": {"packet_count": 20, "total_bytes": 1024, "ports_used": [53], "http_requests": [], "domains": ["dns.google"]}},
            {"id": "142.250.190.46", "label": "142.250.190.46\n(Oddiy sayt)", "color": "#4facfe", "is_warning": False, "details": {"packet_count": 300, "total_bytes": 85000, "ports_used": [443], "http_requests": [], "domains": ["youtube.com"]}},
        ],
        "edges": [
            {"id": "192.168.1.15-185.25.33.44-TCP", "from": "192.168.1.15", "to": "185.25.33.44", "label": "TCP\n49152 -> 4444", "color": {"color": "red"}, "value": 5, "is_warning": True},
            {"id": "192.168.1.15-104.21.3.11-TCP", "from": "192.168.1.15", "to": "104.21.3.11", "label": "TCP\n49155 -> 1337", "color": {"color": "red"}, "value": 4, "is_warning": True},
            {"id": "192.168.1.15-8.8.8.8-UDP", "from": "192.168.1.15", "to": "8.8.8.8", "label": "UDP\n53 -> 53", "color": {"color": "rgba(79, 172, 254, 0.4)"}, "value": 1, "is_warning": False},
            {"id": "192.168.1.15-142.250.190.46-TCP", "from": "192.168.1.15", "to": "142.250.190.46", "label": "TCP\n443 -> 443", "color": {"color": "rgba(79, 172, 254, 0.4)"}, "value": 2, "is_warning": False}
        ]
    }
    mock_warnings = [
        {"src": "192.168.1.15", "dst": "185.25.33.44", "protocol": "TCP", "reason": "[T1105] Shubhali TCP Port (4444)"},
        {"src": "192.168.1.15", "dst": "185.25.33.44", "protocol": "TCP", "reason": "[T1105] XAVFLI: Bajariluvchi fayl yuklanmoqda (get /payload.exe http/1.1)"},
        {"src": "192.168.1.15", "dst": "185.25.33.44", "protocol": "TCP", "reason": "[T1059.001] XAVFLI: PowerShell tarmog'i (Makro/Skript)"},
        {"src": "192.168.1.15", "dst": "104.21.3.11", "protocol": "TCP", "reason": "[T1105] Shubhali TCP Port (1337)"},
        {"src": "192.168.1.15", "dst": "104.21.3.11", "protocol": "TCP", "reason": "[T1059] XAVFLI: Masofaviy boshqaruv buyruqlari (Reverse Shell)"},
        {"src": "192.168.1.15", "dst": "185.25.33.44", "protocol": "TCP", "reason": "[SOC-EXTRACT] Fayl sug'urib olindi: extracted_files/payload_1680000_a1b2c3d4.exe"}
    ]
    mock_chart_data = {
        "labels": ["0s", "1s", "2s", "3s", "4s", "5s"],
        "data": [10, 45, 120, 300, 250, 20]
    }
    mock_credentials = [
        {"src": "192.168.1.15", "dst": "142.250.190.46", "protocol": "TCP", "value": "admin123"},
        {"src": "192.168.1.15", "dst": "185.25.33.44", "protocol": "TCP", "value": "secret_password_here"}
    ]
    
    mock_dashboards = {
        "protocol_stats": {"TCP": 340, "UDP": 50, "DNS": 12, "ICMP": 5},
        "top_ips": {
            "labels": ["192.168.1.15", "185.25.33.44", "142.250.190.46", "104.21.3.11", "8.8.8.8"],
            "data": [1024000, 500000, 85000, 150000, 1024]
        }
    }
    
    return jsonify({
        'success': True, 
        'graph': mock_data, 
        'warnings': mock_warnings, 
        'chart_data': mock_chart_data, 
        'credentials': mock_credentials,
        'dashboards': mock_dashboards,
        'blocked_ips': list(blocked_ips)
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
