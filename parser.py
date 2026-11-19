import re
import os
import time
import hashlib
from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, ICMP
import base64
from collections import defaultdict
import numpy as np
import string

SUSPECT_PORTS = {4444, 1337, 31337, 6667, 8080}
# Mock Threat Intelligence Feed (Top 10 known malicious IPs/ranges)
THREAT_IPS = {'185.25.33.44', '104.21.3.11', '195.22.28.19', '8.8.8.8'}  # 8.8.8.8 here is just for demonstration if user wants to test
CREDENTIAL_PATTERN = re.compile(r"(?i)(?:username|login|password|pwd)\s*[:=]\s*([a-zA-Z0-9_@.-]+)")

def is_mostly_printable(text):
    if not text: return False
    printable = set(string.printable)
    count = sum(1 for c in text if c in printable)
    return count / len(text) > 0.85

def is_suspect(packet):
    warnings = []
    if IP in packet:
        if TCP in packet:
            if packet[TCP].dport in SUSPECT_PORTS or packet[TCP].sport in SUSPECT_PORTS:
                warnings.append(f"[T1105] Shubhali TCP Port ({packet[TCP].dport if packet[TCP].dport in SUSPECT_PORTS else packet[TCP].sport})")
        elif UDP in packet:
            if packet[UDP].dport in SUSPECT_PORTS or packet[UDP].sport in SUSPECT_PORTS:
                warnings.append(f"[T1105] Shubhali UDP Port ({packet[UDP].dport if packet[UDP].dport in SUSPECT_PORTS else packet[UDP].sport})")
        
    if DNSQR in packet and not warnings:
        qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
        
        # 1. Uzunlik va nuqtalar bo'yicha DGA tekshiruvi
        if len(qname) > 50 or qname.count('.') > 4:
            warnings.append(f"[T1071.004] Shubhali DNS So'rov (C2 DGA): {qname}")
            
        # 2. Base64 DNS Exfiltration (Ma'lumot o'g'irlash) tekshiruvi
        parts = qname.split('.')
        for p in parts:
            if len(p) >= 6 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', p):
                try:
                    padded_p = p + '=' * (-len(p) % 4)
                    decoded_bytes = base64.b64decode(padded_p)
                    # Check if it decodes to actual printable text, not random bytes
                    decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                    
                    # Ensure it has letters/numbers and is not just gibberish
                    if len(decoded_str) >= 3 and is_mostly_printable(decoded_str):
                        warnings.append(f"[T1048.003] XAVFLI: DNS orqali ma'lumot o'g'irlanmoqda! Shifr yechildi: '{decoded_str}' (Asl qism: {p})")
                except:
                    pass
            
    if packet.haslayer(Raw):
        raw_bytes = packet[Raw].load
        try:
            text_data = raw_bytes.decode('utf-8', errors='ignore')
            
            if "GET " in text_data and " HTTP/1" in text_data:
                first_line = text_data.split('\r\n')[0].lower()
                if any(ext in first_line for ext in ['.exe ', '.dll ', '.vbs ', '.bat ', '.ps1 ', '.scr ']):
                    warnings.append(f"[T1105] XAVFLI: Bajariluvchi fayl yuklanmoqda ({first_line})")
            
            if "User-Agent: WindowsPowerShell" in text_data:
                warnings.append("[T1059.001] XAVFLI: PowerShell tarmog'i (Makro/Skript)")
            if "User-Agent: Microsoft Office" in text_data and ".exe" in text_data.lower():
                warnings.append("[T1566.001] XAVFLI: Office Makrosidan fayl yuklanmoqda!")

            text_lower = text_data.lower()
            shell_commands = ['whoami', 'ipconfig', 'ifconfig', 'netstat -ano', 'tasklist', 'net user']
            shell_prompts = ['microsoft windows [version', 'c:\\windows\\system32>', '/bin/bash', 'root@']
            
            if any(cmd in text_lower for cmd in shell_commands) or any(prompt in text_lower for prompt in shell_prompts):
                warnings.append("[T1059] XAVFLI: Masofaviy boshqaruv buyruqlari (Reverse Shell)")

        except:
            pass
            
        if b'MZ' in raw_bytes and b'This program cannot be run in DOS mode' in raw_bytes:
            warnings.append("[T1105] XAVFLI: Tarmoq ichida EXE (virus) fayl uzatilmoqda!")
            
            # FILE EXTRACTION (Bosqich 2)
            try:
                os.makedirs('extracted_files', exist_ok=True)
                file_hash = hashlib.md5(raw_bytes).hexdigest()[:8]
                extract_path = f"extracted_files/payload_{int(time.time())}_{file_hash}.exe"
                with open(extract_path, "wb") as f:
                    f.write(raw_bytes)
                warnings.append(f"[SOC-EXTRACT] Fayl sug'urib olindi: {extract_path}")
            except Exception as e:
                pass

    return warnings if len(warnings) > 0 else None

def parse_packet_list(packets):
    nodes = {}
    edges = {}
    warnings = []
    malicious_packets = []
    stolen_credentials = []
    shell_history = []
    
    # Store timestamps per connection for Beaconing detection
    connection_times = defaultdict(list)
    
    # Time-series for charting (packets per second timestamp)
    time_series = defaultdict(int)
    
    # Protocol distribution stats
    protocol_stats = defaultdict(int)
    
    dns_map = {}

    for pkt in packets:
        # Time tracking
        pkt_time = int(pkt.time)
        time_series[pkt_time] += 1
        
        # DNS Mapping
        if DNS in pkt and pkt.haslayer(DNSRR):
            for i in range(pkt[DNS].ancount):
                rr = pkt[DNS].an[i]
                if rr.type == 1:
                    ip_addr = rr.rdata
                    domain = rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                    if isinstance(ip_addr, str):
                        dns_map[ip_addr] = domain

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            pkt_len = len(pkt)
            
            for ip in [src_ip, dst_ip]:
                if ip not in nodes:
                    nodes[ip] = {
                        "id": ip, "label": ip, "color": "#4facfe", "is_warning": False,
                        "details": {"packet_count": 0, "total_bytes": 0, "ports_used": set(), "http_requests": [], "domains": set(), "threat_info": set()}
                    }
            
            nodes[src_ip]["details"]["packet_count"] += 1
            nodes[src_ip]["details"]["total_bytes"] += pkt_len
            nodes[dst_ip]["details"]["packet_count"] += 1
            nodes[dst_ip]["details"]["total_bytes"] += pkt_len

            protocol = "IP"
            port_info = ""
            
            if TCP in pkt:
                protocol = "TCP"
                protocol_stats["TCP"] += 1
                port_info = f"{pkt[TCP].sport} -> {pkt[TCP].dport}"
                nodes[src_ip]["details"]["ports_used"].add(pkt[TCP].sport)
                nodes[dst_ip]["details"]["ports_used"].add(pkt[TCP].dport)
            elif UDP in pkt:
                if DNS in pkt:
                    protocol = "DNS"
                    protocol_stats["DNS"] += 1
                else:
                    protocol = "UDP"
                    protocol_stats["UDP"] += 1
                port_info = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
                nodes[src_ip]["details"]["ports_used"].add(pkt[UDP].sport)
                nodes[dst_ip]["details"]["ports_used"].add(pkt[UDP].dport)
            elif ICMP in pkt:
                protocol = "ICMP"
                protocol_stats["ICMP"] += 1
            else:
                protocol_stats["Boshqa"] += 1

            if pkt.haslayer(Raw):
                try:
                    raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                    
                    if is_mostly_printable(raw_data):
                        # Sniff HTTP Basic Auth or Form Logins
                        cred_match = re.search(r'(?i)(?:username|login|password|pwd)\s*[:=]\s*([a-zA-Z0-9_@.-]{3,20})', raw_data)
                        if cred_match:
                            stolen_credentials.append({
                                "src": src_ip,
                                "dst": dst_ip,
                                "protocol": protocol,
                                "value": cred_match.group(1)
                            })
                            
                        # Capture Shell Output
                        text_lower = raw_data.lower()
                        shell_prompts = ['c:\\windows', 'root@', '/bin/bash', 'bash-', 'ps c:\\']
                        if any(prompt in text_lower for prompt in shell_prompts) or 'whoami' in text_lower or 'ipconfig' in text_lower:
                            shell_history.append({
                                "src": src_ip,
                                "dst": dst_ip,
                                "time": pkt.time,
                                "content": raw_data[:200]
                            })
                except:
                    pass

            # Threat Intelligence Check
            if src_ip in THREAT_IPS or dst_ip in THREAT_IPS:
                warnings.append({
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocol": protocol,
                    "reason": f"[SOC-THREAT] Qora Ro'yxatdagi IP aniqlandi: {src_ip if src_ip in THREAT_IPS else dst_ip}"
                })

            # Collect connection times for beaconing analysis
            conn_key = tuple(sorted([src_ip, dst_ip]))
            connection_times[conn_key].append(pkt.time)

            # C2 Detection
            suspect_warnings = is_suspect(pkt)
            is_warning = suspect_warnings is not None
            
            if is_warning:
                malicious_packets.append(pkt)
                nodes[src_ip]["color"] = "#ff5c5c"
                nodes[dst_ip]["color"] = "#ff5c5c"
                nodes[src_ip]["is_warning"] = True
                nodes[dst_ip]["is_warning"] = True
                
                for w_reason in suspect_warnings:
                    nodes[src_ip]["details"]["threat_info"].add(w_reason)
                    nodes[dst_ip]["details"]["threat_info"].add(w_reason)
                    warnings.append({
                        "src": src_ip,
                        "dst": dst_ip,
                        "protocol": protocol,
                        "reason": w_reason
                    })

            # Edges
            edge_id = f"{src_ip}-{dst_ip}-{protocol}"
            if edge_id not in edges:
                edges[edge_id] = {
                    "id": edge_id, "from": src_ip, "to": dst_ip, "label": f"{protocol}\n{port_info}",
                    "color": {"color": "#ff0000"} if is_warning else {"color": "rgba(79, 172, 254, 0.4)"},
                    "value": 1, "is_warning": is_warning
                }
            else:
                edges[edge_id]["value"] += 1
                if is_warning:
                     edges[edge_id]["color"] = {"color": "#ff0000"}
                     edges[edge_id]["is_warning"] = True

    # Finalize nodes
    for ip, node in nodes.items():
        if ip in dns_map:
            node["details"]["domains"].add(dns_map[ip])
        node["details"]["ports_used"] = list(node["details"]["ports_used"])
        node["details"]["domains"] = list(node["details"]["domains"])
        node["details"]["http_requests"] = list(set(node["details"]["http_requests"]))
        node["details"]["threat_info"] = list(node["details"]["threat_info"])

    # Format time series
    sorted_times = sorted(time_series.keys())
    if len(sorted_times) > 0:
        start_time = sorted_times[0]
        chart_data = {
            "labels": [str(int(t - start_time)) + "s" for t in sorted_times],
            "data": [time_series[t] for t in sorted_times]
        }
    else:
        chart_data = {"labels": [], "data": []}

    # Calculate Top 5 Talkers
    top_nodes = sorted(nodes.values(), key=lambda x: x["details"]["total_bytes"], reverse=True)[:5]
    top_ips = {
        "labels": [n["id"] for n in top_nodes],
        "data": [n["details"]["total_bytes"] for n in top_nodes]
    }

    graph_data = {
        "nodes": list(nodes.values()),
        "edges": list(edges.values())
    }
    
    # Detect Beaconing (Time Delta Analysis)
    for (ip1, ip2), times in connection_times.items():
        if len(times) > 5:  # Need minimum packets to establish a pattern
            float_times = sorted([float(t) for t in times])
            deltas = [float_times[i] - float_times[i-1] for i in range(1, len(float_times))]
            avg_delta = float(np.mean(deltas))
            std_dev = float(np.std(deltas))
            
            # If standard deviation is very low, it means exact repeating intervals (Beacon)
            if std_dev < 0.5 and avg_delta > 1.0: 
                warnings.append({
                    "src": ip1,
                    "dst": ip2,
                    "protocol": "BEACON",
                    "reason": f"[T1132] XAVFLI BEACONING: har {avg_delta:.2f} soniyada (std: {std_dev:.2f})"
                })

    dashboards = {
        "protocol_stats": dict(protocol_stats),
        "top_ips": top_ips,
        "shell_history": shell_history
    }
    
    unique_warnings = []
    seen_warnings = set()
    for w in warnings:
        if isinstance(w, str):
            continue
        # Deduplicate based on reason, src, and dst to avoid spam
        sig = f"{w.get('src', '')}-{w.get('dst', '')}-{w.get('reason', '')}"
        if sig not in seen_warnings:
            seen_warnings.add(sig)
            unique_warnings.append(w)
    
    return graph_data, unique_warnings, chart_data, stolen_credentials, dashboards, malicious_packets

def parse_pcap(filepath):
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        raise Exception(f"PCAP o'qishda xatolik: {str(e)}")
        
    graph_data, warnings, chart_data, stolen_credentials, dashboards, malicious_packets = parse_packet_list(packets)
    
    # Write malicious packets if any
    if len(malicious_packets) > 0:
        dir_name = os.path.dirname(filepath) if os.path.dirname(filepath) else 'uploads'
        os.makedirs(dir_name, exist_ok=True)
        malicious_pcap_path = os.path.join(dir_name, 'malicious.pcap')
        wrpcap(malicious_pcap_path, malicious_packets)
        
    return graph_data, warnings, chart_data, stolen_credentials, dashboards

def parse_log(filepath):
    nodes = {}
    edges = {}
    warnings = []
    stolen_credentials = []
    dashboards = {
        "protocol_stats": {"Boshqa (Log)": 0},
        "top_ips": {"labels": [], "data": []},
        "shell_history": []
    }
    chart_data = {"labels": [], "data": []}
    
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    threat_keywords = ['failed', 'error', 'unauthorized', 'denied', 'attack', 'malicious', 'blocked', 'warning', 'critical']
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_idx, line in enumerate(f):
                ips = ip_pattern.findall(line)
                if len(ips) >= 1:
                    src_ip = ips[0]
                    dst_ip = ips[1] if len(ips) > 1 else ips[0]
                    
                    for ip in [src_ip, dst_ip]:
                        if ip not in nodes:
                            nodes[ip] = {
                                "id": ip, "label": ip, "color": "#4facfe", "is_warning": False,
                                "details": {"packet_count": 0, "total_bytes": 0, "ports_used": [], "http_requests": [], "domains": [], "threat_info": set()}
                            }
                    
                    nodes[src_ip]["details"]["packet_count"] += 1
                    nodes[dst_ip]["details"]["packet_count"] += 1
                    dashboards["protocol_stats"]["Boshqa (Log)"] += 1
                    
                    is_warning = False
                    line_lower = line.lower()
                    if any(kw in line_lower for kw in threat_keywords) or src_ip in THREAT_IPS or dst_ip in THREAT_IPS:
                        is_warning = True
                        nodes[src_ip]["color"] = "#ff5c5c"
                        nodes[dst_ip]["color"] = "#ff5c5c"
                        nodes[src_ip]["is_warning"] = True
                        nodes[dst_ip]["is_warning"] = True
                        reason = f"[LOG] Shubhali qator: {line[:80].strip()}..."
                        nodes[src_ip]["details"]["threat_info"].add(reason)
                        nodes[dst_ip]["details"]["threat_info"].add(reason)
                        warnings.append({
                            "src": src_ip,
                            "dst": dst_ip,
                            "protocol": "LOG",
                            "reason": reason
                        })
                    
                    edge_id = f"{src_ip}-{dst_ip}-LOG"
                    if edge_id not in edges:
                        edges[edge_id] = {
                            "id": edge_id, "from": src_ip, "to": dst_ip, "label": "LOG",
                            "color": {"color": "#ff0000"} if is_warning else {"color": "rgba(79, 172, 254, 0.4)"},
                            "value": 1, "is_warning": is_warning
                        }
                    else:
                        edges[edge_id]["value"] += 1
                        if is_warning:
                             edges[edge_id]["color"] = {"color": "#ff0000"}
                             edges[edge_id]["is_warning"] = True
    except Exception as e:
        raise Exception(f"Log o'qishda xatolik: {str(e)}")
        
    top_nodes = sorted(nodes.values(), key=lambda x: x["details"]["packet_count"], reverse=True)[:5]
    dashboards["top_ips"] = {
        "labels": [n["id"] for n in top_nodes],
        "data": [n["details"]["packet_count"] for n in top_nodes]
    }
    
    for node in nodes.values():
        node["details"]["threat_info"] = list(node["details"]["threat_info"])

    graph_data = {
        "nodes": list(nodes.values()),
        "edges": list(edges.values())
    }
    
    unique_warnings = []
    seen = set()
    for w in warnings:
        if w["reason"] not in seen:
            seen.add(w["reason"])
            unique_warnings.append(w)
            
    return graph_data, unique_warnings[:50], chart_data, stolen_credentials, dashboards
