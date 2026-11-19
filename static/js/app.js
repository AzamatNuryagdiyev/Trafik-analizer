document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('uploadForm');
    const pcapFile = document.getElementById('pcapFile');
    const fileName = document.getElementById('fileName');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loader = document.getElementById('loader');
    const dashboard = document.getElementById('dashboard');
    const networkGraph = document.getElementById('networkGraph');
    const startLiveBtn = document.getElementById('startLiveBtn');
    const stopLiveBtn = document.getElementById('stopLiveBtn');
    
    // Stats elements
    const nodeCount = document.getElementById('nodeCount');
    const edgeCount = document.getElementById('edgeCount');
    const demoBtn = document.getElementById('demoBtn');
    const filtersSection = document.getElementById('filtersSection');
    const filterRadios = document.getElementsByName('trafficFilter');

    // Modal elements
    const nodeModal = document.getElementById('nodeModal');
    const closeModal = document.getElementById('closeModal');
    const blockIpBtn = document.getElementById('blockIpBtn');
    const unblockIpBtn = document.getElementById('unblockIpBtn');
    const modalIpTitle = document.getElementById('modalIpTitle');
    const modalDomains = document.getElementById('modalDomains');
    const modalPorts = document.getElementById('modalPorts');
    const modalTraffic = document.getElementById('modalTraffic');
    const modalGeo = document.getElementById('modalGeo');
    const modalHttp = document.getElementById('modalHttp');
    const modalThreatsGroup = document.getElementById('modalThreatsGroup');
    const modalThreats = document.getElementById('modalThreats');
    const vtBtn = document.getElementById('vtBtn');
    const blockedIpsSection = document.getElementById('blockedIpsSection');
    const blockedIpsList = document.getElementById('blockedIpsList');

    // New UI Elements
    const downloadMaliciousBtn = document.getElementById('downloadMaliciousBtn');
    const credentialsSection = document.getElementById('credentialsSection');
    const credentialsList = document.getElementById('credentialsList');
    const chartContainer = document.getElementById('chartContainer');
    const splunkDashboards = document.getElementById('splunkDashboards');
    const shellReplaySection = document.getElementById('shellReplaySection');
    const terminalBox = document.getElementById('terminalBox');
    const mapSection = document.getElementById('mapSection');
    const fullscreenMapBtn = document.getElementById('fullscreenMapBtn');
    
    const ctx = document.getElementById('timeSeriesChart').getContext('2d');
    const ctxPie = document.getElementById('protocolPieChart').getContext('2d');
    const ctxBar = document.getElementById('topIpsBarChart').getContext('2d');
    
    let timeChart = null;
    let pieChart = null;
    let barChart = null;

    let network = null;
    let globalGraphData = null; // Store for filtering
    let liveInterval = null;
    
    let leafletMap = null;
    let mapMarkers = [];
    let mapLines = [];

    let currentSelectedIp = null;
    let currentBlockedIps = [];

    if (fullscreenMapBtn) {
        fullscreenMapBtn.addEventListener('click', () => {
            const mapDiv = document.getElementById('mapSection');
            mapDiv.classList.toggle('map-fullscreen');
            if (mapDiv.classList.contains('map-fullscreen')) {
                fullscreenMapBtn.innerHTML = '<i class="fas fa-compress"></i> Kichraytirish';
                document.body.style.overflow = 'hidden';
            } else {
                fullscreenMapBtn.innerHTML = '<i class="fas fa-expand"></i> Katta Ekranga O\'tish';
                document.body.style.overflow = '';
            }
            if (leafletMap) {
                setTimeout(() => leafletMap.invalidateSize(), 300);
            }
        });
    }

    closeModal.addEventListener('click', () => {
        nodeModal.classList.add('hidden');
        currentSelectedIp = null;
    });

    blockIpBtn.addEventListener('click', async () => {
        if (!currentSelectedIp) return;
        if (!confirm(`Siz rostan ham ${currentSelectedIp} manzilini Windows Firewall orqali bloklamoqchimisiz?`)) return;
        
        try {
            const res = await fetch('/block_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: currentSelectedIp })
            });
            const data = await res.json();
            if (data.error) {
                alert(data.error);
            } else {
                alert(data.message);
                currentBlockedIps = data.blocked_ips;
                updateBlockedUI();
                updateModalButtons();
            }
        } catch (e) {
            alert('Bloklash xatosi: ' + e.message);
        }
    });

    unblockIpBtn.addEventListener('click', async () => {
        if (!currentSelectedIp) return;
        
        try {
            const res = await fetch('/unblock_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: currentSelectedIp })
            });
            const data = await res.json();
            if (data.error) {
                alert(data.error);
            } else {
                alert(data.message);
                currentBlockedIps = data.blocked_ips;
                updateBlockedUI();
                updateModalButtons();
            }
        } catch (e) {
            alert('Blokdan yechish xatosi: ' + e.message);
        }
    });

    // Close on background click
    nodeModal.addEventListener('click', (e) => {
        if (e.target === nodeModal) {
            nodeModal.classList.add('hidden');
        }
    });

    pcapFile.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            fileName.textContent = e.target.files[0].name;
        } else {
            fileName.textContent = 'Fayl yo\'q';
        }
    });

    demoBtn.addEventListener('click', async () => {
        loader.classList.remove('hidden');
        dashboard.classList.add('hidden');
        analyzeBtn.disabled = true;
        demoBtn.disabled = true;

        try {
            const response = await fetch('/test_example');
            const result = await response.json();
            
            globalGraphData = result;
            renderDashboard(result);
        } catch (error) {
            alert('Error loading demo: ' + error.message);
        } finally {
            loader.classList.add('hidden');
            analyzeBtn.disabled = false;
            demoBtn.disabled = false;
        }
    });

    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        if (!pcapFile.files.length) return;

        const formData = new FormData();
        formData.append('file', pcapFile.files[0]);

        loader.classList.remove('hidden');
        dashboard.classList.add('hidden');
        analyzeBtn.disabled = true;

        try {
            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });

            let result;
            try {
                result = await response.json();
            } catch (jsonErr) {
                const text = await response.text();
                throw new Error("Server noto'g'ri javob qaytardi (Katta fayl bo'lishi mumkin): " + text.substring(0, 100));
            }

            if (!response.ok) {
                throw new Error(result.error || 'Server error occurred.');
            }

            globalGraphData = result;
            renderDashboard(result);
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            loader.classList.add('hidden');
            analyzeBtn.disabled = false;
        }
    });

    startLiveBtn.addEventListener('click', async () => {
        try {
            const res = await fetch('/start_live', { method: 'POST' });
            const data = await res.json();
            if (data.error) {
                alert(data.error);
                return;
            }
            startLiveBtn.classList.add('hidden');
            stopLiveBtn.classList.remove('hidden');
            analyzeBtn.disabled = true;
            demoBtn.disabled = true;
            
            // Start polling
            liveInterval = setInterval(fetchLiveData, 2000);
        } catch (e) {
            alert('Live error: ' + e.message);
        }
    });

    stopLiveBtn.addEventListener('click', async () => {
        try {
            await fetch('/stop_live', { method: 'POST' });
            clearInterval(liveInterval);
            stopLiveBtn.classList.add('hidden');
            startLiveBtn.classList.remove('hidden');
            analyzeBtn.disabled = false;
            demoBtn.disabled = false;
        } catch (e) {}
    });

    async function fetchLiveData() {
        try {
            const res = await fetch('/get_live_data');
            const result = await res.json();
            if (result.success && result.graph.nodes.length > 0) {
                globalGraphData = result;
                renderDashboard(result);
            }
        } catch (e) {}
    }

    function renderDashboard(result) {
        dashboard.classList.remove('hidden');

        const graphData = result.graph;
        const warnings = result.warnings;
        const credentials = result.credentials;
        const chartData = result.chart_data;
        const dashboardsData = result.dashboards;
        
        if (result.blocked_ips) {
            currentBlockedIps = result.blocked_ips;
            updateBlockedUI();
        }

        nodeCount.textContent = graphData.nodes.length;
        edgeCount.textContent = graphData.edges.length;
        
        filtersSection.classList.remove('hidden');

        const warningsList = document.getElementById('warningsList');
        const verdictBanner = document.getElementById('verdictBanner');

        warningsList.innerHTML = '';
        if (warnings && warnings.length > 0) {
            
            verdictBanner.className = 'verdict-banner verdict-danger';
            verdictBanner.innerHTML = '🚨 XAVFLI TRAFIK: Virus yoki C2 botnet aloqasi topildi!';
            downloadMaliciousBtn.classList.remove('hidden');
            
            warnings.forEach(w => {
                const li = document.createElement('li');
                li.className = 'warning-item';
                li.innerHTML = `
                    <strong>⚠️ ${w.reason}</strong>
                    <span>${w.src} ➡️ ${w.dst} (${w.protocol})</span>
                `;
                warningsList.appendChild(li);
            });
        } else {
            verdictBanner.className = 'verdict-banner verdict-safe';
            verdictBanner.innerHTML = '✅ XAVFSIZ: Shubhali trafik va zararli fayllar topilmadi.';
            downloadMaliciousBtn.classList.add('hidden');
            
            const li = document.createElement('li');
            li.style.color = 'var(--success)';
            li.textContent = '✅ Hech qanday muammo topilmadi.';
            warningsList.appendChild(li);
        }

        // Render Credentials
        credentialsList.innerHTML = '';
        if (credentials && credentials.length > 0) {
            credentialsSection.classList.remove('hidden');
            credentials.forEach(c => {
                const li = document.createElement('li');
                li.className = 'warning-item';
                li.style.borderColor = 'var(--warning)';
                li.innerHTML = `
                    <strong style="color: var(--warning)">🔑 Topilgan parol: ${c.value}</strong>
                    <span>${c.src} ➡️ ${c.dst} (${c.protocol})</span>
                `;
                credentialsList.appendChild(li);
            });
        } else {
            credentialsSection.classList.add('hidden');
        }

        // Render Chart
        if (chartData && chartData.labels.length > 0) {
            chartContainer.classList.remove('hidden');
            renderChart(chartData);
        }
        
        // Render Dashboards
        if (dashboardsData) {
            splunkDashboards.classList.remove('hidden');
            renderDashboards(dashboardsData);
        }
        
        // Draw GeoIP Map
        renderGeoMap(graphData);
    }

    // Filter Logic
    for (const radio of filterRadios) {
        radio.addEventListener('change', drawFilteredGraph);
    }

    function drawFilteredGraph() {
        if (!globalGraphData) return;
        
        const filterValue = document.querySelector('input[name="trafficFilter"]:checked').value;
        let graphData = globalGraphData.graph;

        if (filterValue === 'threats') {
            const filteredEdges = graphData.edges.filter(e => e.is_warning);
            const warningNodeIds = new Set();
            filteredEdges.forEach(e => {
                warningNodeIds.add(e.from);
                warningNodeIds.add(e.to);
            });
            const filteredNodes = graphData.nodes.filter(n => n.is_warning || warningNodeIds.has(n.id));
            
            graphData = { nodes: filteredNodes, edges: filteredEdges };
        }

        renderGeoMap(graphData);
    }

    function renderChart(chartData) {
        if (timeChart) {
            timeChart.destroy();
        }

        timeChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: chartData.labels,
                datasets: [{
                    label: 'Paketlar Soni',
                    data: chartData.data,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.2)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    pointHitRadius: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#f8fafc' }
                    }
                },
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                }
            }
        });
    }

    function renderDashboards(dashboardsData) {
        if (pieChart) pieChart.destroy();
        if (barChart) barChart.destroy();

        // 1. Protocol Pie Chart
        const protocols = Object.keys(dashboardsData.protocol_stats);
        const protocolCounts = Object.values(dashboardsData.protocol_stats);
        
        pieChart = new Chart(ctxPie, {
            type: 'doughnut',
            data: {
                labels: protocols,
                datasets: [{
                    data: protocolCounts,
                    backgroundColor: ['#4facfe', '#ff5c5c', '#fbbf24', '#34d399', '#a78bfa'],
                    borderWidth: 1,
                    borderColor: '#1e293b'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'right', labels: { color: '#f8fafc' } } }
            }
        });

        // 2. Top IPs Bar Chart
        barChart = new Chart(ctxBar, {
            type: 'bar',
            data: {
                labels: dashboardsData.top_ips.labels,
                datasets: [{
                    label: 'Uzatilgan baytlar',
                    data: dashboardsData.top_ips.data,
                    backgroundColor: 'rgba(79, 172, 254, 0.7)',
                    borderColor: '#4facfe',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { display: false } },
                    y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                }
            }
        });
        
        // 3. Shell Replay rendering
        if (dashboardsData.shell_history && dashboardsData.shell_history.length > 0) {
            shellReplaySection.classList.remove('hidden');
            terminalBox.innerHTML = ''; // clear old
            
            dashboardsData.shell_history.forEach(hist => {
                const p = document.createElement('p');
                const timeStr = new Date(hist.time * 1000).toLocaleTimeString();
                
                p.innerHTML = `<span class="terminal-time">[${timeStr}]</span> <span class="terminal-ip">${hist.src} -> ${hist.dst}</span><br> ${hist.content.replace(/</g, '&lt;').replace(/>/g, '&gt;')}`;
                terminalBox.appendChild(p);
            });
            // auto scroll to bottom
            terminalBox.scrollTop = terminalBox.scrollHeight;
        } else {
            shellReplaySection.classList.add('hidden');
        }
    }
    
    // ======== GEO IP MAP LOGIC ========
    async function renderGeoMap(graphData) {
        if (!leafletMap) {
            leafletMap = L.map('worldMap', {
                center: [20, 0],
                zoom: 2,
                zoomControl: true
            });
            // CartoDB Dark Matter tile layer for dark theme
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
                subdomains: 'abcd',
                maxZoom: 20
            }).addTo(leafletMap);
        }
        
        mapSection.classList.remove('hidden');
        setTimeout(() => leafletMap.invalidateSize(), 500); // Fix map render issue

        // Clear previous markers
        mapMarkers.forEach(m => leafletMap.removeLayer(m));
        mapLines.forEach(l => leafletMap.removeLayer(l));
        mapMarkers = [];
        mapLines = [];
        
        const publicNodes = graphData.nodes.filter(n => {
            const ip = n.id;
            return !(ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '127.0.0.1');
        });
        
        if (publicNodes.length === 0) return;
        
        // Batch Fetch limits to 100 per request
        const nodeChunks = [];
        for (let i = 0; i < publicNodes.length; i += 100) {
            nodeChunks.push(publicNodes.slice(i, i + 100));
        }
        
        const geoDict = {}; // ip -> {lat, lon}
        
        // Define a "Home" location for local IPs (e.g., Tashkent)
        const homeLat = 41.2995;
        const homeLon = 69.2401;

        // Assign home location to local networks so lines can connect to them
        graphData.nodes.forEach(n => {
            const ip = n.id;
            if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '127.0.0.1') {
                const jLat = (Math.random() - 0.5) * 0.05;
                const jLon = (Math.random() - 0.5) * 0.05;
                geoDict[ip] = { lat: homeLat + jLat, lon: homeLon + jLon, country: 'Lokal Tarmoq (Sizning Server)' };
            }
        });
        
        for (const chunk of nodeChunks) {
            const ips = chunk.map(n => n.id);
            try {
                const res = await fetch('http://ip-api.com/batch', {
                    method: 'POST',
                    body: JSON.stringify(ips)
                });
                const data = await res.json();
                data.forEach(d => {
                    if (d.status === 'success') {
                        // Katta trafikni bitta nuqtaga tushib qolmasligi uchun "Jitter" (tarqoqlik) qoshamiz
                        const jLat = (Math.random() - 0.5) * 1.5; 
                        const jLon = (Math.random() - 0.5) * 1.5;
                        geoDict[d.query] = { lat: d.lat + jLat, lon: d.lon + jLon, country: d.country };
                    }
                });
            } catch(e) { console.error("GeoIP Fetch error", e); }
        }
        
        // Draw Nodes
        graphData.nodes.forEach(n => {
            if (geoDict[n.id]) {
                const geo = geoDict[n.id];
                const color = n.color === '#ff5c5c' ? '#ff0000' : '#4facfe';
                const circle = L.circleMarker([geo.lat, geo.lon], {
                    radius: n.color === '#ff5c5c' ? 22 : 14, // Tugunlarni ancha kattalashtirdik
                    fillColor: color,
                    color: '#ffffff', // Oq hoshiya (Yorqinroq ko'rinishi uchun)
                    weight: 3, // Hoshiya qalinligi
                    opacity: 1,
                    fillOpacity: 0.9
                }).addTo(leafletMap);
                
                // Faqat sichqoncha borganda kichik ma'lumot chiqadi (Hover)
                circle.bindTooltip(`<b>${n.id}</b><br>${geo.country}<br><small>(Katta oynani ochish uchun bosing)</small>`, { direction: 'top', className: 'custom-tooltip' });
                
                // Bosilganda yoki ikki marta bosilganda katta Modal oyna ochiladi
                circle.on('click', () => {
                    showNodeDetails(n);
                });
                circle.on('dblclick', () => {
                    showNodeDetails(n);
                });
                
                mapMarkers.push(circle);
            }
        });
        
        // Draw Edges (Attacks)
        graphData.edges.forEach(e => {
            const geo1 = geoDict[e.from];
            const geo2 = geoDict[e.to];
            if (geo1 && geo2) {
                const isWarning = e.is_warning;
                const color = isWarning ? '#ff0000' : 'rgba(79, 172, 254, 0.6)';
                
                // Qalinlashtirilgan tekis chiziqlar
                const line = L.polyline([[geo1.lat, geo1.lon], [geo2.lat, geo2.lon]], {
                    weight: isWarning ? 6 : 3, // Chiziqlar ancha qalinlashtirildi
                    color: color,
                    opacity: isWarning ? 0.9 : 0.5
                }).addTo(leafletMap);
                
                mapLines.push(line);
            }
        });
    }

    async function showNodeDetails(node) {
        modalIpTitle.textContent = "IP: " + node.id;
        
        // Domains
        modalDomains.textContent = node.details.domains.length > 0 ? node.details.domains.join(', ') : 'Topilmadi';
        
        // Threats Info
        if (node.details.threat_info && node.details.threat_info.length > 0) {
            modalThreatsGroup.style.display = 'block';
            modalThreats.innerHTML = node.details.threat_info.map(t => `<div>• ${t}</div>`).join('');
        } else {
            modalThreatsGroup.style.display = 'none';
            modalThreats.innerHTML = '-';
        }

        // Ports
        modalPorts.textContent = node.details.ports_used.length > 0 ? node.details.ports_used.join(', ') : 'Noma\'lum';
        
        // Traffic
        const kb = (node.details.total_bytes / 1024).toFixed(2);
        modalTraffic.textContent = `${node.details.packet_count} paket / ${kb} KB`;
        
        // HTTP 
        if (node.details.http_requests.length > 0) {
            modalHttp.innerHTML = node.details.http_requests.map(r => `<div>${r}</div>`).join('');
        } else {
            modalHttp.innerHTML = 'Yo\'q';
        }

        currentSelectedIp = node.id;
        updateModalButtons();
        
        // VT Button Update
        vtBtn.href = `https://www.virustotal.com/gui/search/${node.id}`;

        // Fetch GeoIP
        modalGeo.textContent = "Yuklanmoqda...";
        nodeModal.classList.remove('hidden');

        try {
            // Internal IPs often fail or return private
            if (node.id.startsWith('192.168.') || node.id.startsWith('10.') || node.id.startsWith('172.')) {
                modalGeo.textContent = "Lokal Tarmoq (Private IP)";
                return;
            }
            
            const response = await fetch(`http://ip-api.com/json/${node.id}`);
            const data = await response.json();
            if (data.status === 'success') {
                modalGeo.textContent = `${data.country}, ${data.city} (${data.isp})`;
            } else {
                modalGeo.textContent = "Aniqlab bo'lmadi";
            }
        } catch (e) {
            modalGeo.textContent = "Ulanish xatosi";
        }
    }

    function updateBlockedUI() {
        if (currentBlockedIps.length > 0) {
            blockedIpsSection.classList.remove('hidden');
            blockedIpsList.innerHTML = currentBlockedIps.map(ip => `<li>🔴 ${ip}</li>`).join('');
        } else {
            blockedIpsSection.classList.add('hidden');
            blockedIpsList.innerHTML = '';
        }
    }

    function updateModalButtons() {
        if (currentSelectedIp && currentBlockedIps.includes(currentSelectedIp)) {
            blockIpBtn.classList.add('hidden');
            unblockIpBtn.classList.remove('hidden');
        } else {
            blockIpBtn.classList.remove('hidden');
            unblockIpBtn.classList.add('hidden');
        }
    }
});
