
    let attackCount = 0, sshCount = 0, httpCount = 0, lastPayload = "", lastIp = null;
    const attackCountEl = document.getElementById('attack-count');
    const terminalEl = document.getElementById('terminal');
    const aiOutput = document.getElementById('ai-response');
    const wsStatus = document.getElementById('ws-status');

    // --- CHART.JS INIT ---
    const ctx = document.getElementById('protocolChart').getContext('2d');
    const protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: { labels: ['SSH / TCP', 'HTTP'], datasets: [{ data: [0, 0], backgroundColor: ['#00f3ff', '#ff0055'] }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#d0e1f9', font: { size: 9 } } } } }
    });

    // --- THREE.JS GLOBE INIT ---
    const container = document.getElementById('canvas-container');
    let renderer, scene, camera, Globe;

    function initGlobe() {
        try {
            scene = new THREE.Scene();
            camera = new THREE.PerspectiveCamera(45, container.clientWidth / container.clientHeight, 1, 2000);
            camera.position.z = 300;

            renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
            renderer.setSize(container.clientWidth, container.clientHeight);
            container.appendChild(renderer.domElement);

            if (typeof ThreeGlobe !== 'undefined') {
                Globe = new ThreeGlobe()
                    .globeImageUrl('https://unpkg.com/three-globe@2.30.0/example/img/earth-night.jpg')
                    .bumpImageUrl('https://unpkg.com/three-globe@2.30.0/example/img/earth-topology.png')
                    .arcColor(() => '#ff0055')
                    .arcAltitude(0.35)
                    .arcStroke(2.0)
                    .ringsData([])
                    .ringColor(() => '#00f3ff');
                scene.add(Globe);
            } else {
                // Fallback Wireframe Sphere
                const geometry = new THREE.SphereGeometry(100, 24, 24);
                const material = new THREE.MeshBasicMaterial({ color: 0x00f3ff, wireframe: true });
                Globe = new THREE.Mesh(geometry, material);
                scene.add(Globe);
            }

            scene.add(new THREE.AmbientLight(0xcccccc, 1.5));

            (function animate() {
                if(Globe) Globe.rotation.y += 0.002;
                renderer.render(scene, camera);
                requestAnimationFrame(animate);
            })();
        } catch(e) {
            console.error("Globe hatasi:", e);
            container.innerHTML = '<div style="color:var(--neon-blue); padding:40px; text-align:center;">[3D VIEW UNAVAILABLE — see browser console]</div>';
        }
    }
    initGlobe();

    // --- WEBSOCKET CONNECTION (8082 PORTına Bagli) ---
    function connectWebSocket() {
        const socket = new SockJS('/ws-honeygrid');
        const stompClient = Stomp.over(socket);
        stompClient.debug = null;

        stompClient.connect({}, function () {
            wsStatus.innerText = "ONLINE";
            wsStatus.style.color = "var(--neon-green)";
            appendLog("[WEBSOCKET CONNECTED] Listening live stream...", "var(--neon-green)");

            stompClient.subscribe('/topic/attacks', function (msg) {
                triggerAttack(JSON.parse(msg.body));
            });
        }, function(err) {
            wsStatus.innerText = "OFFLINE";
            wsStatus.style.color = "var(--neon-red)";
            appendLog("[WEBSOCKET ERROR] Connection failed. Retrying...", "var(--neon-red)");
            setTimeout(connectWebSocket, 3000);
        });
    }
    connectWebSocket();

    function triggerAttack(attack) {
        attackCount++;
        attackCountEl.innerText = String(attackCount).padStart(4, '0');
        lastPayload = attack.payload || "N/A";
        lastIp = attack.ipAddress || "127.0.0.1";

        if ((attack.protocol || '').includes('SSH')) sshCount++; else httpCount++;
        protocolChart.data.datasets[0].data = [sshCount, httpCount];
        protocolChart.update();

        if(attack.geoLocated && Globe && Globe.arcsData) {
            Globe.arcsData([{ startLat: attack.latitude ?? 0, startLng: attack.longitude ?? 0, endLat: 41.0082, endLng: 28.9784 }]);
        }

        HoneygridView.appendEvent(document, terminalEl, attack);
    }

    function appendLog(txt, color) {
        const div = document.createElement('div');
        div.className = 'log-row';
        div.style.color = color;
        div.innerText = txt;
        terminalEl.appendChild(div);
        while (terminalEl.children.length > 300) terminalEl.firstElementChild.remove();
    }

    async function postJson(url, body) {
        const session = await fetch('/api/session/csrf');
        if (!session.ok) throw new Error('Session expired. Sign in again.');
        const csrf = await session.json();
        const response = await fetch(url, { method: 'POST', headers: {
            'Content-Type': 'application/json', [csrf.headerName]: csrf.token
        }, body: JSON.stringify(body || {}) });
        const data = await response.json();
        if (!response.ok && response.status !== 501) throw new Error('Request failed: ' + response.status);
        return data;
    }
    function askAiAnalyst() {
        if (!lastIp) { aiOutput.innerText = 'Wait for an observed event first.'; return; }
        aiOutput.innerText = "Analyzing attack payload...";
        postJson('/api/v1/soc-ai/analyze-payload', { payload: lastPayload, ip: lastIp })
            .then(data => {
                aiOutput.innerText = data.analystRecommendation || "[SOC AI] Analysis completed.";
            })
            .catch(err => {
                aiOutput.innerText = "[SOC AI ERROR] Could not analyze: " + err.message;
            });
    }

    function triggerSoarContainment() {
        if (!lastIp) { alert('Wait for an observed event first.'); return; }
        postJson('/api/v1/soc-ai/execute-containment?ip=' + encodeURIComponent(lastIp))
            .then(data => alert('SOAR: ' + data.status + '\n' + data.message))
            .catch(err => alert('SOAR Error: ' + err.message));
    }
    function downloadYara() {
        if (!lastIp) { alert('Wait for an observed event first.'); return; }
        const query = new URLSearchParams({ ip: lastIp, vuln: 'OBSERVED_PAYLOAD', payload: lastPayload });
        window.open('/api/v1/advanced-cti/yara/generate?' + query, '_blank', 'noopener');
    }
    window.addEventListener('resize', () => {
        if (!renderer || !camera) return;
        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
    });


document.getElementById('soar-button').addEventListener('click', triggerSoarContainment);
document.getElementById('yara-button').addEventListener('click', downloadYara);
document.getElementById('pdf-button').addEventListener('click', () => window.open('/api/v1/reports/download/pdf', '_blank', 'noopener'));
document.getElementById('analysis-button').addEventListener('click', askAiAnalyst);
