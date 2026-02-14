// Binary Transparency & Security Analyzer - Core Engine

class SecurityAnalyzer {
    constructor() {
        this.selectedFile = null;
        this.isScanning = false;
        this.apiBaseUrl = 'http://localhost:5000/api';
        this.init();
    }

    init() {
        this.initMatrix();
        this.initEventListeners();
        this.initTabs();
        this.initScrollObserver();
    }

    // --- Scroll Animations ---
    initScrollObserver() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('active');
                }
            });
        }, { threshold: 0.1 });

        document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
    }

    // --- Matrix Animation ---
    initMatrix() {
        const canvas = document.getElementById('matrix-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const chars = "01010101ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = [];

        for (let x = 0; x < columns; x++) {
            drops[x] = 1;
        }

        const draw = () => {
            ctx.fillStyle = 'rgba(15, 15, 15, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#00ff88';
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = chars.charAt(Math.floor(Math.random() * chars.length));
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        };

        setInterval(draw, 50);

        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
    }

    // --- UI Interactions ---
    initEventListeners() {
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const scanBtn = document.getElementById('scanButton');
        const removeBtn = document.getElementById('removeFile');

        if (dropZone) {
            dropZone.addEventListener('click', () => fileInput.click());
            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZone.classList.add('active');
            });
            dropZone.addEventListener('dragleave', () => dropZone.classList.remove('active'));
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('active');
                if (e.dataTransfer.files.length > 0) this.handleFileSelect(e.dataTransfer.files[0]);
            });
        }

        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) this.handleFileSelect(e.target.files[0]);
            });
        }

        if (scanBtn) {
            scanBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.executeScan();
            });
        }

        if (removeBtn) {
            removeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.resetUpload();
            });
        }
    }

    handleFileSelect(file) {
        const allowed = ['apk', 'exe', 'pdf', 'jar', 'dll', 'so', 'ipa', 'js'];
        const ext = file.name.split('.').pop().toLowerCase();

        if (!allowed.includes(ext)) {
            alert(`File type .${ext} is not supported. Please use: ${allowed.join(', ')}`);
            return;
        }

        this.selectedFile = file;
        document.querySelector('.upload-content').classList.add('hidden');
        document.getElementById('filePreview').classList.remove('hidden');
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = this.formatSize(file.size);
    }

    formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    resetUpload() {
        this.selectedFile = null;
        document.querySelector('.upload-content').classList.remove('hidden');
        document.getElementById('filePreview').classList.add('hidden');
        document.getElementById('fileInput').value = '';
    }

    // --- Scanning Engine ---
    async executeScan() {
        if (!this.selectedFile || this.isScanning) return;
        this.isScanning = true;

        // Hide upload preview, show console
        document.getElementById('filePreview').classList.add('hidden');
        const consoleEl = document.getElementById('consoleContainer');
        consoleEl.style.display = 'block';

        await this.logToConsole("Initializing Binary Analyzer...");
        await this.logToConsole(`Target: ${this.selectedFile.name}`);
        await this.logToConsole("Extracting headers and strings...");
        await this.delay(800);
        await this.logToConsole("Identifying entry points and syscalls...");
        await this.delay(500);
        await this.logToConsole("Running heuristic rule engine [YARA v4.2]...");

        try {
            const formData = new FormData();
            formData.append('file', this.selectedFile);

            const response = await fetch(`${this.apiBaseUrl}/scan/file`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Scan failed');
            }

            const data = await response.json();

            await this.logToConsole("Static analysis complete. Compiling findings...");
            await this.delay(600);
            await this.logToConsole("Generating security report...");
            await this.delay(400);

            this.showResults(data);

        } catch (error) {
            await this.logToConsole(`ERROR: ${error.message}`, 'critical');
            alert(`Scan Failed: ${error.message}`);
            this.resetUpload();
            this.isScanning = false;
        }
    }

    async logToConsole(message, type = '') {
        const lines = document.getElementById('consoleLines');
        const line = document.createElement('div');
        line.className = `console-line ${type}`;
        lines.appendChild(line);

        // Typing effect
        for (let i = 0; i < message.length; i++) {
            line.textContent += message[i];
            await this.delay(20);
        }

        // Scroll to bottom
        const container = document.getElementById('consoleContainer');
        container.scrollTop = container.scrollHeight;
    }

    delay(ms) { return new Promise(res => setTimeout(res, ms)); }

    // --- Results Display ---
    showResults(data) {
        document.getElementById('consoleContainer').style.display = 'none';
        document.getElementById('resultsSection').style.display = 'block';
        document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });

        const score = data.security_score || 0;
        this.animateScore(score);
        this.populateFindings(data);
        this.isScanning = false;
    }

    animateScore(target) {
        const circle = document.getElementById('scoreCircle');
        const value = document.getElementById('scoreValue');
        const label = document.getElementById('riskLabel');

        // Map 0-100 to offset 565-0
        const offset = 565 - (target / 100) * 565;
        circle.style.strokeDashoffset = offset;

        // Update color based on score
        let color = '#00ff88'; // Default Green (Low Risk)
        let statusText = 'SYSTEM SECURE';

        if (target > 70) {
            color = '#ff3e3e'; // Red (High Risk)
            statusText = 'CRITICAL THREATS';
        } else if (target > 30) {
            color = '#ffb800'; // Yellow (Medium Risk)
            statusText = 'SYSTEM VULNERABLE';
        }

        circle.style.stroke = color;
        label.style.color = color;
        label.textContent = statusText;

        // Counter
        let count = 0;
        const interval = setInterval(() => {
            if (count >= target) {
                count = target;
                clearInterval(interval);
            }
            value.textContent = count;
            count++;
        }, 20);
    }

    populateFindings(data) {
        const list = document.getElementById('findingsList');
        const userSummary = document.getElementById('userSummary');
        const recommendations = document.getElementById('recommendationsList');

        list.innerHTML = '';
        recommendations.innerHTML = '';

        let allFindings = [];
        if (data.findings) {
            for (let category in data.findings) {
                const categoryFindings = data.findings[category].findings || [];
                allFindings = [...allFindings, ...categoryFindings.map(f => ({ ...f, category }))];
            }
        }

        if (allFindings.length === 0) {
            list.innerHTML = '<div class="finding-card"><div class="finding-header">No threats detected. Binary appears clean.</div></div>';
            userSummary.innerHTML = "<h3>Security Status: Clear</h3><p>Our analysis found no suspicious patterns, leaks, or infrastructure exposures in this file.</p>";
        } else {
            allFindings.forEach(f => {
                const card = document.createElement('div');
                card.className = 'finding-card';

                const sevClass = `sev-${(f.severity || 'low').toLowerCase()}`;

                card.innerHTML = `
                    <div class="finding-header">
                        <span class="mono">${f.type || f.category}</span>
                        <span class="severity-badge ${sevClass}">${f.severity || 'LOW'}</span>
                    </div>
                    <div class="finding-body">
                        <p>${f.description || f.value || 'No detailed description available.'}</p>
                        <div style="margin-top:10px; font-size:0.7rem; color:var(--secondary);">[ SECTION: ${f.section || 'GLOBAL'} ]</div>
                    </div>
                `;

                card.querySelector('.finding-header').addEventListener('click', () => {
                    card.querySelector('.finding-body').classList.toggle('expanded');
                });

                list.appendChild(card);
            });

            // Populate User View
            userSummary.innerHTML = `
                <h3>Analysis Summary</h3>
                <p>We detected ${allFindings.length} security concern(s). This file may contain sensitive information exposure or insecure patterns.</p>
                <div class="mt-40 mono" style="color:var(--secondary); border-left:2px solid var(--secondary); padding-left:15px;">
                    Risk Factors: ${[...new Set(allFindings.map(f => f.type))].join(', ')}
                </div>
            `;

            (data.recommendations || []).forEach(rec => {
                const recEl = document.createElement('div');
                recEl.className = 'finding-card';
                recEl.innerHTML = `
                    <div class="finding-header">
                        <span class="mono">💡 RECOMMENDATION</span>
                    </div>
                    <div class="finding-body expanded">
                        <p>${rec}</p>
                    </div>
                `;
                recommendations.appendChild(recEl);
            });
        }
    }

    initTabs() {
        const buttons = document.querySelectorAll('.tab-btn');
        const devContent = document.getElementById('developerContent');
        const userContent = document.getElementById('userContent');

        buttons.forEach(btn => {
            btn.addEventListener('click', () => {
                buttons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                const view = btn.dataset.view;
                if (view === 'developer') {
                    devContent.classList.remove('hidden');
                    userContent.classList.add('hidden');
                } else {
                    devContent.classList.add('hidden');
                    userContent.classList.remove('hidden');
                }
            });
        });
    }
}

// Initialize on Load
document.addEventListener('DOMContentLoaded', () => {
    new SecurityAnalyzer();
});
