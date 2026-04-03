// --- Theme Management ---
const themeToggleBtn = document.getElementById('themeToggle');
const savedTheme = localStorage.getItem('theme') || 'dark';
if (savedTheme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
}

if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        if (currentTheme === 'light') {
            document.documentElement.removeAttribute('data-theme');
            localStorage.setItem('theme', 'dark');
        } else {
            document.documentElement.setAttribute('data-theme', 'light');
            localStorage.setItem('theme', 'light');
        }
    });
}

// --- API Interactions ---
const repoForm = document.getElementById('repoForm');
const codeForm = document.getElementById('codeForm');

function showScanStatus(message, isError = false) {
    const statusDiv = document.getElementById('scanStatus');
    if (!statusDiv) return;
    statusDiv.textContent = message;
    statusDiv.style.background = isError ? 'rgba(255, 82, 82, 0.1)' : 'rgba(0, 212, 255, 0.1)';
    statusDiv.style.color = isError ? 'var(--red)' : 'var(--cyan)';
    statusDiv.style.border = `1px solid ${isError ? 'var(--red)' : 'var(--cyan)'}`;
    statusDiv.classList.remove('hidden');
}

function renderResults(data) {
    document.getElementById('resultArea').classList.remove('hidden');
    document.getElementById('resFiles').textContent = data.files_scanned || 0;
    
    const vulns = data.vulnerabilities || [];
    const numVulns = vulns.length;
    document.getElementById('resVulns').textContent = numVulns;
    
    const cleanFiles = Math.max(0, (data.files_scanned || 0) - numVulns);
    document.getElementById('resClean').textContent = cleanFiles;
    
    const riskBadge = document.getElementById('resRisk');
    if (numVulns === 0) {
        riskBadge.textContent = "SAFE";
        riskBadge.style.color = "var(--green)";
        document.getElementById('cleanState').classList.remove('hidden');
        document.getElementById('vulnList').classList.add('hidden');
    } else {
        riskBadge.textContent = numVulns > 2 ? "HIGH" : "MEDIUM";
        riskBadge.style.color = numVulns > 2 ? "var(--red)" : "var(--amber)";
        
        document.getElementById('cleanState').classList.add('hidden');
        document.getElementById('vulnList').classList.remove('hidden');
        
        const tbody = document.getElementById('vulnTableBody');
        tbody.innerHTML = '';
        vulns.forEach(v => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding: 12px; border-bottom: 1px solid var(--border);">${v.file}</td>
                <td style="padding: 12px; border-bottom: 1px solid var(--border);"><span style="background: rgba(255,82,82,0.1); color: var(--red); padding: 2px 8px; border-radius: 4px; font-size: 0.85rem;">${v.vulnerability}</span></td>
                <td style="padding: 12px; border-bottom: 1px solid var(--border);">${(v.confidence * 100).toFixed(1)}%</td>
            `;
            tbody.appendChild(tr);
        });
    }
}

if (repoForm) {
    repoForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('repoUrl').value;
        const btn = document.getElementById('repoBtn');
        
        btn.disabled = true;
        btn.textContent = "⏳ Scanning...";
        showScanStatus("Fetching repository and running AI analysis...", false);
        
        try {
            const response = await fetch('/api/scan/repo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await response.json();
            
            if (response.ok) {
                showScanStatus("✅ Scan Complete!", false);
                renderResults(data);
            } else {
                showScanStatus(data.error || "Failed to scan repository", true);
            }
        } catch (err) {
            showScanStatus("Server connection failed.", true);
        } finally {
            btn.disabled = false;
            btn.textContent = "🔍 Scan Repository";
        }
    });
}

if (codeForm) {
    codeForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('codeSnippet').value;
        const btn = document.getElementById('codeBtn');
        
        btn.disabled = true;
        btn.textContent = "🧠 Analysing...";
        showScanStatus("Running AI vulnerability analysis...", false);
        
        try {
            const response = await fetch('/api/scan/code', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code })
            });
            const data = await response.json();
            
            if (response.ok) {
                showScanStatus("✅ Analysis Complete!", false);
                renderResults(data);
            } else {
                showScanStatus(data.error || "Failed to analyze code", true);
            }
        } catch (err) {
            showScanStatus("Server connection failed.", true);
        } finally {
            btn.disabled = false;
            btn.textContent = "🔍 Analyse Code";
        }
    });
}
