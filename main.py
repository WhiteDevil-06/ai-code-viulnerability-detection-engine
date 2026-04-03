import os
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

# Lazy load models so server boots instantly
scanner = None
engine_ready = False

def get_scanner():
    global scanner, engine_ready
    if scanner is None:
        try:
            from github_scanner import GitHubScanner
            print("[*] Init AI Engine in background...")
            scanner = GitHubScanner()
            engine_ready = True
        except Exception as e:
            print(f"Warning: AI Engine could not be loaded. {e}")
            engine_ready = False
    return scanner

load_dotenv()

# We set template_folder to target our templates directory
app = Flask(__name__, template_folder='templates', static_folder='static')

# --- Pages Routing ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# --- API Endpoints ---
@app.route('/api/status', methods=['GET'])
def get_status():
    get_scanner()
    return jsonify({"engine_ready": engine_ready})

@app.route('/api/scan/code', methods=['POST'])
def scan_code():
    s = get_scanner()
    if not engine_ready or s is None:
        return jsonify({"error": "AI Engine is offline"}), 503
        
    data = request.get_json()
    code_snippet = data.get('code', '')
    
    if not code_snippet:
        return jsonify({"error": "No code provided"}), 400
        
    try:
        vuln_type, confidence = s.engine.scan_code_snippet(code_snippet)
        vulns = []
        if vuln_type != "Safe Code":
            vulns.append({
                "file": "pasted_snippet.py", 
                "vulnerability": vuln_type, 
                "confidence": confidence
            })
            
        return jsonify({
            "target": "Pasted Code",
            "files_scanned": 1,
            "vulnerabilities": vulns
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/repo', methods=['POST'])
def scan_repo():
    s = get_scanner()
    if not engine_ready or s is None:
        return jsonify({"error": "AI Engine is offline"}), 503
        
    data = request.get_json()
    repo_url = data.get('url', '')
    
    if not repo_url or not repo_url.startswith('https://github.com/'):
        return jsonify({"error": "Invalid GitHub URL format"}), 400
        
    try:
        # get_scan_results is the method from github_scanner
        result = s.get_scan_results(repo_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
