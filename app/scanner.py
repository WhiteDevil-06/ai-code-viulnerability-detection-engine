import os
# pyrefly: ignore [missing-import]
import joblib
import re
import json

class CodeScanner:
    def __init__(
        self,
        model_path='artifacts/vulnerability_model.pkl',
        vectorizer_path='artifacts/tfidf_vectorizer.pkl',
        scaler_path='artifacts/scaler.pkl',
        config_path='artifacts/model_config.json'
    ):
        """
        Initialize the Vulnerability Scanner by loading the exported ML models.
        """
        print("[*] Loading AI models...")
        try:
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
            self.scaler = joblib.load(scaler_path)
            print("[+] Models loaded successfully.")
        except FileNotFoundError as e:
            print(f"[-] Error: Could not find model files. {e}")
            print("    Please ensure 'vulnerability_model.pkl', 'tfidf_vectorizer.pkl', and 'scaler.pkl' are built and exported.")
            exit(1)
            
        # Load calibrated threshold
        self.threshold = 0.45
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.threshold = config.get("optimal_threshold", 0.45)
                    print(f"[+] Calibrated threshold loaded: {self.threshold:.4f}")
            except Exception as e:
                print(f"Warning: Could not parse model config. Using default threshold 0.45. {e}")

        # These map our integer predictions back to readable vulnerability names
        self.vuln_mapping = {
            0: "Safe Code",
            1: "Vulnerable Code"
        }
        
    def custom_dedent(self, code: str) -> str:
        """Dedent Python code using the first line's indentation level."""
        if not code:
            return code
        lines = code.splitlines()
        first_line = lines[0]
        leading_whitespace = ""
        for char in first_line:
            if char in " \t":
                leading_whitespace += char
            else:
                break
        if not leading_whitespace:
            return code
        res = []
        for line in lines:
            if line.startswith(leading_whitespace):
                res.append(line[len(leading_whitespace):])
            else:
                res.append(line.lstrip() if not line.strip() else line)
        return "\n".join(res)

    def clean_code(self, code_string):
        """
        Code Preprocessing (Matches the exact preprocessing used in dataset training)
        """
        dedented = self.custom_dedent(code_string)
        if not dedented:
            return ""
        # Remove comments
        code = re.sub(r'#.*', '', dedented)
        # Remove triple-quoted docstrings
        code = re.sub(r'\"\"\"[\s\S]*?\"\"\"', '', code)
        code = re.sub(r"\'\'\'[\s\S]*?\'\'\'", '', code)
        # Normalize whitespace
        code = re.sub(r"\s+", " ", code).strip()
        return code
        
    def identify_vuln_type(self, code_snippet: str) -> str:
        """Refines binary vulnerable class prediction into specific CWE categories using pattern matching."""
        code_lower = code_snippet.lower()
        if "eval(" in code_lower or "exec(" in code_lower:
            return "Unsafe eval() usage"
        if any(cmd in code_lower for cmd in ["os.system", "os.popen", "subprocess.run", "subprocess.popen", "subprocess.call", "subprocess.check_output"]):
            return "Command Injection"
        if any(sql in code_lower for sql in ["select ", "insert ", "update ", "delete "]) and (".execute(" in code_lower or ".executemany(" in code_lower):
            return "SQL Injection"
        if "render_template_string" in code_lower or "markup(" in code_lower:
            return "Cross-Site Scripting (XSS)"
            
        # Fallbacks for other types
        if "hashlib.md5" in code_lower or "hashlib.sha1" in code_lower:
            return "Weak Cryptography"
        if "requests.get(" in code_lower or "urllib." in code_lower:
            return "Potential SSRF / Open Redirect"
            
        return "Vulnerable Code"
        
    def calculate_metrics(self, raw_code: str) -> dict:
        """Estimate code metrics (nloc, complexity, token_count, nesting) dynamically."""
        if not raw_code:
            return {"nloc": 0.0, "complexity": 1.0, "token_count": 0.0, "top_nesting_level": 0.0}
            
        lines = raw_code.splitlines()
        
        # 1. nloc: count non-empty and non-comment lines
        nloc = 0.0
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                nloc += 1.0
                
        # 2. complexity: cyclomatic complexity estimate (decision points + 1)
        decision_keywords = ["if", "elif", "for", "while", "except", "with", "and", "or"]
        complexity = 1.0
        clean_text = self.clean_code(raw_code)
        words = re.findall(r"\b\w+\b", clean_text.lower())
        for word in words:
            if word in decision_keywords:
                complexity += 1.0
                
        # 3. token_count: rough count of code tokens
        tokens = re.findall(r"\w+|[^\w\s]", raw_code)
        token_count = float(len(tokens))
        
        # 4. top_nesting_level: maximum nesting level (using line indentation)
        max_nesting = 0.0
        for line in lines:
            if not line.strip():
                continue
            indent = 0
            for char in line:
                if char == " ":
                    indent += 1
                elif char == "\t":
                    indent += 4
                else:
                    break
            nesting = indent // 4
            if nesting > max_nesting:
                max_nesting = nesting
                
        return {
            "nloc": nloc,
            "complexity": complexity,
            "token_count": token_count,
            "top_nesting_level": float(max_nesting)
        }

    def extract_heuristics_single(self, code_string: str) -> list[float]:
        """Extract security heuristics for a single code snippet."""
        code_lower = code_string.lower()
        
        has_eval = 1.0 if "eval(" in code_lower or "exec(" in code_lower else 0.0
        
        has_system = 1.0 if any(cmd in code_lower for cmd in ["os.system", "os.popen", "subprocess.run", "subprocess.popen", "subprocess.call"]) else 0.0
        
        has_sql = 0.0
        if any(sql in code_lower for sql in ["select ", "insert ", "update ", "delete "]) and (".execute(" in code_lower or ".executemany(" in code_lower):
            has_sql = 1.0
            
        has_format_sql = 0.0
        if has_sql and any(fmt in code_lower for fmt in ["f'", 'f"', "%", ".format("]):
            has_format_sql = 1.0
            
        has_xss = 1.0 if "render_template_string" in code_lower or "markup(" in code_lower else 0.0
        
        return [has_eval, has_system, has_sql, has_format_sql, has_xss]

    def _heuristic_verification(self, code_string: str, vuln_type: str) -> bool:
        """
        Guardrail to reduce false positives.
        Returns True if the heuristic confirms the vulnerability, False if it overrides it as Safe.
        """
        code_lower = code_string.lower()
        
        has_execute = ".execute(" in code_lower or ".executemany(" in code_lower or "cursor(" in code_lower
        has_sql = any(k in code_lower for k in ["select ", "insert ", "update ", "delete ", "drop "])
        has_sql_format = any(fmt in code_lower for fmt in ["f'", 'f"', "%", ".format(", " + ", "{}"])
        has_system = any(cmd in code_lower for cmd in ["os.system", "os.popen", "subprocess.", "popen(", "sys.call"])
        has_eval = "eval(" in code_lower or "exec(" in code_lower
        has_xss = "render_template" in code_lower or "markup(" in code_lower or "send_file(" in code_lower
        has_crypto = "hashlib" in code_lower or "md5" in code_lower or "sha1" in code_lower or "base64" in code_lower
        has_network = "requests." in code_lower or "urllib" in code_lower or "socket" in code_lower

        if vuln_type == "SQL Injection":
            if not (has_execute and has_sql and has_sql_format): return False
        elif vuln_type == "Command Injection":
            if not has_system: return False
        elif vuln_type == "Unsafe eval() usage":
            if not has_eval: return False
        elif vuln_type == "Cross-Site Scripting (XSS)":
            if not has_xss: return False
        elif vuln_type == "Weak Cryptography":
            if not has_crypto: return False
        elif vuln_type == "Potential SSRF / Open Redirect":
            if not has_network: return False
        else:
            # For general "Vulnerable Code", require at least one major indicator
            if not (has_execute or has_system or has_eval or has_xss or has_crypto or has_network):
                return False
                
        return True

    def scan_code_snippet(self, raw_code):
        """
        Takes raw Python code, preprocesses it, vectorizes it, and predicts vulnerabilities.
        """
        import scipy.sparse as sp
        import numpy as np
        
        # 1. Clean it so it looks exactly like the training data
        cleaned_code = self.clean_code(raw_code)
        
        if not cleaned_code:
            return "Safe Code", 0.0
            
        # 2. Convert text to Mathematical Array (TF-IDF)
        vectorized_text = self.vectorizer.transform([cleaned_code])
        
        # 3. Calculate dynamic metrics and scale them
        metrics = self.calculate_metrics(raw_code)
        meta_vals = [[metrics["nloc"], metrics["complexity"], metrics["token_count"], metrics["top_nesting_level"]]]
        meta_scaled = self.scaler.transform(meta_vals)
        
        # 4. Extract heuristics
        heuristics = [self.extract_heuristics_single(cleaned_code)]
        
        # 5. Combine features
        X_all = sp.hstack([vectorized_text, meta_scaled, heuristics], format="csr")
        
        # 6. Get the probability of Vulnerable class (class 1)
        prob = self.model.predict_proba(X_all)[0][1]
        
        # 7. Classify using the calibrated threshold
        if prob >= self.threshold:
            vuln_type = self.identify_vuln_type(raw_code)
            
            # 8. Run Heuristic Guardrail
            if not self._heuristic_verification(raw_code, vuln_type):
                return "Safe Code", float(1.0 - prob)
                
            confidence = prob
            return vuln_type, float(confidence)
        else:
            return "Safe Code", float(1.0 - prob)

    def generate_report(self, file_path):
        """
        Reads a file and prints a formatted security report.
        """
        print(f"\n--- Scanning File: {file_path} ---")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_code = f.read()
                
            vuln_type, confidence = self.scan_code_snippet(raw_code)
            
            # Formatting the output report
            print(f"Vulnerability: {vuln_type}")
            print(f"Confidence Score: {confidence * 100:.2f}%")
            
            if vuln_type == "Safe Code":
                print("Risk Level: Low")
                print("Recommendation: No immediate threats detected.")
            else:
                print("Risk Level: HIGH")
                
                # We provide actionable recommendations
                if vuln_type == "SQL Injection":
                    print("Recommendation: Use parameterized SQL queries (e.g., cursor.execute('SELECT * FROM users WHERE id=%s', (id,))) instead of f-strings or concatenation.")
                elif vuln_type == "Command Injection":
                    print("Recommendation: Avoid os.system(). Use the subprocess module with 'shell=False' or validate all inputs strictly.")
                elif vuln_type == "Unsafe eval() usage":
                    print("Recommendation: Never use eval() on user input. Use ast.literal_eval() for safe mathematical evaluation, or strict JSON parsing.")
                elif vuln_type == "Cross-Site Scripting (XSS)":
                    print("Recommendation: Sanitize all user input before rendering it in an HTML response using escaping libraries (e.g., markupsafe.escape or Jinja templates).")
                elif vuln_type == "Vulnerable Code":
                    print("Recommendation: General vulnerability flagged. Please review code logic for potential security loopholes or input validation issues.")
                    
        except Exception as e:
            print(f"[-] Error reading file: {e}")

if __name__ == "__main__":
    scanner = CodeScanner()
    print("\n[+] Running automated engine tests...")
    
    test_snippets = [
        ("def login(username, password):\n    query = f'SELECT * FROM users WHERE user=\"{username}\" AND pass=\"{password}\"'\n    cursor.execute(query)", "SQL Injection"),
        ("def execute_cmd(user_input):\n    os.system('ping ' + user_input)", "Command Injection"),
        ("def calculate(expr):\n    return eval(expr)", "Unsafe eval() usage"),
        ("def render_welcome(user_name):\n    return render_template_string('<h1>Welcome ' + user_name + '</h1>')", "Cross-Site Scripting (XSS)"),
        ("def greet(name):\n    print('Hello, ' + name)", "Safe Code")
    ]
    
    for code, expected in test_snippets:
        res_type, conf = scanner.scan_code_snippet(code)
        print(f"Code: {code.splitlines()[0]}... | Expected: {expected} | Predicted: {res_type} ({conf*100:.1f}%)")
