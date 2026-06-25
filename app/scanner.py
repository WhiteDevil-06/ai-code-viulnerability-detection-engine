import os
import joblib
import re
import json

class CodeScanner:
    def __init__(
        self,
        model_path='artifacts/vulnerability_model.pkl',
        vectorizer_path='artifacts/tfidf_vectorizer.pkl',
        config_path='artifacts/model_config.json'
    ):
        """
        Initialize the Vulnerability Scanner by loading the exported ML models.
        """
        print("[*] Loading AI models...")
        try:
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
            print("[+] Models loaded successfully.")
        except FileNotFoundError as e:
            print(f"[-] Error: Could not find model files. {e}")
            print("    Please ensure 'vulnerability_model.pkl' and 'tfidf_vectorizer.pkl' are built and exported.")
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
        if any(cmd in code_lower for cmd in ["os.system", "os.popen", "subprocess.run", "subprocess.popen", "subprocess.call"]):
            return "Command Injection"
        if any(sql in code_lower for sql in ["select ", "insert ", "update ", "delete "]) and (".execute(" in code_lower or ".executemany(" in code_lower):
            if any(fmt in code_lower for fmt in ["f'", 'f"', "%", ".format("]):
                return "SQL Injection"
        if "render_template_string" in code_lower or "markup(" in code_lower:
            return "Cross-Site Scripting (XSS)"
        return "Vulnerable Code"
        
    def scan_code_snippet(self, raw_code):
        """
        Takes raw Python code, preprocesses it, vectorizes it, and predicts vulnerabilities.
        """
        # 1. Clean it so it looks exactly like the training data
        cleaned_code = self.clean_code(raw_code)
        
        if not cleaned_code:
            return "Safe Code", 0.0
            
        # 2. Convert text to Mathematical Array (TF-IDF)
        vectorized_text = self.vectorizer.transform([cleaned_code])
        
        # 3. Get the probability of Vulnerable class (class 1)
        prob = self.model.predict_proba(vectorized_text)[0][1]
        
        # 4. Classify using the calibrated threshold
        if prob >= self.threshold:
            vuln_type = self.identify_vuln_type(raw_code)
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
