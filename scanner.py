import os
import joblib
import re

class CodeScanner:
    def __init__(self, model_path='vulnerability_rf_model.pkl', vectorizer_path='tfidf_vectorizer.pkl'):
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
            print("    Please ensure 'vulnerability_rf_model.pkl' and 'tfidf_vectorizer.pkl' are in the same directory.")
            exit(1)
            
        # These map our integer predictions back to readable vulnerability names
        self.vuln_mapping = {
            0: "Safe Code",
            1: "SQL Injection",
            2: "Command Injection",
            3: "Unsafe eval() usage",
            4: "Cross-Site Scripting (XSS)"
        }
        
    def clean_code(self, code_string):
        """
        Module 2: Code Preprocessing (Must match the exact preprocessing used in dataset training)
        """
        # Remove comments
        code_string = re.sub(r'#.*', '', code_string)
        # Remove docstrings
        code_string = re.sub(r'\"\"\"[\s\S]*?\"\"\"', '', code_string)
        code_string = re.sub(r"\'\'\'[\s\S]*?\'\'\'", '', code_string)
        # Remove blank lines and standardise
        lines = [line.strip() for line in code_string.split('\n') if line.strip()]
        return ' '.join(lines)
        
    def scan_code_snippet(self, raw_code):
        """
        Module 6: Takes raw Python code, preprocesses it, vectorizes it, and predicts vulnerabilities.
        """
        # 1. Clean it so it looks exactly like the training data
        cleaned_code = self.clean_code(raw_code)
        
        if not cleaned_code:
            return "Unable to scan (Empty file or only contains comments)", 0.0
            
        # 2. Convert text to Mathematical Array (TF-IDF)
        vectorized_text = self.vectorizer.transform([cleaned_code])
        
        # 3. Predict the Class (0, 1, 2, 3, 4)
        prediction_val = self.model.predict(vectorized_text)[0]
        
        # 4. Get the Probability (Confidence score)
        # predict_proba returns an array of probabilities for each class.
        probabilities = self.model.predict_proba(vectorized_text)[0]
        confidence = probabilities[prediction_val]
        
        vuln_name = self.vuln_mapping.get(prediction_val, "Unknown")
        
        return vuln_name, float(confidence)

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
                
                # Rule 1: We provide actionable recommendations
                if vuln_type == "SQL Injection":
                    print("Recommendation: Use parameterized SQL queries (e.g., cursor.execute('SELECT * FROM users WHERE id=%s', (id,))) instead of f-strings or concatenation.")
                elif vuln_type == "Command Injection":
                    print("Recommendation: Avoid os.system(). Use the subprocess module with 'shell=False' or validate all inputs strictly.")
                elif vuln_type == "Unsafe eval() usage":
                    print("Recommendation: Never use eval() on user input. Use ast.literal_eval() for safe mathematical evaluation, or strict JSON parsing.")
                elif vuln_type == "Cross-Site Scripting (XSS)":
                    print("Recommendation: Sanitize all user input before rendering it in an HTML response using escaping libraries (e.g., markupsafe.escape or Jinja templates).")
                    
        except Exception as e:
            print(f"[-] Error reading file: {e}")

if __name__ == "__main__":
    # Test the scanner against the synthetic datasets we generated!
    scanner = CodeScanner()
    
    # Let's test one SQL file and one Safe file to prove the brain works.
    print("\n[+] Running automated engine tests...")
    
    test_files = [
        "dataset/sql_injection/sample_0.py",
        "dataset/safe/sample_0.py"
    ]
    
    for test_file in test_files:
        if os.path.exists(test_file):
            scanner.generate_report(test_file)
        else:
            print(f"[-] {test_file} not found. Skipping test.")
