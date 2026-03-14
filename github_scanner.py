import os
import subprocess
import tempfile
from scanner import CodeScanner

class GitHubScanner:
    def __init__(self):
        """
        Initialize the GitHub Scanner. It reuses the CodeScanner engine we built in Milestone 6.
        """
        self.engine = CodeScanner()

    def scan_repository(self, github_url):
        """
        Module 1 (Ingestion): Clones a GitHub repo using native git,
        finds all Python files, and feeds them to the scanner engine.
        """
        print(f"\n[*] Preparing to scan repository: {github_url}")
        
        # Security Feature: Basic validation to prevent arbitrary terminal command injection
        if not github_url.startswith("https://github.com/"):
            print("[-] Error: Only https://github.com/ URLs are supported.")
            return

        # Create a temporary directory that automatically deletes itself when the scan finishes
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_dir = os.path.join(temp_dir, "repo")
            
            try:
                print(f"[*] Cloning repository via Git...")
                # We use subprocess.run to execute actual terminal commands safely
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", github_url, repo_dir], 
                    capture_output=True, 
                    text=True,
                    check=True # This raises an exception instantly if the clone fails (e.g., repo doesn't exist)
                )
                print("[+] Repository cloned successfully.")
                
            except subprocess.CalledProcessError as e:
                print(f"[-] Error: Failed to clone repository. Is the URL correct and the repo public?")
                # e.stderr contains the exact error Git threw
                print(f"    Git output: {e.stderr.strip()}")
                return
            except FileNotFoundError:
                print("[-] Error: 'git' is not installed or not in your system PATH.")
                return

            print("[*] Commencing security scan on all Python files...")
            vulnerabilities_found = []
            files_scanned = 0
            
            # Walk through every folder and subfolder in the cloned repo
            for root, dirs, files in os.walk(repo_dir):
                for file in files:
                    if file.endswith('.py'):
                        files_scanned += 1
                        file_path = os.path.join(root, file)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                raw_code = f.read()
                                
                            # Feed the raw code into our Random Forest engine
                            vuln_type, confidence = self.engine.scan_code_snippet(raw_code)
                            
                            # Log anything that isn't completely safe
                            if vuln_type != "Safe Code":
                                # We slice off the big temporary folder path so the report is clean
                                clean_filename = file_path.replace(repo_dir, "").strip("\\/")
                                vulnerabilities_found.append({
                                    "file": clean_filename,
                                    "vulnerability": vuln_type,
                                    "confidence": confidence
                                })
                                
                        except UnicodeDecodeError:
                            # Skip files that aren't readable text (like compiled binaries ending in .py somehow)
                            pass
                        except Exception as e:
                            print(f"[-] Failed to scan {file}: {e}")
                            
            # Print the final formatted report
            self._print_report(files_scanned, vulnerabilities_found, github_url)


    def _print_report(self, files_scanned, vulnerabilities, url):
        """
        Outputs a clean summary of the GitHub scan.
        """
        print("\n" + "="*50)
        print("    GITHUB REPOSITORY SECURITY REPORT")
        print("="*50)
        print(f"Target: {url}")
        print(f"Total Python (.py) Files Scanned: {files_scanned}")
        print(f"Vulnerabilities Detected: {len(vulnerabilities)}\n")
        
        if not vulnerabilities:
            if files_scanned == 0:
                print("[-] WARNING: No Python files were found in this repository.")
            else:
                print("[+] SUCCESS: No vulnerabilities detected in the repository.")
        else:
            print("[-] CRITICAL: Vulnerable files found.\n")
            # We sort vulnerabilities by confidence score so the worst ones are at the top
            vulnerabilities.sort(key=lambda x: x['confidence'], reverse=True)
            
            for v in vulnerabilities:
                print(f"--> File: {v['file']}")
                print(f"    Issue: {v['vulnerability']}")
                print(f"    Confidence: {v['confidence']*100:.2f}%\n")


if __name__ == "__main__":
    scanner = GitHubScanner()
    
    print("\n--- AI GitHub Vulnerability Scanner ---")
    user_url = input("Enter a public GitHub repository URL to scan: ").strip()
    
    if user_url:
        scanner.scan_repository(user_url)
    else:
        print("[-] Error: No URL provided.")
