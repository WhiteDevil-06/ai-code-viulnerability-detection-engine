"""
github_scanner.py — VulnScanner AI
Scans a GitHub repository for Python vulnerabilities.
Strategy:
  1. Try git clone (if git is installed)
  2. Fallback: download repo ZIP via GitHub API (no git required)
"""
import os
import shutil
import subprocess
import tempfile
import zipfile
import io
import requests
from scanner import CodeScanner


class GitHubScanner:
    def __init__(self):
        self.engine = CodeScanner()

    # ── Public API ──────────────────────────────────────────────────────────────
    def get_scan_results(self, github_url: str) -> dict:
        """
        Scan a GitHub repo. Tries git clone first; falls back to zipball download.
        Returns: { target, files_scanned, vulnerabilities: [{file, vulnerability, confidence}] }
        """
        if not github_url.startswith("https://github.com/"):
            raise ValueError("Only https://github.com/ URLs are supported.")

        with tempfile.TemporaryDirectory() as tmp:
            # Choose download method
            if shutil.which("git"):
                repo_dir = self._clone_via_git(github_url, tmp)
            else:
                repo_dir = self._download_via_zip(github_url, tmp)

            return self._scan_directory(github_url, repo_dir)

    # ── Download methods ────────────────────────────────────────────────────────
    def _clone_via_git(self, github_url: str, tmp_dir: str) -> str:
        """Try git clone. Raises on failure so caller can catch and fallback."""
        repo_dir = os.path.join(tmp_dir, "repo")
        subprocess.run(
            ["git", "clone", "--depth", "1", github_url, repo_dir],
            capture_output=True,
            text=True,
            check=True
        )
        return repo_dir

    def _download_via_zip(self, github_url: str, tmp_dir: str) -> str:
        """
        Downloads the repo as a ZIP via GitHub's zipball API.
        Works without git installed.
        URL pattern: https://api.github.com/repos/{owner}/{repo}/zipball/HEAD
        """
        parts = github_url.rstrip("/").replace(".git", "").split("/")
        if len(parts) < 5:
            raise ValueError(f"Cannot parse owner/repo from URL: {github_url}")

        owner = parts[-2]
        repo  = parts[-1]
        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/HEAD"

        headers = {"Accept": "application/vnd.github+json", "User-Agent": "VulnScanner-AI"}
        resp = requests.get(zip_url, headers=headers, timeout=60, allow_redirects=True)

        if resp.status_code == 404:
            raise ValueError(f"Repository not found: {github_url}. Is it public?")
        resp.raise_for_status()

        # Extract ZIP
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            z.extractall(extract_dir)

        # GitHub ZIP has a single top-level folder like "owner-repo-sha/"
        children = os.listdir(extract_dir)
        if children:
            return os.path.join(extract_dir, children[0])
        return extract_dir

    # ── Scan engine ─────────────────────────────────────────────────────────────
    def _scan_directory(self, github_url: str, repo_dir: str) -> dict:
        files_scanned = 0
        vulnerabilities = []

        for root, _, files in os.walk(repo_dir):
            for file in files:
                if file.endswith(".py"):
                    files_scanned += 1
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            raw_code = f.read()
                        vuln_type, confidence = self.engine.scan_code_snippet(raw_code)
                        if vuln_type != "Safe Code":
                            clean_name = file_path.replace(repo_dir, "").lstrip("/\\")
                            vulnerabilities.append({
                                "file":          clean_name,
                                "vulnerability": vuln_type,
                                "confidence":    confidence
                            })
                    except Exception:
                        pass

        return {
            "target":          github_url,
            "files_scanned":   files_scanned,
            "vulnerabilities": vulnerabilities
        }

    # ── Legacy CLI entry point (unchanged) ──────────────────────────────────────
    def scan_repository(self, github_url: str):
        result = self.get_scan_results(github_url)
        self._print_report(
            result["files_scanned"],
            result["vulnerabilities"],
            result["target"]
        )

    def _print_report(self, files_scanned, vulnerabilities, url):
        print("\n" + "="*50)
        print("    GITHUB REPOSITORY SECURITY REPORT")
        print("="*50)
        print(f"Target: {url}")
        print(f"Python Files Scanned: {files_scanned}")
        print(f"Vulnerabilities: {len(vulnerabilities)}\n")
        if not vulnerabilities:
            print("[+] No vulnerabilities detected.")
        else:
            for v in sorted(vulnerabilities, key=lambda x: x["confidence"], reverse=True):
                print(f"--> {v['file']}: {v['vulnerability']} ({v['confidence']*100:.1f}%)")


if __name__ == "__main__":
    s = GitHubScanner()
    url = input("GitHub URL: ").strip()
    if url:
        s.scan_repository(url)
