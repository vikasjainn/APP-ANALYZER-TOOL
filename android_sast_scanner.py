#!/usr/bin/env python3
"""
Android APK Vulnerability Scanner
"""

import os
import re
import subprocess
import sys
import shutil
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Set


@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: str
    count: int = 0
    findings: List[Tuple[str, int, str]] = field(default_factory=list)


class AndroidVulnerabilityScanner:

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        self.output_dir = f"scan_output_{apk_name}"
        self.jadx_output = os.path.join(self.output_dir, "jadx")
        self.valid_source_dirs: Set[str] = set()
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self._init_vulnerabilities()

    def _init_vulnerabilities(self):
        self.vulnerabilities = {
            "insecure_logging": Vulnerability(
                "insecure_logging",
                "Insecure Logging",
                "Sensitive data written to logs",
                "MEDIUM"
            ),
            "insecure_data_storage": Vulnerability(
                "insecure_data_storage",
                "Insecure Local Data Storage",
                "Sensitive data stored insecurely",
                "HIGH"
            ),
            "insecure_capturing": Vulnerability(
                "insecure_capturing",
                "Insecure Screen Capturing",
                "Screenshots or screen recording allowed",
                "MEDIUM"
            ),
            "malicious_url_loading": Vulnerability(
                "malicious_url_loading",
                "Malicious URL Loading",
                "Loading cleartext or untrusted URLs",
                "HIGH"
            ),
            "embedded_secrets": Vulnerability(
                "embedded_secrets",
                "Embedded Secrets",
                "Hardcoded API keys or tokens",
                "CRITICAL"
            )
        }

    # ===================== SCAN FLOW =====================

    def scan(self):
        print("\n[+] Starting Android APK Security Scan \n")

        if not self._decompile_apk():
            print("[-] Decompilation failed")
            return

        self._collect_source_dirs()

        if not self.valid_source_dirs:
            print("[-] No Java source files found")
            return

        self._detect_insecure_logging()
        self._detect_insecure_data_storage()
        self._detect_insecure_capturing()
        self._detect_malicious_url_loading()
        self._detect_embedded_secrets()

        self._print_results()

    # ===================== APK HANDLING =====================

    def _decompile_apk(self) -> bool:
        jadx = shutil.which("jadx") or shutil.which("jadx.bat")
        if not jadx:
            print("[!] jadx not found in PATH")
            return False

        os.makedirs(self.output_dir, exist_ok=True)

        try:
            subprocess.run(
                [jadx, self.apk_path, "-d", self.jadx_output, "--no-res"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=600
            )
            return os.path.exists(os.path.join(self.jadx_output, "sources"))
        except Exception:
            return False

    def _collect_source_dirs(self):
        src = os.path.join(self.jadx_output, "sources")
        for root, _, files in os.walk(src):
            if any(f.endswith(".java") for f in files):
                self.valid_source_dirs.add(root)

    def _grep(self, pattern: str) -> List[Tuple[str, int, str]]:
        results = []
        for d in self.valid_source_dirs:
            for root, _, files in os.walk(d):
                for file in files:
                    if not file.endswith(".java"):
                        continue
                    path = os.path.join(root, file)
                    try:
                        with open(path, errors="ignore") as f:
                            for i, line in enumerate(f, 1):
                                if re.search(pattern, line):
                                    results.append((path, i, line.strip()))
                    except Exception:
                        pass
        return results

    # ===================== DETECTORS =====================

    def _detect_insecure_logging(self):
        vuln = self.vulnerabilities["insecure_logging"]
        matches = self._grep(r'Log\.[diew]|printStackTrace')
        for f, l, c in matches:
            if re.search(r'password|token|secret|key', c, re.I):
                vuln.findings.append((f, l, c))
                vuln.count += 1

    def _detect_insecure_data_storage(self):
        vuln = self.vulnerabilities["insecure_data_storage"]
        for f, l, c in self._grep(r'MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|SharedPreferences.*password'):
            vuln.findings.append((f, l, c))
            vuln.count += 1

    def _detect_insecure_capturing(self):
        vuln = self.vulnerabilities["insecure_capturing"]
        if not self._grep(r'FLAG_SECURE'):
            vuln.findings.append(("Application", 0, "FLAG_SECURE not set"))
            vuln.count = 1

    def _detect_malicious_url_loading(self):
        vuln = self.vulnerabilities["malicious_url_loading"]
        for f, l, c in self._grep(r'http://|loadUrl'):
            if "https://" not in c:
                vuln.findings.append((f, l, c))
                vuln.count += 1

    def _detect_embedded_secrets(self):
        vuln = self.vulnerabilities["embedded_secrets"]
        patterns = r'AIza[0-9A-Za-z\-_]{35}|sk_live_[0-9a-zA-Z]{24}|Bearer\s+[A-Za-z0-9._-]+'
        for f, l, c in self._grep(patterns):
            vuln.findings.append((f, l, c))
            vuln.count += 1

    # ===================== OUTPUT =====================

    def _print_results(self):
        print("\n========== SCAN RESULTS ==========")

        for vuln in self.vulnerabilities.values():
            if vuln.count == 0:
                continue

            print(f"\n[{vuln.severity}] {vuln.title}")
            print(f"Description   : {vuln.description}")
            print(f"Total Findings: {vuln.count}\n")

            for idx, (file, line, code) in enumerate(vuln.findings, 1):
                short_path = file if len(file) < 80 else "..." + file[-77:]
                print(f"  [{idx}] File : {short_path}")
                print(f"      Line : {line}")
                print(f"      Code : {code}\n")

        print("Scan completed.\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python android_vuln_scanner.py <apk_file>")
        return

    scanner = AndroidVulnerabilityScanner(sys.argv[1])
    scanner.scan()


if __name__ == "__main__":
    main()
