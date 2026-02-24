📱 Android APK Vulnerability Scanner

A lightweight Static Application Security Testing (SAST) tool that scans Android APK files for common security vulnerabilities using static code analysis.

This tool decompiles APKs using jadx and analyzes Java source code to detect insecure implementations.

🚀 Features

The scanner currently detects:

🔐 Insecure Logging

Sensitive data written to logs (passwords, tokens, secrets)

💾 Insecure Local Data Storage

World-readable/writable modes

Sensitive data stored in SharedPreferences

📸 Insecure Screen Capturing

Missing FLAG_SECURE (screenshots allowed)

🌐 Malicious / Unsafe URL Loading

Cleartext HTTP usage

Unsafe WebView URL loading

🔑 Embedded Secrets

Hardcoded API keys

Bearer tokens

Stripe / Google API keys

🏗️ Architecture
APK File
   ↓
JADX Decompilation
   ↓
Source Code Extraction
   ↓
Regex-based Static Analysis
   ↓
Structured Vulnerability Report

The tool follows a simplified SAST model:

No dynamic execution

Pure static pattern-based inspection

File-level & line-level detection

🛠️ Installation
1️⃣ Install jadx

Download from:
https://github.com/skylot/jadx/releases

Add jadx to your system PATH.

2️⃣ Clone Repository
````
git clone https://github.com/yourusername/android-apk-vulnerability-scanner.git
cd android-apk-vulnerability-scanner
````
3️⃣ Run the Scanner
````
python android_sast_scanner.py app.apk
````
📊 Example Output
````
[CRITICAL] Embedded Secrets
Description   : Hardcoded API keys or tokens
Total Findings: 2

  [1] File : sources/com/example/api/ApiClient.java
      Line : 45
      Code : String apiKey = "AIzaSyXXXXXXX";

[HIGH] Malicious URL Loading
Description   : Loading cleartext or untrusted URLs
Total Findings: 1

  [1] File : sources/com/example/web/WebActivity.java
      Line : 67
      Code : webView.loadUrl("http://example.com");
````
