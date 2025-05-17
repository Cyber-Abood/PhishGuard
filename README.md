# PhishGuard
The system provides a two-layer URL and QR code detection
# PhishGuard: Phishing Detection Web App & Browser Extension

PhishGuard is a comprehensive anti-phishing solution consisting of a web application and a browser extension. The system provides a **two-layer URL and QR code detection** process:

1. **Layer 1: VirusTotal API**

   * Scans submitted URLs or QR-coded URLs against VirusTotal's database.
2. **Layer 2: AI Model (CherBERT)**

   * Applies a custom BERT‑based model (CherBERT) to analyze URL text and metadata for subtle phishing patterns.

Meanwhile, the **PhishGuard browser extension** protects users in real time while they browse:

* Intercepts requests and responses.
* Blocks pages identified as malicious.
* Displays a warning page (`warning.html`) when phishing is detected.

The **web interface** allows users to:

* Enter URLs manually for on-the-fly phishing checks.
* Upload a QR code image to extract and scan embedded URLs.
* Download and install the browser extension for continuous protection.

---

## 🚀 Features

* **Dual-layer scanning** using VirusTotal and CherBERT.
* **QR Code support**: upload PNG/JPG images to scan encoded links.
* **Real-time browser protection** with a WebExtension:

  * Blocks malicious navigation.
  * Shows a customizable warning page.
* **Progressive Web App** (PWA) capabilities for offline fallback and fast loading.

---

## 🗂️ Repository Structure

```
PhishGuardWebsite/
├── public/                  # Frontend assets served by Express
│   ├── extension/           # Packaged extension ZIP for download
│   ├── scripts/             # Client-side JavaScript logic
│   ├── index.html           # Main web interface
│   └── sw.js                # Service worker (PWA support)
├── server/                  # Backend source code
│   ├── app.js               # Express server & routes
│   ├── routes/              # API route handlers
│   └── services/            # VirusTotal & AI model integration
├── uploads/                 # Temporary uploads for QR scans
├── .env                     # Environment variables (not tracked)
├── .gitignore               # Files & folders to ignore in Git
├── package.json             # Node.js dependencies & scripts
└── README.md                # <-- You are here

PhishGuardExtension/         # Browser extension source
├── manifest.json            # WebExtension manifest & permissions
├── background.js            # Background script intercepting traffic
├── warning.html             # Warning page for blocked URLs
├── warning.js               # Logic for warning page behavior
├── icons/                   # Extension icons (16x16, 32x32, ...)
└── popup/                   # (Optional) popup panel UI
```

---

## 🔧 Installation & Setup

1. **Clone the repo**

   ```bash
   git clone https://github.com/Cyber-Abood/PhishGuard.git
   cd PhishGuardWebsite
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Configure environment**
   Copy `.env.example` to `.env` and set:

   ```ini
   PORT=3000
   VIRUSTOTAL_API_KEY=your_api_key_here
   YOUR_PRODUCTION_DOMAIN=yourdomain.com
   ```

4. **Run the server**

   ```bash
   npm start
   python AI_model.py
   node app.js
   ```

5. **Open** `http://localhost:3000` in your browser.

6. **Install the extension**

   * Download via the web UI.
   * In Firefox: Go to `about:debugging` → **Load Temporary Add-on** → select the downloaded ZIP.
   * In Chrome (unpacked): Go to `fire://extensions` → **Load unpacked** → select `PhishGuardExtension/` folder.

---

## 🧠 AI Model: CherBERT

* A fine-tuned BERT-based model trained on phishing vs. legitimate URL datasets.
* Hosted as a service (`\server\routes\charbert-bert-wiki`) and invoked after VirusTotal returns a neutral result.
* charbert-bert-wiki finetuned folder : https://mega.nz/folder/Gdtm2IqJ#lnDue23hmmoD5ejlyQxS0w

---

## 🛡️ Usage

* **Manual URL scan**: Enter any URL and hit **Scan URL**.
* **QR code scan**: Upload a PNG/JPG containing a QR code.
* **Real-time protection**: Browse normally with the extension; malicious sites will be blocked automatically.

---


## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 💬 Contact

Built by **Abdalqader Hussam** - feel free to reach out at [abdalqaderhussam@gmail.com](mailto:abdalqader@example.com) or open an issue here on GitHub.
linked in : https://www.linkedin.com/in/abdalqader-hussam-a376b722b/
