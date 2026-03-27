# TrueHash Forensics

TrueHash Forensics is a professional forensic tool designed for secure data acquisition and digital footprinting. Written in Python with a wxPython GUI, its primary goal is to ensure the integrity of digital evidence through a structured workflow.

## Key Features
*   **Hash Calculation:** Generates industry-standard SHA-256 hashes for individual files or entire directories.
*   **ZIP Processing:** Automatically extracts and hashes the contents of compressed archives.
*   **Professional Reporting:** Creates detailed PDF forensic reports featuring case metadata, investigator information, and an interactive file index.
*   **Digital Certification:** Integrates **TSA (Time-Stamping Authority)** through DigiCert to provide legally-verifiable timestamps.
*   **Blockchain Notarization:** Utilizes the **OpenTimestamps** protocol to anchor document hashes to the Bitcoin blockchain for immutable proof of existence.
*   **Chain of Custody:** Automatically generates a delivery report (*Verbale di Consegna*) to document the transfer of evidence.

## Installation & Running

### Prerequisites
*   Python 3.9+
*   Poetry or virtualenv (recommended)

### Setup
```bash
git clone https://github.com/YOUR_USERNAME/TrueHash-Forensics.git
cd TrueHash-Forensics
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt # Or install dependencies manually if no requirements.txt
```

### Running
```bash
python main.py
```

## Packaging
To build a standalone executable or an installer (like a macOS `.dmg`), you can use PyInstaller or similar tools. A `TrueHash Forensics.spec` file is included for this purpose.

## License
This project is licensed under the GNU GPL v3. See the `LICENSE` file for details.
