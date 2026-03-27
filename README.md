# TrueHash Forensics

🇮🇹 **Italiano** | 🇬🇧 [English](#english)

TrueHash Forensics è uno strumento forense professionale ideato per l'acquisizione sicura di dati e il tracciamento digitale. Sviluppato in Python con interfaccia grafica wxPython, il suo obiettivo principale è garantire l'integrità delle prove digitali attraverso un flusso di lavoro strutturato.

## Funzionalità Principali
*   **Calcolo Hash:** Genera hash SHA-256, standard del settore, per singoli file o intere directory.
*   **Elaborazione ZIP:** Estrae e calcola automaticamente l'hash del contenuto degli archivi compressi.
*   **Reportistica Professionale:** Crea report forensi dettagliati in PDF completi di metadati del caso, informazioni sull'investigatore e un indice interattivo dei file.
*   **Certificazione Digitale:** Integra **TSA (Time-Stamping Authority)** tramite DigiCert per fornire marche temporali legalmente verificabili.
*   **Notarizzazione Blockchain:** Utilizza il protocollo **OpenTimestamps** per ancorare gli hash dei documenti alla blockchain di Bitcoin per una prova di esistenza immutabile.

## Installazione e Avvio

### ⬇️ Utenti Finali (Raccomandato)
Puoi scaricare l'applicazione pre-compilata dalla pagina [Releases](https://github.com/jpaladins/TrueHash-Forensics/releases).
*   **macOS:** Scarica l'ultima release, il file `.dmg`, aprilo e trascina l'applicazione nella tua cartella Applicazioni.
*   **Windows:** In arrivo nelle prossime versioni (sarà disponibile un file `.exe`).

### 💻 Sviluppatori (Avvio dal Codice Sorgente)
```bash
git clone https://github.com/jpaladins/TrueHash-Forensics.git
cd TrueHash-Forensics
python -m venv .venv
source .venv/bin/activate  # Su Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

<hr>

<h1 id="english">🇬🇧 English</h1>

TrueHash Forensics is a professional forensic tool designed for secure data acquisition and digital footprinting. Written in Python with a wxPython GUI, its primary goal is to ensure the integrity of digital evidence through a structured workflow.

## Key Features
*   **Hash Calculation:** Generates industry-standard SHA-256 hashes for individual files or entire directories.
*   **ZIP Processing:** Automatically extracts and hashes the contents of compressed archives.
*   **Professional Reporting:** Creates detailed PDF forensic reports featuring case metadata, investigator information, and an interactive file index.
*   **Digital Certification:** Integrates **TSA (Time-Stamping Authority)** through DigiCert to provide legally-verifiable timestamps.
*   **Blockchain Notarization:** Utilizes the **OpenTimestamps** protocol to anchor document hashes to the Bitcoin blockchain for immutable proof of existence.

## Installation & Running

### ⬇️ End Users (Recommended)
You can download the pre-compiled application from the [Releases](https://github.com/jpaladins/TrueHash-Forensics/releases) page.
*   **macOS:** Download the latest release `.dmg` file, open it, and drag the application to your Applications folder.
*   **Windows:** Coming in future versions (a `.exe` installer will be available).

### 💻 Developers (Running from Source)
```bash
git clone https://github.com/jpaladins/TrueHash-Forensics.git
cd TrueHash-Forensics
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Packaging
To build a standalone executable or an installer (like a macOS `.dmg`), you can use PyInstaller or similar tools. A `TrueHash Forensics.spec` file is included for this purpose.

## License
This project is licensed under the GNU GPL v3. See the `LICENSE` file for details.
