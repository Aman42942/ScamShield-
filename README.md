# ScamShield — Complete Backend + Interactive UI

## Stack
- Flask
- scikit-learn
- TF-IDF + Logistic Regression
- CSV dataset
- HTML/CSS/JavaScript
- No React, Vite, Docker, SQLite, or external database

## Project flow

User input → Flask validation → detection engine → ML prediction + rule engine + URL analysis + stage detection → risk aggregation → scam type/stage/red flags/recommendation → result page. Supported Hindi/Hinglish and selected regional-language scam phrases are normalized before text analysis, and language-analysis details are included in the result.

## Backend modules

```text
backend/
├── detector.py            # orchestration
├── rules.py               # rule and scam taxonomy
├── stage_detector.py      # stage signals
├── url_analyzer.py        # URL heuristics
├── scoring.py             # risk aggregation
├── recommendations.py     # safety guidance
├── validation.py          # input validation
├── language_detector.py   # language/script heuristics and scam-phrase normalization
├── xai_engine.py          # Explainable AI (XAI) feature attribution & token weights
├── brand_detector.py      # brand impersonation, deceptive subdomains & typosquatting
└── complaint_generator.py # I4C Helpline 1930 & cybercrime.gov.in complaint drafting
```

## API

- `GET /api/health`
- `GET /api/model`
- `GET /api/scam-types`
- `GET /api/stages`
- `POST /api/analyze`
- `POST /api/analyze/batch`

See `docs/BACKEND_API.md`.

## Setup

```bash
pip install -r requirements.txt
python ml/preprocess_data.py
python -m ml.train_model
python -m ml.evaluate_model
python app.py
```

Open `http://127.0.0.1:5000`.

## Backend smoke test

```bash
python tests_backend.py
```

## Important
The Week-3 dataset is a small educational dataset. The risk score is a prototype score, not a calibrated probability of fraud.


## Windows / IDE launch note

The application runs with Flask's development reloader disabled:

```python
app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
```

This avoids the `ValueError: signal only works in main thread of the main interpreter`
error that can occur when Flask is launched from some IDEs, embedded consoles,
or non-main threads.


## Easiest way to run on Windows

1. Extract the ZIP completely.
2. Open the `ScamShield_Backend_Complete` folder.
3. Double-click `start_scamshield.bat`.
4. The launcher installs the required Python packages and starts Flask.
5. Your browser should open automatically at:

`http://127.0.0.1:5000`

If the browser does not open automatically, copy that address into Chrome/Edge.

### If something fails

Run:

```bat
python check_backend.py
```

and copy the complete output.

### Manual start

```bat
python -m pip install -r requirements.txt
python app.py
```

Keep the terminal window open while using the website. Closing it stops the backend.


## Multilingual / Hinglish detection

`backend/language_detector.py` uses Unicode-script heuristics and a curated phrase map for a limited set of scam-related phrases in Hindi, Hinglish, Bengali, Tamil, Telugu, Marathi, and Punjabi. It passes English text through and reports detected language, script, heuristic confidence, matched phrases, and a coverage note. This is **not** general-purpose translation or a guarantee of language identification; unfamiliar wording and dialects may be missed. Treat the confidence value as a heuristic indicator, not a calibrated probability.

The scan result page includes a Language Analysis section. Test the normalizer with:

```bash
python -m unittest discover -s tests -v
```


## Local account management
The avatar menu supports account creation, login, profile-name updates, password changes, and logout. Accounts are stored in `data/accounts.json` (passwords are hashed, not stored in plain text). This is a local demonstration implementation, not a production identity system. Before deployment, configure a strong `SCAMSHIELD_SECRET_KEY`, use HTTPS, add CSRF protection and rate limiting, and review privacy/security requirements.


## Weekly Progress & Implementation Summary (Semester 7 Review)

### 1. New Features Implemented
- **Explainable AI (XAI) Feature Attribution (`backend/xai_engine.py`)**:
  Calculates local token contribution weights ($c_i = \text{TF-IDF}_i \times w_i$) from the Logistic Regression decision boundary. Provides visual token highlighting in scan results (red tags for risk-driving tokens, green tags for legitimate conversational context) and top contributing feature rankings.
- **Brand Impersonation & Typosquatting Defense (`backend/brand_detector.py`)**:
  Identifies unauthorized brand claims (SBI, HDFC, ICICI, India Post, Income Tax, Netflix, Amazon, etc.), detects deceptive subdomains (e.g. `sbi.fraudsite.xyz`), catches lookalike homoglyphs/typosquatting via normalized Levenshtein distance, and flags high-risk disposable TLDs (`.xyz`, `.top`, `.vip`).
- **National Cybercrime Reporting Portal & 1930 Helpline Complaint Generator (`backend/complaint_generator.py`)**:
  Automatically synthesizes an official FIR/Complaint draft conforming to Ministry of Home Affairs (MHA) Indian Cyber Crime Coordination Centre (I4C) standards. Extracts phone numbers, UPI VPAs, domains, and applies relevant provisions of the IT Act, 2000 (Section 66C, Section 66D) and IPC 419/420.
- **Cryptographic Evidence Integrity (SHA-256) & Printable Forensic Report**:
  Computes a SHA-256 tamper-evident fingerprint for analyzed payloads and includes a printable audit report view for digital forensic evidence submission.
- **Dataset Expansion & Re-training**:
  Expanded raw and processed datasets from 40 to 90 balanced samples covering modern Indian fraud vectors (digital arrest scams, electricity cutoff threats, APK loan app blackmail, and YouTube task scams).

### 2. Technical Errors Encountered & Resolved
- **Error 1: Windows PyManager Access Denied (`WinError 5: Access is denied: C:\Users\...\AppData\Local\Python`)**
  - *Cause*: Default `python` executable in PATH routed to a broken Windows PyManager shim that lacked permissions.
  - *Resolution*: Updated `start_scamshield.bat` and `start_scamshield.ps1` to detect and prioritize the direct Python 3.11 installation path (`%LOCALAPPDATA%\Programs\Python\Python311\python.exe`).
- **Error 2: CSV Parsing Tokenizer Error (`pandas.errors.ParserError: Expected 2 fields, saw 3`)**
  - *Cause*: Unquoted commas inside message samples in `data/raw/raw_dataset.csv`.
  - *Resolution*: Re-serialized the dataset using Python's standard `csv` module with `csv.QUOTE_MINIMAL` and quoted multi-clause text fields.
- **Error 3: Flask 3.1 `__version__` Deprecation Warning**
  - *Cause*: Calling `flask.__version__` is deprecated in Flask 3.1+.
  - *Resolution*: Migrated to standard `importlib.metadata.version("flask")` in `check_backend.py`.
- **Error 4: Zero-Distance Homoglyph Trap in Typosquatting Analyzer**
  - *Cause*: Homoglyph character substitution (e.g. `0` -> `o` turning `amaz0n` into `amazon`) resulted in Levenshtein distance 0 against the target brand, failing a strict `1 <= dist <= 2` check.
  - *Resolution*: Added a check verifying that when normalized distance is 0 on an unauthorized domain, it is immediately flagged as a high-confidence homoglyph spoofing attack.
