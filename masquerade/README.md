# Masquerade: Explainable Static Malware Triage

Masquerade is a localhost prototype for **explainable static triage of Windows PE files**. It works through
PE contradiction detection and calibrated risk scoring:

```
Upload PE → Extract features → Detect contradictions → Explainable 0–100 risk → Calibrated probability → Report
```

It asks whether a file's properties **agree with each other and with its claimed identity**, rather than judging
one feature at a time. Every verdict is shown as named, scored evidence that an analyst can check in the file.

> **Safety:** analysis is purely static. Uploaded files are read as bytes and parsed with `pefile`. They are
> never executed, loaded or passed to a subprocess. Stored copies get a neutral `.sample` suffix.

---

## Quick start

```bash
cd masquerade
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**

On first start the demo ML model trains in about 20 s and is cached in `models/`. Later starts are instant.
Everything runs locally, with no cloud services, API keys, accounts or CDN assets.

## Demo instructions

The upload page offers three built-in samples, so you don't need a real malware file:

| Option | What it is | Parsing |
|---|---|---|
| **Demo Sample** (DEMO / ILLUSTRATIVE) | A hand-written feature record for a disguised, packed injector (`Q3_financial_report.pdf.exe`). Hashes are digests of a label string; IoCs use reserved documentation ranges. | The record goes through the real engine, scoring and ML |
| **Synthetic contradiction fixture** | A non-functional PE32 built in memory. Its only instruction is `RET`, and it has an RWX high-entropy section, injection-style imports and the name `invoice_2024.pdf.exe`. Nothing is written to disk. | Real `pefile` parsing |
| **Benign reference** | The local `python.exe` interpreter, a genuine benign PE (read only) | Real `pefile` parsing |

You can also upload any `.exe`, `.dll` or `.sys` file. Uploading a non-PE file (for example a `.txt` or `.pdf`) shows the
**Not a valid PE** view with its hashes and detected content type.

## Pages

| Route | Purpose |
|---|---|
| `/` | Upload page, built-in samples and recent reports |
| `/analyze` (POST) | Runs the pipeline and redirects to the report |
| `/report/<id>` | Full explainable triage report |
| `/features/<id>` | Raw extractor output (highlighted JSON) · `/features/<id>.json` downloads it |
| `/report/<id>.json` | Complete report record (findings, score breakdown, ML vector) |
| `/model` | Model & calibration: reliability diagram, calibration map, Experiments 1–3, ROC, importances |
| `/about` | Methodology |

## Architecture

```
masquerade/
├── app.py                  Flask app factory, filters, start-up model load
├── config.py               Paths, upload limit, host/port
├── analyzer/
│   ├── utils.py            Hashing, Shannon entropy, string extraction, magic sniffing
│   ├── extractor.py        Stage 02: pefile feature extraction (headers, sections, imports, strings, overlay, version info)
│   ├── contradictions.py   Stage 03: five contradiction rule sets + unscored context notes
│   ├── scoring.py          Stage 04: weighted evidence → 0–100 risk score with breakdown
│   ├── ml_model.py         Stage 05: synthetic dataset, Random Forest, CalibratedClassifierCV, metrics
│   ├── pipeline.py         Orchestrates stages 01–06, persists reports/<id>.json
│   ├── demo.py             DEMO / ILLUSTRATIVE feature record
│   └── samples.py          In-memory synthetic test PE builder, benign reference path
├── routes/main.py          HTTP routes
├── templates/              Jinja2 pages (report, features, model, about, invalid, error)
├── static/css, static/js   Dark analyst theme, dependency-free SVG charts
├── uploads/                Uploaded samples (stored as <id>.sample)
├── reports/                JSON report records
├── models/                 Trained model bundle (joblib)
└── data/                   demo_training_features.csv (synthetic)
```

**Tech stack:** Python 3, Flask, pefile, pandas, NumPy, scikit-learn, joblib, and vanilla JS/SVG for the charts
(there are no front-end libraries).

## How static analysis works

`extractor.py` parses the PE with `pefile` and records:
PE type, architecture, subsystem, entry point and entry-point section, image base, timestamp, linker/OS version,
checksum (declared vs computed), DLL characteristics (ASLR, DEP, CFG), signature-directory presence, .NET flag, TLS callbacks,
debug/PDB info, Rich header, imphash. For each section it records the name, addresses, virtual/raw size, entropy and
R/W/X permissions. It also records imported DLLs and APIs (tagged by behaviour), exports, ASCII and UTF-16 strings
with suspicious-pattern hits (URLs, IPs, run keys, LOLBin commands, ransom text), overlay offset/size/entropy,
version-info strings, resource types and parser warnings, plus SHA-256, SHA-1 and MD5 hashes.

## Contradiction categories

| | Category | Implemented checks |
|---|---|---|
| A | **Identity** | Double extension (`report.pdf.exe`), document extension on PE content, RLO character, DLL/EXE mismatch, unsigned system-binary name, OriginalFilename mismatch, unsigned "Microsoft" claim |
| B | **Section** | RWX / W+X sections, executable section with no raw data, virtual ≫ raw size, packer section names, non-standard names, data section marked executable, duplicates |
| C | **Entropy-Content** | Section entropy ≥ 7.0; high entropy + sparse imports + few strings (possible packing); no import table; high-entropy overlay |
| D | **API** | Allocate + write + remote-thread injection chain (partial chains too), process hollowing, minimal imports + LoadLibrary/GetProcAddress, keylogging, download-and-execute, ransomware, Run-key persistence, recovery tampering, anti-debug. **A single API is never scored.** |
| E | **Structural** | Entry point outside sections / in non-executable / last / writable section, implausible timestamp, SizeOfImage or checksum mismatch, overlapping sections, odd section count, TLS callbacks, malformed headers |

Each finding has: `name`, `category`, `severity` (LOW/MEDIUM/HIGH), `score`, raw `evidence`, a plain-language
`explanation`, a `why` rationale and, where one applies, a MITRE ATT&CK reference.

## Risk scoring methodology

| Evidence bucket | Initial weight |
|---|---|
| Identity mismatch | 10 |
| RWX / section anomaly | 20 |
| High entropy | 15 |
| Entropy-content contradiction | 15 |
| API combination | 15 |
| Structural anomaly | 10 |

* Severity factor: HIGH × 1.0, MEDIUM × 0.6, LOW × 0.3.
* Per bucket, the strongest finding counts in full. Each additional finding adds 25% of its value, and the bucket is capped at its weight.
* `risk = round(100 × Σ bucket points / 85)`. Levels: **LOW 0–29 · MEDIUM 30–59 · HIGH 60–79 · CRITICAL 80–100**.
* One signal alone keeps a file LOW or MEDIUM. The score rises when independent categories agree.
* **The weights are initial values that still need tuning on a validation set. They are not claimed to be optimal.**

The report shows the per-bucket breakdown, the formula and the points applied for every finding.

## ML and calibration methodology

* There are 24 features: 15 conventional ones (size, entropy, imports, strings, signature, overlay…) and 9 contradiction ones (per-category severity, RWX count, unusual entry point, finding count).
* The data is split 70 / 15 / 15 (stratified). `RandomForestClassifier` (200 trees) is fit on the **training** split.
* `CalibratedClassifierCV` with **Platt (sigmoid)** scaling is fit on the **validation** split. Isotonic results are reported for comparison.
* Brier score, expected calibration error, a reliability diagram, ROC-AUC and a confusion matrix are computed on the untouched **test** split.
* The report shows **Raw RF score → Calibrated probability → Reported malware probability** and a calibration-map chart with the sample marked. It also includes a local sensitivity probe ("what moved the model").
* Experiment 1 (conventional features) vs Experiment 2 (+ contradiction features) is shown on `/model`.

> **Demo data disclosure.** No malware corpus ships with this prototype. `data/demo_training_features.csv` holds
> **4,000 synthetic rows** generated reproducibly (seed 42) from hand-written benign, benign-packed and malicious
> feature profiles, with 2% label noise. Every metric describes this synthetic data only and **does not represent real-world
> detection performance**. To train on real data, extract features from a labelled, de-duplicated corpus into
> the same columns and run `python -m analyzer.ml_model`.

## Limitations

* Static analysis cannot see run-time behaviour, and packed files reveal little until they are unpacked.
* Rules are heuristics, so installers, protectors, JIT runtimes and security tools can trigger them.
* The tool detects whether a signature directory is present but does not verify the signature.
* The ML layer is trained on synthetic data, so weights and thresholds need tuning on a real corpus.
* Dynamic validation (Ghidra, Procmon, Wireshark in an isolated VM) is a separate manual step outside this tool.
