# 🛡️ HIPAA PII Masking Service

A **Python-based anonymization service** designed for internal enterprise use.  
It leverages **Microsoft Presidio** and **spaCy** to detect and mask the **18 HIPAA identifiers** specified under the **HIPAA Safe Harbor Provision**.  
The system combines **Natural Language Processing (NLP)** and **custom Regular Expressions (Regex)** for accurate and context-aware PII masking.

---

## ✨ Features

- **NLP-Powered Recognition:**  
  Uses `spaCy`'s `en_core_web_lg` model to identify entity types such as:
  - `PERSON`, `LOCATION`, `DATE_TIME`, and `ORGANIZATION`

- **Custom Regex Recognizers:**  
  Adds precise recognizers for identifiers not easily caught by NLP models:
  - Medical Record Numbers (`MRN-#####`)  
  - U.S. ZIP Codes (5-digit and 5+4 digit)  
  - Vehicle Identification Numbers (VIN)  
  - License Plates  
  - Health Plan IDs  
  - Device Identifiers  
  - U.S. ITINs (Individual Taxpayer Identification Numbers)

- **High-Confidence Overrides:**  
  Introduces custom, high-score recognizers for:
  - `US_SSN` (Social Security Number)  
  - `US_PASSPORT`  
  These reduce false positives from similar numeric formats.

- **Custom Masking Tags:**  
  PII is replaced with clear, context-preserving placeholders such as `<SSN>`, `<MRN>`, `<PERSON>`, and `<DATE>` instead of generic `****` masking.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yashatnutrail/hipaa-masking-service
cd hipaa-masking-service
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Download the spaCy NLP model

```bash
python -m spacy download en_core_web_lg
```

---

## 🚀 Usage

### Run Example Script

To test the service, run:

```bash
python example.py
```

This script:
- Processes multiple text samples
- Detects and masks HIPAA-compliant PII entities
- Prints the original, masked text, and detected entity list

### Example Output

| Input | Masked Output |
|-------|---------------|
| `"Patient John Doe's MRN is MRN-98453 and SSN is 123-45-6789."` | `"Patient <PERSON>'s MRN is <MRN> and SSN is <SSN>."` |

---

## 🧪 Testing

To validate the implementation:

```bash
pytest
```

This executes the internal test suite and ensures that all components — NLP recognizers, regex matchers, and mask logic — are functioning as expected.

---

## 🧰 Development Guidelines

This project uses **ruff** for linting and formatting.

### Format the codebase:

```bash
ruff format .
```

### Check and automatically fix linting issues:

```bash
ruff check . --fix
```

---

## 🩺 HIPAA Identifiers Covered

The service is designed to detect and mask all **18 HIPAA Safe Harbor identifiers**, including:

1. Names
2. Geographic identifiers smaller than a state
3. Dates (except year) directly related to an individual
4. Telephone and fax numbers
5. Email addresses
6. Social Security Numbers
7. Medical Record Numbers
8. Health Plan Beneficiary Numbers
9. Account Numbers
10. Certificate or License Numbers
11. Vehicle Identifiers and Serial Numbers (VINs, License Plates)
12. Device Identifiers and Serial Numbers
13. Web URLs
14. IP Addresses
15. Biometric Identifiers (fingerprints, voiceprints)
16. Full-face Photographic Images
17. Any other unique identifying code or characteristic
18. Combinations of data that can identify an individual

---

## 🧩 Tech Stack

| Component | Description |
|-----------|-------------|
| **Language** | Python 3.10+ |
| **Core Library** | Microsoft Presidio |
| **NLP Engine** | spaCy (en_core_web_lg) |
| **Regex Matching** | Custom recognizers |
| **Testing** | pytest |
| **Code Quality** | ruff |

---

## 📂 Project Structure

```
hipaa-masking-service/
├── README.md
├── requirements.txt
├── example.py
├── test_hipaa_masking_service.py
└── hipaa_masking_service.py
    
```

---

## 🔒 Security & Compliance

- This service is designed for **internal enterprise use** only
- All masking operations are performed **locally** with no external API calls
- The service follows the **HIPAA Safe Harbor** de-identification standard
- Regular security audits and updates are recommended to maintain compliance

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure all tests pass and code is formatted with `ruff` before submitting.