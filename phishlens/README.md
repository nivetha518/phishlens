# PhishLens – AI-Based Malicious URL Detection

Classifies a URL as **Safe / Suspicious / Malicious** and explains the risk indicators.
Logistic regression over 19 URL features; each indicator's bar is its exact contribution to the score.

## Setup
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python train.py                  # creates model.joblib
python app.py                    # open http://127.0.0.1:5000
```

## Train on real data
Download a labelled dataset (PhishTank, Kaggle "Malicious URLs") as CSV with `url,label` columns:
```bash
python train.py --csv urls.csv
```
The default run uses synthetic demo data, so metrics from it are optimistic.

## Structure
- `features.py` – feature extraction (length, special chars, domain structure, keywords, look-alikes...)
- `train.py` – model training
- `app.py` – Flask API (`POST /api/predict`) + web server
- `static/index.html` – UI

## Verdict thresholds
< 35% Safe, 35–70% Suspicious, > 70% Malicious.
