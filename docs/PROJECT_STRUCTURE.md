# ScamShield Project Structure

```text
ScamShield_Proper/
├── app.py
├── config.py
├── requirements.txt
├── backend/
│   ├── detector.py
│   ├── rules.py
│   ├── stage_detector.py
│   └── url_analyzer.py
├── ml/
│   ├── preprocess_data.py
│   ├── train_model.py
│   └── evaluate_model.py
├── data/
│   ├── raw/raw_dataset.csv
│   └── processed/cleaned_dataset.csv
├── models/scam_model.pkl
├── reports/evaluation.txt
└── frontend/
    ├── templates/
    └── static/
        ├── css/style.css
        └── js/
```

Flow: User -> Flask -> detector -> ML + rules + URL + stage -> risk result -> UI.

- `backend/language_detector.py`: heuristic language/script detection and limited scam phrase normalization for supported languages.
