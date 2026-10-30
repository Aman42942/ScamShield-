"""ScamShield backend package.

The backend is intentionally modular:
- validation.py: request/input validation
- rules.py: explainable keyword signals and scam taxonomy
- url_analyzer.py: URL extraction and heuristic checks
- stage_detector.py: scam-stage signals
- scoring.py: risk-score aggregation
- recommendations.py: user-facing safety guidance
- detector.py: orchestration layer
"""
