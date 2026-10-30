"""Smoke test suite for the ScamShield backend."""
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from app import app

client = app.test_client()

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"

def test_analyze():
    r = client.post("/api/analyze", json={
        "content": "Your SBI account is blocked today. Verify your KYC immediately at http://sbi.kyc-verification.xyz or call 9876543210 and send OTP.",
        "input_type": "message",
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data["success"] is True
    res = data["result"]
    assert "risk" in res
    assert "scam_type" in res
    assert "stage" in res
    assert "xai_analysis" in res
    assert res["xai_analysis"]["available"] is True
    assert len(res["xai_analysis"]["risk_tokens"]) > 0
    assert "brand_analysis" in res
    assert res["brand_analysis"]["impersonation_detected"] is True
    assert "complaint_draft" in res
    assert "CYB-" in res["complaint_draft"]["incident_id"]
    assert len(res["evidence_sha256"]) == 64

def test_validation():
    r = client.post("/api/analyze", json={"content": ""})
    assert r.status_code == 400

def test_batch():
    r = client.post("/api/analyze/batch", json={
        "items": [
            {"content": "Send your OTP immediately.", "input_type": "message"},
            {"content": "The meeting is at 5 PM.", "input_type": "message"},
        ]
    })
    assert r.status_code == 200
    assert r.get_json()["count"] == 2

if __name__ == "__main__":
    test_health()
    test_analyze()
    test_validation()
    test_batch()
    print("All backend smoke tests passed.")
