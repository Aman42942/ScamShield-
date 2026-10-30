import unittest
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from ml.model_service import load_or_train
from backend.xai_engine import extract_token_attributions
from backend.brand_detector import detect_brand_impersonation
from backend.complaint_generator import generate_complaint_draft
from backend.url_analyzer import analyze_urls


class AdvancedForensicsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = load_or_train()

    def test_xai_token_attribution(self):
        text = "Your bank account will be blocked today. Verify KYC immediately and send OTP."
        xai = extract_token_attributions(self.model, text)
        self.assertTrue(xai["available"])
        self.assertGreater(len(xai["risk_tokens"]), 0)
        tokens = [t["token"] for t in xai["risk_tokens"]]
        # Assert key pressure tokens are identified
        self.assertTrue(any(tok in ["immediately", "verify", "account", "bank account", "your bank"] for tok in tokens))
        self.assertIn("xai-risk", xai["highlighted_html"])

    def test_xai_empty_text_graceful(self):
        xai = extract_token_attributions(self.model, "")
        self.assertFalse(xai["available"])
        self.assertEqual(xai["risk_tokens"], [])

    def test_brand_impersonation_deceptive_subdomain(self):
        text = "Urgent: Verify your SBI account at http://sbi.kyc-portal.xyz/login"
        urls = analyze_urls(text)
        brand = detect_brand_impersonation(text, urls)
        self.assertTrue(brand["impersonation_detected"])
        self.assertIn("State Bank of India (SBI)", brand["targeted_brands"])
        self.assertTrue(any("Deceptive Subdomain" in f for f in brand["findings"]))

    def test_brand_impersonation_homoglyph_typosquatting(self):
        text = "Your order update at http://amaz0n-prime.xyz"
        urls = analyze_urls(text)
        brand = detect_brand_impersonation(text, urls)
        self.assertTrue(brand["impersonation_detected"])
        self.assertTrue(any("Typosquatting" in f or "lookalike" in f for f in brand["findings"]))

    def test_cybercrime_complaint_draft(self):
        text = "Send Rs 15000 immediately to fraudster@okaxis or call 9876543210 to stop arrest."
        draft = generate_complaint_draft(
            text=text,
            scam_type="Digital Arrest Scam",
            risk_level="HIGH RISK",
            risk_percent=85,
            stage="Payment Request",
        )
        self.assertTrue(draft["incident_id"].startswith("CYB-"))
        self.assertEqual(len(draft["evidence_sha256"]), 64)
        self.assertIn("9876543210", draft["phone_numbers"])
        self.assertIn("fraudster@okaxis", draft["upi_ids"])
        self.assertIn("Section 66D", draft["complaint_draft"])
        self.assertIn("1930", draft["helpline"])


if __name__ == "__main__":
    unittest.main()
