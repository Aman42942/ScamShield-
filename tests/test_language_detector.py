import unittest
from backend.language_detector import detect_language, normalize_for_detection


class LanguageDetectorTests(unittest.TestCase):
    def test_hinglish_phrase_normalizes(self):
        normalized, info = normalize_for_detection("Aapka account band ho jayega, abhi verify karo")
        self.assertIn("account will be blocked", normalized)
        self.assertIn("verify now", normalized)
        self.assertEqual(info["language"], "Hinglish")
        self.assertTrue(info["normalization_applied"])

    def test_hindi_phrase_normalizes(self):
        normalized, info = normalize_for_detection("अपना ओटीपी साझा करें")
        self.assertIn("share your otp", normalized)
        self.assertEqual(info["language"], "Hindi")

    def test_bengali_phrase_normalizes(self):
        normalized, info = normalize_for_detection("এখনই টাকা পাঠান")
        self.assertIn("send money immediately", normalized)
        self.assertEqual(info["language"], "Bengali")

    def test_english_passes_through(self):
        normalized, info = normalize_for_detection("Your account needs verification")
        self.assertIn("your account needs verification", normalized)
        self.assertEqual(info["language"], "English / undetermined")

    def test_detector_returns_coverage_note(self):
        _, info = normalize_for_detection("random message")
        self.assertIn("not full translation", info["coverage_note"])


if __name__ == "__main__":
    unittest.main()
