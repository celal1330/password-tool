"""
Unit tests for Password Generator & Validator
Written to make sure everything behaves as expected (and a bit more).
"""

import unittest
from password_tool import PasswordGenerator, PasswordValidator


class TestPasswordGenerator(unittest.TestCase):
    """Tests for the PasswordGenerator class — making sure generated passwords look right."""

    def setUp(self):
        # Initialize a generator before each test
        self.gen = PasswordGenerator()

    def test_default_password(self):
        """Default generation should produce a decent, mixed 16-char password."""
        pwd = self.gen.generate()
        self.assertEqual(len(pwd), 16)
        self.assertTrue(any(c.islower() for c in pwd), "Missing lowercase chars")
        self.assertTrue(any(c.isupper() for c in pwd), "Missing uppercase chars")
        self.assertTrue(any(c.isdigit() for c in pwd), "Missing digits")
        # Note: not checking for special chars every time, but they should usually appear.

    def test_custom_length(self):
        """Should handle custom lengths properly."""
        pwd = self.gen.generate(length=20)
        self.assertEqual(len(pwd), 20)

    def test_too_short_password_raises(self):
        """Length below 8 should raise ValueError (security reasons)."""
        with self.assertRaises(ValueError):
            self.gen.generate(length=5)

    def test_lowercase_only_mode(self):
        """When only lowercase is enabled, output should be all lowercase."""
        pwd = self.gen.generate(
            use_uppercase=False,
            use_digits=False,
            use_special=False
        )
        self.assertTrue(all(c.islower() for c in pwd))

    def test_passphrase_creation(self):
        """Passphrase generation should return several words + a number."""
        phrase = self.gen.generate_passphrase(word_count=4)
        # Expect 4 words + 1 number, separated by '-'
        parts = phrase.split('-')
        self.assertEqual(len(parts), 5)
        # Quick sanity check: last part should be numeric
        self.assertTrue(parts[-1].isdigit())


class TestPasswordValidator(unittest.TestCase):
    """Tests for PasswordValidator class — strength checks, entropy, hashing, etc."""

    def setUp(self):
        self.val = PasswordValidator()

    def test_strong_password_validation(self):
        """A well-structured strong password should pass all major checks."""
        pw = "Str0ng!P@ssw0rd#2024"
        result = self.val.validate(pw)
        self.assertIn(result['strength'], ['Strong', 'Very Strong'])
        self.assertTrue(result['checks']['lowercase'])
        self.assertTrue(result['checks']['uppercase'])
        self.assertTrue(result['checks']['digit'])
        self.assertTrue(result['checks']['special'])

    def test_weak_common_password(self):
        """Common weak passwords like 'password' should fail badly."""
        result = self.val.validate("password")
        self.assertIn(result['strength'], ['Very Weak', 'Weak'])
        self.assertFalse(result['checks']['not_common'])

    def test_entropy_is_numeric(self):
        """Entropy calculation should return a positive float."""
        ent = self.val.calculate_entropy("Str0ng!P@ss")
        self.assertIsInstance(ent, float)
        self.assertGreater(ent, 0.0)

    def test_sha256_hash_consistency(self):
        """Hashing should be deterministic and 64 chars long."""
        pw = "TestPassword123"
        h1 = self.val.hash_password(pw)
        h2 = self.val.hash_password(pw)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_detects_common_passwords(self):
        """Make sure the validator flags known common passwords."""
        result = self.val.validate("password123")
        self.assertFalse(result['checks']['not_common'])

    # (Optional) Example of a slightly redundant test — humans tend to do this :)
    def test_random_password_entropy_is_high_enough(self):
        """Quick check to make sure generated passwords aren't too weak."""
        gen = PasswordGenerator()
        pwd = gen.generate(length=12)
        entropy = self.val.calculate_entropy(pwd)
        self.assertGreater(entropy, 40, "Entropy seems suspiciously low for a random password")


if __name__ == '__main__':
    # Note: Using verbosity=2 for more detailed output when run manually.
    unittest.main(verbosity=2)
