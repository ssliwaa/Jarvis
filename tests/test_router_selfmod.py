import unittest

from router import classify


class ReminderIntentTest(unittest.TestCase):
    def test_przypomnij_is_memory_reminder(self):
        result = classify("przypomnij mi o spotkaniu")
        self.assertEqual(result["intent"], "memory")
        self.assertEqual(result["label"], "REMINDER")
        self.assertEqual(result["action"], "memory")

    def test_przypominam_is_memory_reminder(self):
        result = classify("Przypominam o rachunku")
        self.assertEqual(result["intent"], "memory")
        self.assertEqual(result["label"], "REMINDER")

    def test_existing_remember_unchanged(self):
        result = classify("zapamiętaj to")
        self.assertEqual(result["intent"], "memory")
        self.assertEqual(result["label"], "MEMORY")


if __name__ == "__main__":
    unittest.main()
