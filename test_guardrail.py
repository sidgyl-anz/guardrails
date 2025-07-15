import unittest
from standalone_guardrail import StandaloneGuardrail

class TestGuardrail(unittest.TestCase):
    def test_guardrail_initialization(self):
        try:
            StandaloneGuardrail()
        except Exception as e:
            self.fail(f"StandaloneGuardrail initialization failed with an exception: {e}")

if __name__ == '__main__':
    unittest.main()
