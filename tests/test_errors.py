"""Unit tests for errors: the shared loopback-layer exception.

AppError is deliberately tiny (code/message/status); these tests pin the
public contract used by server.py and the *_routes modules.
"""
import unittest

import errors


class TestAppError(unittest.TestCase):
    """AppError: attributes, defaults and Exception behaviour."""

    def test_attributes_and_default_status(self):
        err = errors.AppError("E_MISSING", "thing not found")
        self.assertEqual(err.code, "E_MISSING")
        self.assertEqual(err.message, "thing not found")
        self.assertEqual(err.status, 400)

    def test_custom_status_kept(self):
        err = errors.AppError("E_TEAPOT", "brewing", 418)
        self.assertEqual(err.status, 418)

    def test_is_a_regular_exception(self):
        err = errors.AppError("E_X", "kaput", 500)
        self.assertIsInstance(err, Exception)
        self.assertEqual(str(err), "kaput")
        self.assertEqual(err.args, ("kaput",))

    def test_raise_and_catch_roundtrip(self):
        with self.assertRaises(errors.AppError) as ctx:
            raise errors.AppError("E_LOOP", "echo", 502)
        err = ctx.exception
        self.assertEqual((err.code, err.status), ("E_LOOP", 502))

    def test_non_string_code_allowed(self):
        err = errors.AppError(7, "numerical", 500)
        self.assertEqual(err.code, 7)

    def test_message_used_for_exception_args(self):
        # super().__init__(message) keeps traceback formatting consistent.
        err = errors.AppError("E_ARGS", "abc")
        self.assertEqual(err.args, ("abc",))
        self.assertIn("abc", repr(err))


if __name__ == "__main__":
    unittest.main()
