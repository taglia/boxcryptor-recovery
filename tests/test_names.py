"""Base4K and filename-cipher tests. Uses the public secomba/base4k README vectors and random keys only."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import decrypt_tree as D  # noqa: E402


class Base4KTests(unittest.TestCase):
    def test_readme_vectors(self):
        # From https://github.com/secomba/base4k README (current alphabet, base 0x6000)
        self.assertEqual(D.base4k_encode(b"f", legacy=False), "䁦")
        self.assertEqual(D.base4k_encode(b"foobar", legacy=False), "晦潯昦慲")
        self.assertEqual(D.base4k_decode("晦潯昦慲"), b"foobar")
        self.assertEqual(D.base4k_decode("䁦"), b"f")

    def test_round_trip_both_alphabets(self):
        for n in range(0, 70):
            data = bytes((i * 37 + 11) & 0xFF for i in range(n))
            self.assertEqual(D.base4k_decode(D.base4k_encode(data, legacy=True)), data, n)
            self.assertEqual(D.base4k_decode(D.base4k_encode(data, legacy=False)), data, n)

    def test_rejects_non_base4k(self):
        with self.assertRaises(D.Base4KError):
            D.base4k_decode("hello.txt")


class NameCipherTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(64)
        self.uid = "8123456789012345678"

    def test_key_holder_hash_is_one_byte_and_stable(self):
        h = D.key_holder_hash(self.uid)
        self.assertTrue(0 <= h <= 255)
        self.assertEqual(h, D.key_holder_hash(self.uid))

    def test_round_trip(self):
        for name in ["a", "report.docx", "Vacation photos 2016", "übergrößé ñ 日本語.txt",
                     "x" * 64, "y" * 65, "a very long file name " * 6 + ".pst"]:
            enc = D.encrypt_name(name, self.key, self.uid)
            self.assertTrue(all(0x4000 <= ord(c) < 0x6000 for c in enc), enc)
            self.assertEqual(D.decrypt_name(enc, self.key, self.uid), name)

    def test_layout(self):
        enc = D.encrypt_name("hello.txt", self.key, self.uid)
        raw = D.base4k_decode(enc)
        self.assertEqual(raw[0], 1)
        self.assertEqual(raw[1], D.key_holder_hash(self.uid))
        self.assertEqual(len(raw), 7 + len(b"hello.txt"))

    def test_wrong_key_or_user_fails(self):
        enc = D.encrypt_name("hello.txt", self.key, self.uid)
        with self.assertRaises(D.NameError_):
            D.decrypt_name(enc, os.urandom(64), self.uid)
        with self.assertRaises(D.NameError_):
            D.decrypt_name(enc, self.key, "999")

    def test_tamper_detected(self):
        enc = D.encrypt_name("hello.txt", self.key, self.uid)
        raw = bytearray(D.base4k_decode(enc))
        raw[-1] ^= 0x01
        with self.assertRaises(D.NameError_):
            D.decrypt_name(D.base4k_encode(bytes(raw)), self.key, self.uid)


class SanitizeTests(unittest.TestCase):
    def test_separators_control_chars_and_dots(self):
        self.assertEqual(D.sanitize("a/b"), "a_b")
        self.assertEqual(D.sanitize("a\\b"), "a_b")
        self.assertEqual(D.sanitize("../etc/passwd"), ".._etc_passwd")
        self.assertEqual(D.sanitize(".."), "_..")
        self.assertEqual(D.sanitize("."), "_.")
        self.assertEqual(D.sanitize(""), "_")
        self.assertEqual(D.sanitize("a\x00b\x1fc"), "a_b_c")

    def test_windows_reserved_names(self):
        self.assertEqual(D.sanitize("CON"), "_CON")
        self.assertEqual(D.sanitize("nul.txt"), "_nul.txt")
        self.assertEqual(D.sanitize("COM1"), "_COM1")
        self.assertEqual(D.sanitize("console.txt"), "console.txt")

    def test_ordinary_names_untouched(self):
        for name in ["Normal name (1).txt", "ünïcödé 日本.pdf", "~$lock.docx", "a.b.c", "archives.bc"]:
            self.assertEqual(D.sanitize(name), name)


if __name__ == "__main__":
    unittest.main()
