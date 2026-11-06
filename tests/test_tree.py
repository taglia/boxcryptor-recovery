"""End-to-end test: build a synthetic Boxcryptor 2.x vault with a freshly generated key, run decrypt_tree.py
on it as a subprocess, and compare the output tree with the plaintexts. No real key or data involved."""
import base64
import hashlib
import hmac
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import decrypt_tree as D  # noqa: E402

SCRIPT = os.path.join(ROOT, "decrypt_tree.py")
PASSWORD = "correct horse battery staple"
UID = "8123456789012345678"
BLOCK = 4096


def aes_cbc(key, iv, data, pad):
    if pad:
        n = 16 - len(data) % 16
        data = data + bytes([n]) * n
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def wrap_blob(plain, aes_key, mac_key):
    iv = os.urandom(16)
    ct = aes_cbc(aes_key, iv, plain, pad=True)
    return iv + hmac.new(mac_key, ct, hashlib.sha256).digest() + ct


class Vault:
    """Builds key.bckey + an encrypted tree the way the client lays it out."""

    def __init__(self, base):
        self.base = base
        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        salt = os.urandom(24)
        pk = PBKDF2HMAC(hashes.SHA512(), 64, salt, 1000).derive(PASSWORD.encode())
        pw_aes, pw_mac = pk[:32], pk[32:]
        wrapping = os.urandom(64)
        self.fn_key = os.urandom(64)
        aes96 = os.urandom(32) + self.fn_key
        priv_der_b64 = base64.b64encode(self.priv.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        user = {
            "id": UID, "username": "test@example.invalid",
            "publicKey": base64.b64encode(self.priv.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
            "privateKey": base64.b64encode(wrap_blob(priv_der_b64, pw_aes, pw_mac)).decode(),
            "aesKey": base64.b64encode(self.rsa_wrap(aes96)).decode(),
            "wrappingKey": base64.b64encode(wrap_blob(wrapping, pw_aes, pw_mac)).decode(),
            "keys": {"filename": base64.b64encode(wrap_blob(self.fn_key, wrapping[:32], wrapping[32:])).decode()},
            "salt": base64.b64encode(salt).decode(), "kdfIterations": 1000, "password": "unused",
        }
        doc = {"artifact": "keyfile", "version": 1, "users": [user], "groups": [], "groupMemberships": [],
               "organization": {"id": "1", "name": "Boxcryptor", "keys": {}}}
        with open(os.path.join(base, "key.bckey"), "w", encoding="utf-8-sig") as f:   # BOM, like real exports
            json.dump(doc, f)
        with open(os.path.join(base, "pass.txt"), "w") as f:
            f.write(PASSWORD)

    def rsa_wrap(self, data):
        return self.priv.public_key().encrypt(
            data, apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))

    def enc_name(self, plain):
        return D.encrypt_name(plain, self.fn_key, UID)

    def container(self, path, enc_name, plaintext=None):
        """Write a bc01 container. plaintext=None -> header-only (FolderKey.bch)."""
        file_key = os.urandom(96)
        k = file_key[32:64]
        iv = os.urandom(16)
        header = {"artifact": "header", "version": 1,
                  "cipher": {"algorithm": "AES", "mode": "CBC", "padding": "PKCS7", "keySize": 256,
                             "blockSize": BLOCK, "iv": base64.b64encode(iv).decode(), "mac": {"enabled": "false"}},
                  "metadata": {"name": {"value": enc_name, "encrypted": True}},
                  "encryptedFileKeys": [{"type": "data", "id": UID,
                                         "value": base64.b64encode(self.rsa_wrap(file_key)).decode()}]}
        core = json.dumps(header).encode()
        pad = BLOCK - 48 - len(core)
        body, cpad = b"", 0
        if plaintext is not None and len(plaintext) > 0:
            blocks = [plaintext[i:i + BLOCK] for i in range(0, len(plaintext), BLOCK)]
            for i, p in enumerate(blocks):
                biv = hmac.new(k, iv + i.to_bytes(8, "little"), hashlib.sha256).digest()[:16]
                last = i == len(blocks) - 1
                if last:
                    cpad = 16 - len(p) % 16
                body += aes_cbc(k, biv, p, pad=last)
        with open(path, "wb") as f:
            f.write(b"bc01" + struct.pack("<III", len(core), pad, cpad) + os.urandom(32) + core + bytes(pad) + body)


class TreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bcrec-")
        self.v = Vault(self.tmp)
        self.expected = {}   # decrypted relative path -> bytes
        root_plain = "My Backup"
        self.root_enc = self.v.enc_name(root_plain)
        root = os.path.join(self.tmp, self.root_enc)
        sub_plain, sub_enc = "Photos 2016", self.v.enc_name("Photos 2016")
        os.makedirs(os.path.join(root, sub_enc))
        self.v.container(os.path.join(root, "FolderKey.bch"), self.root_enc)
        self.v.container(os.path.join(root, sub_enc, "FolderKey.bch"), sub_enc)
        files = {
            "notes.txt": b"hello, world\n",
            "empty.bin": b"",
            "almost-a-block.bin": os.urandom(BLOCK - 1),
            "several-blocks.bin": os.urandom(3 * BLOCK + 7),
            "~$lock.docx": b"office lock file junk",
            "ünïcödé 日本.pdf": os.urandom(1000),
        }
        for name, data in files.items():
            if name.startswith("~$"):
                disk = "~$" + self.v.enc_name(name[2:]) + ".bc"
            else:
                disk = self.v.enc_name(name) + ".bc"
            self.v.container(os.path.join(root, disk), disk[:-3] if not disk.startswith("~$") else disk, data)
            self.expected[os.path.join(root_plain, name)] = data
        sub_data = os.urandom(2 * BLOCK + 100)
        self.v.container(os.path.join(root, sub_enc, self.v.enc_name("img001.jpg") + ".bc"),
                         self.v.enc_name("img001.jpg"), sub_data)
        self.expected[os.path.join(root_plain, sub_plain, "img001.jpg")] = sub_data
        with open(os.path.join(root, sub_enc, "desktop.ini"), "wb") as f:
            f.write(b"[plain]\n")
        self.expected[os.path.join(root_plain, sub_plain, "desktop.ini")] = b"[plain]\n"
        # an empty folder: must be recreated
        os.makedirs(os.path.join(root, self.v.enc_name("Empty folder")))
        # a plain (unencrypted) folder whose name ends in .bc: must keep its name
        os.makedirs(os.path.join(root, "archives.bc"))
        self.v.container(os.path.join(root, "archives.bc", self.v.enc_name("inside.txt") + ".bc"),
                         self.v.enc_name("inside.txt"), b"inside a plain-named folder\n")
        self.expected[os.path.join(root_plain, "archives.bc", "inside.txt")] = b"inside a plain-named folder\n"
        # a traversal attempt hidden in an encrypted name: must land inside the destination
        self.v.container(os.path.join(root, self.v.enc_name("../../escaped.txt") + ".bc"),
                         self.v.enc_name("../../escaped.txt"), b"must stay inside")
        self.expected[os.path.join(root_plain, ".._.._escaped.txt")] = b"must stay inside"
        # two names differing only by case: a collision on macOS/Windows, so one of them gets a '~' suffix
        for n, data in (("Same.txt", b"UPPER"), ("same.txt", b"lower")):
            self.v.container(os.path.join(root, self.v.enc_name(n) + ".bc"), self.v.enc_name(n), data)
        self.root = root
        self.root_plain = root_plain

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_tool(self, *args):
        return subprocess.run([sys.executable, "-I", SCRIPT, "--password-file", "pass.txt", *args, self.root], cwd=self.tmp,
                              capture_output=True, text=True, timeout=300)

    def test_dry_run_writes_nothing(self):
        r = self.run_tool("--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, self.root_plain)))
        self.assertIn("->  My Backup/Photos 2016", r.stdout)
        self.assertIn("img001.jpg", r.stdout)

    def test_full_decrypt_then_resume(self):
        r = self.run_tool("--workers", "2")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for rel, data in self.expected.items():
            p = os.path.join(self.tmp, rel)
            self.assertTrue(os.path.isfile(p), "missing %s\n%s" % (rel, r.stdout))
            with open(p, "rb") as f:
                self.assertEqual(f.read(), data, rel)
        out_root = os.path.join(self.tmp, self.root_plain)
        self.assertFalse(any(n.endswith(".bch") for _, _, fs in os.walk(out_root) for n in fs))
        self.assertTrue(os.path.isfile(os.path.join(out_root, "_boxcryptor_decrypt.log")))
        self.assertIn("0 failures", r.stdout)
        self.assertTrue(os.path.isdir(os.path.join(out_root, "Empty folder")))
        self.assertTrue(os.path.isdir(os.path.join(out_root, "archives.bc")))
        self.assertFalse(os.path.exists(os.path.join(out_root, "archives")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escaped.txt")))
        # the case collision: both files written, the second one (in walk order) with a '~' suffix
        same = sorted(n for n in os.listdir(out_root) if n.lower().startswith("same.txt"))
        self.assertEqual(len(same), 2, same)
        self.assertEqual(sum(n.endswith("~") for n in same), 1, same)
        contents = set()
        for n in same:
            with open(os.path.join(out_root, n), "rb") as f:
                contents.add(f.read())
        self.assertEqual(contents, {b"UPPER", b"lower"})
        self.assertIn("1 name collisions", r.stdout)
        self.assertIn("(name collision)", r.stdout)
        # second run: everything is skipped, the collision resolves the same way
        r2 = self.run_tool()
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertIn("found  : 0 .bc files to decrypt", r2.stdout)
        self.assertEqual(sorted(n for n in os.listdir(out_root) if n.lower().startswith("same.txt")), same)

    def test_wrong_password_is_rejected(self):
        with open(os.path.join(self.tmp, "pass.txt"), "w") as f:
            f.write("not the password")
        r = self.run_tool("--dry-run")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, self.root_plain)))

    def test_refuses_multi_user_export(self):
        p = os.path.join(self.tmp, "key.bckey")
        with open(p, encoding="utf-8-sig") as f:
            doc = json.load(f)
        doc["users"].append(dict(doc["users"][0], id="42"))
        with open(p, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        r = self.run_tool("--dry-run")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("STOP", r.stderr + r.stdout)


if __name__ == "__main__":
    unittest.main()
